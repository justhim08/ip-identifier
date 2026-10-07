import contextlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from pypdf import PdfWriter

from sentinel.cli import main, run_file_analysis
from sentinel.files.analysis import analyze_file
from sentinel.files.extractor import MAX_EXTRACTION_BYTES, extract_file
from sentinel.reports.renderer import render_report


class ArtifactAnalysisTests(unittest.TestCase):
	def analyze_text(self, directory, name="note.txt", content="Contact analyst@example.com and see https://Example.com/docs"):
		path = Path(directory) / name
		path.write_text(content, encoding="utf-8")
		return analyze_file(path), path

	def test_artifact_analysis_includes_identity_hashes_metadata_indicators_and_text(self):
		with tempfile.TemporaryDirectory() as directory:
			report, path = self.analyze_text(directory)
		artifact = report["artifact"]
		self.assertEqual(artifact["identity"]["name"], "note.txt")
		self.assertEqual(artifact["identity"]["detected_type"], "Plain text")
		self.assertEqual(artifact["file_info"]["analysis_status"], "COMPLETE")
		self.assertEqual(len(artifact["hashes"]["sha256"]), 64)
		self.assertIn("analyst@example.com", artifact["legacy_indicators"]["email_addresses"])
		self.assertIn("https://example.com/docs", artifact["legacy_indicators"]["urls"])
		self.assertIn("Contact analyst@example.com", artifact["text"])
		self.assertEqual(artifact["path"], str(path.resolve()))
		self.assertIn(
			"note.txt",
			[item["value"] for item in artifact["indicators"]["filename"]],
		)
		self.assertIn(
			str(path.resolve()),
			[item["value"] for item in artifact["indicators"]["path"]],
		)
		self.assertEqual(
			sum(item["normalized_value"] == "note.txt" for item in artifact["indicators"]["filename"]),
			1,
		)

	def test_artifact_to_indicator_relationship_and_provenance_are_preserved(self):
		with tempfile.TemporaryDirectory() as directory:
			report, _ = self.analyze_text(directory)
		self.assertTrue(any(
			edge["relationship"] == "contains indicator"
			and edge["target"] == "url:https://example.com/docs"
			for edge in report["relationships"]
		))
		self.assertTrue(any(
			item["category"] == "url"
			and item["source"] == "local file analysis"
			and item["classification"] == "directly_observed"
			for item in report["intelligence"]
		))
		self.assertTrue(any(
			edge["relationship"] == "references hostname"
			and edge["source"] == "https://example.com/docs"
			and edge["target"] == "example.com"
			for edge in report["relationships"]
		))

	def test_repeated_indicator_is_deduplicated_with_occurrence_count(self):
		with tempfile.TemporaryDirectory() as directory:
			report, _ = self.analyze_text(
				directory, content="https://example.com/a https://EXAMPLE.com/a https://example.com/a",
			)
		url = report["artifact"]["indicators"]["url"][0]
		self.assertEqual(url["normalized_value"], "https://example.com/a")
		self.assertEqual(url["occurrence_count"], 3)
		self.assertEqual(len(url["evidence"]), 3)

	def test_type_mismatch_is_a_cautious_observation_finding(self):
		with tempfile.TemporaryDirectory() as directory:
			path = Path(directory) / "report.txt"
			path.write_bytes(b"%PDF-1.4\nmalformed but signature observed")
			report = analyze_file(path)
		finding = next(item for item in report["findings"] if item["id"] == "ARTIFACT-TYPE-001")
		self.assertEqual(finding["severity"], "LOW")
		self.assertEqual(finding["confidence"], "HIGH")
		self.assertEqual(finding["status"], "OBSERVED")
		self.assertIn("does not indicate maliciousness", finding["description"])
		self.assertEqual(report["artifact"]["analysis_status"], "PARTIAL")

	def test_html_report_metadata_and_links_are_extracted_safely(self):
		with tempfile.TemporaryDirectory() as directory:
			path = Path(directory) / "index.html"
			path.write_text(
				'<html><head><title>Public page</title><meta name="author" content="Team"></head>'
				'<body><a href="https://example.com/">external</a>'
				'<script>throw new Error("never run")</script></body></html>',
				encoding="utf-8",
			)
			report = analyze_file(path)
		artifact = report["artifact"]
		self.assertEqual(artifact["metadata"]["html_metadata"]["author"], "Team")
		self.assertIn("https://example.com/", artifact["legacy_indicators"]["urls"])
		self.assertNotIn("never run", artifact["text"])
		self.assertTrue(any(finding["id"] == "ARTIFACT-INDICATOR-001" for finding in report["findings"]))

	def test_email_headers_and_attachment_metadata_are_included_without_executing(self):
		from email.message import EmailMessage

		message = EmailMessage()
		message["From"] = "sender@example.net"
		message["To"] = "recipient@example.org"
		message["Subject"] = "Artifact sample"
		message.set_content("See https://example.com/")
		message.add_attachment(b"not executed", maintype="application", subtype="octet-stream", filename="payload.bin")
		with tempfile.TemporaryDirectory() as directory:
			path = Path(directory) / "sample.eml"
			path.write_bytes(message.as_bytes())
			report = analyze_file(path)
		metadata = report["artifact"]["metadata"]
		self.assertEqual(metadata["subject"], "Artifact sample")
		self.assertEqual(metadata["attachments"][0]["filename"], "payload.bin")
		self.assertFalse(metadata["attachments"][0]["payload_opened"])

	def test_missing_unsupported_and_unreadable_paths_have_clear_errors(self):
		with tempfile.TemporaryDirectory() as directory:
			missing = Path(directory) / "missing.txt"
			with self.assertRaisesRegex(ValueError, "does not exist"):
				analyze_file(missing)
			unsupported = Path(directory) / "unknown.xyz"
			unsupported.write_bytes(b"unknown data")
			with self.assertRaisesRegex(ValueError, "Unsupported detected file type"):
				analyze_file(unsupported)
			valid = Path(directory) / "readable.txt"
			valid.write_text("data", encoding="utf-8")
			with patch("pathlib.Path.open", side_effect=PermissionError("access denied")):
				with self.assertRaises(PermissionError):
					analyze_file(valid)

	def test_large_file_returns_partial_analysis_and_still_hashes_streaming(self):
		with tempfile.TemporaryDirectory() as directory:
			path = Path(directory) / "large.txt"
			with path.open("wb") as file_handle:
				file_handle.truncate(MAX_EXTRACTION_BYTES + 1)
			report = analyze_file(path)
		artifact = report["artifact"]
		self.assertEqual(artifact["analysis_status"], "PARTIAL")
		self.assertTrue(artifact["hashes"]["sha256"])
		self.assertEqual(artifact["text"], "")
		self.assertIn("limit", artifact["errors"][0]["message"])

	def test_malformed_docx_returns_partial_with_error(self):
		with tempfile.TemporaryDirectory() as directory:
			path = Path(directory) / "broken.docx"
			path.write_bytes(b"not a valid package")
			report = analyze_file(path)
		self.assertEqual(report["artifact"]["analysis_status"], "PARTIAL")
		self.assertTrue(report["artifact"]["errors"])

	def test_docx_uncompressed_size_limit_returns_partial(self):
		with tempfile.TemporaryDirectory() as directory:
			path = Path(directory) / "oversized.docx"
			with zipfile.ZipFile(path, "w") as package:
				package.writestr("word/document.xml", b"x" * 1024)
			with patch("sentinel.files.extractor.MAX_DOCX_UNCOMPRESSED_BYTES", 16):
				report = analyze_file(path)
		self.assertEqual(report["artifact"]["analysis_status"], "PARTIAL")
		self.assertIn("uncompressed-size limit", report["artifact"]["errors"][0]["message"])

	def test_pdf_page_limit_returns_partial_with_extraction_note(self):
		with tempfile.TemporaryDirectory() as directory:
			path = Path(directory) / "limited.pdf"
			writer = PdfWriter()
			writer.add_blank_page(width=72, height=72)
			with path.open("wb") as file_handle:
				writer.write(file_handle)
			with patch("sentinel.files.extractor.MAX_PDF_PAGES", 0):
				report = analyze_file(path)
		self.assertEqual(report["artifact"]["analysis_status"], "PARTIAL")
		self.assertIn("PDF text extraction was limited", report["artifact"]["errors"][0]["message"])

	def test_legacy_extractor_remains_compatible(self):
		with tempfile.TemporaryDirectory() as directory:
			path = Path(directory) / "old.txt"
			path.write_text("https://example.com", encoding="utf-8")
			result = extract_file(path)
		self.assertEqual(result["indicators"]["urls"], ["https://example.com"])


class ArtifactCliAndReportTests(unittest.TestCase):
	def test_file_cli_dispatches_through_structured_analysis(self):
		with tempfile.TemporaryDirectory() as directory:
			path = Path(directory) / "sample.txt"
			path.write_text("hello", encoding="utf-8")
			with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
				report = run_file_analysis(str(path))
		self.assertIn("artifact", report)
		self.assertEqual(report["type"], "artifact")

	def test_cli_writes_artifact_json_and_text_reports(self):
		with tempfile.TemporaryDirectory() as directory:
			path = Path(directory) / "input.txt"
			path.write_text("https://example.com", encoding="utf-8")
			json_path = Path(directory) / "artifact.json"
			with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
				status = main(["file", str(path), "--output", str(json_path)])
			self.assertEqual(status, 0)
			report = json.loads(json_path.read_text(encoding="utf-8"))
			self.assertIn("hashes", report["artifact"])
			self.assertIn("intelligence", report)

			text = render_report(report, "txt")
			self.assertIn("SENTINEL FILE & ARTIFACT ANALYSIS", text)
			self.assertIn("OBSERVED METADATA", text)
			self.assertIn("ARTIFACT RELATIONSHIPS", text)
			self.assertIn("were not executed", text)

	def test_csv_report_preserves_artifact_provenance_and_findings(self):
		with tempfile.TemporaryDirectory() as directory:
			path = Path(directory) / "input.txt"
			path.write_text("https://example.com", encoding="utf-8")
			report = analyze_file(path)
		csv_text = render_report(report, "csv")
		self.assertIn("artifact.hashes.sha256", csv_text)
		self.assertIn("intelligence[0].source,local file analysis", csv_text)
		self.assertIn("relationships[0].source_name,local file analysis", csv_text)

	def test_cli_error_exit_code_for_missing_file(self):
		with tempfile.TemporaryDirectory() as directory:
			missing = Path(directory) / "missing.txt"
			with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
				status = main(["file", str(missing)])
		self.assertEqual(status, 3)


if __name__ == "__main__":
	unittest.main()
