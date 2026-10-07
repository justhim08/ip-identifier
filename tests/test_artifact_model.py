import unittest
import email
from email import policy
import tempfile
from pathlib import Path

from sentinel.files.extractor import (
	_extract_email,
	_extract_indicator_records,
	_extract_text,
	hash_file,
	identify_file,
)
from sentinel.files.models import Artifact


class ArtifactModelTests(unittest.TestCase):
	def test_artifact_serializes_identity_file_info_and_analysis_data(self):
		artifact = Artifact(
			path="reports/sample.pdf",
			detected_type="PDF",
			size=42,
			mime_type="application/pdf",
			extension=".pdf",
			hashes={"sha256": "abc"},
			metadata={"title": "Example"},
			indicators={"urls": []},
			evidence=[{"source": "file metadata", "value": "title=Example"}],
			confidence="high",
		)
		report = artifact.to_dict()
		self.assertEqual(artifact.name, "sample.pdf")
		self.assertEqual(report["identity"]["detected_type"], "PDF")
		self.assertEqual(report["file_info"]["size"], 42)
		self.assertEqual(report["hashes"]["sha256"], "abc")
		self.assertEqual(report["confidence"], "HIGH")
		self.assertTrue(report["timestamp"].endswith("Z"))

	def test_artifact_validates_size_status_confidence_and_type(self):
		invalid = (
			{"path": "sample.txt", "detected_type": "TEXT", "size": -1},
			{"path": "sample.txt", "detected_type": "TEXT", "size": 0, "analysis_status": "UNKNOWN"},
			{"path": "sample.txt", "detected_type": "TEXT", "size": 0, "confidence": "CERTAIN"},
			{"path": "sample.txt", "detected_type": "", "size": 0},
		)
		for values in invalid:
			with self.subTest(values=values), self.assertRaises(ValueError):
				Artifact(**values)


class FileIdentificationTests(unittest.TestCase):
	def test_pdf_signature_overrides_filename_extension_and_preserves_mismatch(self):
		with tempfile.TemporaryDirectory() as directory:
			path = Path(directory) / "misleading.txt"
			path.write_bytes(b"%PDF-1.7\n")
			result = identify_file(path)
		self.assertEqual(result["extension"], ".txt")
		self.assertEqual(result["extension_type"], "Plain text")
		self.assertEqual(result["detected_type"], "PDF")
		self.assertEqual(result["mime_type"], "application/pdf")
		self.assertTrue(result["type_mismatch"])
		self.assertEqual(result["confidence"], "HIGH")

	def test_docx_is_detected_by_safe_zip_structure(self):
		import zipfile

		with tempfile.TemporaryDirectory() as directory:
			path = Path(directory) / "document.bin"
			with zipfile.ZipFile(path, "w") as archive:
				archive.writestr("word/document.xml", "<document/>")
			result = identify_file(path)
		self.assertEqual(result["detected_type"], "DOCX document")
		self.assertFalse(result["type_mismatch"])

	def test_unknown_extension_is_not_mislabeled_as_supported_format(self):
		with tempfile.TemporaryDirectory() as directory:
			path = Path(directory) / "unknown.bin"
			path.write_bytes(b"\x00\x01\x02")
			result = identify_file(path)
		self.assertEqual(result["detected_type"], "Unknown")
		self.assertIsNone(result["extension_type"])
		self.assertEqual(result["readable"], True)


class FileHashingTests(unittest.TestCase):
	def test_empty_file_hashes_are_deterministic(self):
		with tempfile.TemporaryDirectory() as directory:
			path = Path(directory) / "empty.txt"
			path.touch()
			first = hash_file(path)
			second = hash_file(path)
		self.assertEqual(first, second)
		self.assertEqual(first["sha256"], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
		self.assertIn("sha1", first)
		self.assertIn("md5", first)

	def test_large_file_hash_is_chunked_and_correct(self):
		import hashlib

		data = b"sentinel-artifact-test\n" * 100000
		with tempfile.TemporaryDirectory() as directory:
			path = Path(directory) / "large.bin"
			path.write_bytes(data)
			result = hash_file(path, algorithms=("sha256",), chunk_size=8192)
		self.assertEqual(result["sha256"], hashlib.sha256(data).hexdigest())

	def test_unsupported_hash_and_invalid_chunk_size_are_reported(self):
		with tempfile.TemporaryDirectory() as directory:
			path = Path(directory) / "sample"
			path.write_bytes(b"sample")
			with self.assertRaisesRegex(ValueError, "Unsupported hash"):
				hash_file(path, algorithms=("not-a-hash",))
			with self.assertRaisesRegex(ValueError, "chunk size"):
				hash_file(path, chunk_size=0)


class SafeMetadataTests(unittest.TestCase):
	def test_html_metadata_and_links_are_collected_without_script_execution(self):
		with tempfile.TemporaryDirectory() as directory:
			path = Path(directory) / "page.html"
			path.write_text(
				'<html><head><title>Example title</title>'
				'<meta name="author" content="Analyst"></head><body>'
				'<a href="https://example.com/path">link</a>'
				'<script>window.executed = true</script>'
				'<img src="/image.png"></body></html>',
				encoding="utf-8",
			)
			text, metadata = _extract_text(path)
		self.assertIn("Example title", metadata["html_metadata"]["title"])
		self.assertEqual(metadata["html_metadata"]["author"], "Analyst")
		self.assertEqual(metadata["references"], ["/image.png", "https://example.com/path"])
		self.assertNotIn("window.executed", text)

	def test_email_headers_and_attachment_metadata_are_read_without_payload_open(self):
		message = email.message.EmailMessage(policy=policy.default)
		message["From"] = "sender@example.net"
		message["To"] = "recipient@example.org"
		message["Subject"] = "Example"
		message["Date"] = "Tue, 06 Oct 2026 12:00:00 +0000"
		message.set_content("Visit https://example.com/")
		message.add_attachment(b"opaque data", maintype="application", subtype="octet-stream", filename="sample.bin")
		with tempfile.TemporaryDirectory() as directory:
			path = Path(directory) / "message.eml"
			path.write_bytes(message.as_bytes())
			text, metadata = _extract_email(path)
		self.assertEqual(metadata["from"], "sender@example.net")
		self.assertEqual(metadata["to"], "recipient@example.org")
		self.assertEqual(metadata["subject"], "Example")
		self.assertEqual(metadata["attachments"][0]["filename"], "sample.bin")
		self.assertFalse(metadata["attachments"][0]["payload_opened"])
		self.assertIn("Visit", text)

	def test_docx_hyperlink_relationship_is_extracted_as_reference(self):
		from docx import Document
		from docx.opc.constants import RELATIONSHIP_TYPE as RT

		with tempfile.TemporaryDirectory() as directory:
			path = Path(directory) / "linked.docx"
			document = Document()
			document.add_paragraph("Document text")
			document.part.relate_to("https://example.com/doc", RT.HYPERLINK, is_external=True)
			document.save(path)
			text, metadata = _extract_text(path)
		self.assertIn("Document text", text)
		self.assertEqual(metadata["hyperlinks"], ["https://example.com/doc"])


class IndicatorNormalizationTests(unittest.TestCase):
	def test_network_file_and_command_indicators_are_normalized_and_deduplicated(self):
		text = (
			"HTTP://Example.COM/a http://example.com/a "
			"Analyst@Example.com 203.0.113.8 2001:db8::1 "
			"example.com " + "a" * 64 + " C:\\Temp\\sample.exe powershell.exe"
		)
		result = _extract_indicator_records(text)
		url = result["url"][0]
		self.assertEqual(url["value"], "http://example.com/a")
		self.assertEqual(url["occurrence_count"], 2)
		self.assertEqual(len(url["original_values"]), 2)
		self.assertEqual(result["email"][0]["value"], "analyst@example.com")
		self.assertEqual(
			{item["value"] for item in result["ip_address"]},
			{"203.0.113.8", "2001:db8::1"},
		)
		self.assertEqual(result["hash"][0]["value"], "a" * 64)
		self.assertIn("C:\\Temp\\sample.exe", {item["value"] for item in result["path"]})
		self.assertIn("sample.exe", {item["value"] for item in result["filename"]})
		self.assertIn("powershell.exe", {item["value"] for item in result["command_reference"]})
		self.assertGreaterEqual(url["evidence"][0]["offset"], 0)
		self.assertIn("context", url["evidence"][0])

	def test_metadata_hyperlinks_are_indicators_with_provenance(self):
		result = _extract_indicator_records(
			"Visible text",
			{"hyperlinks": ["HTTPS://Example.com/path"]},
		)
		url = result["url"][0]
		self.assertEqual(url["value"], "https://example.com/path")
		self.assertEqual(url["occurrence_count"], 1)
		self.assertEqual(url["evidence"][0]["source"], "metadata.hyperlinks[0]")

	def test_artifact_supports_partial_and_failed_statuses(self):
		for status in ("PARTIAL", "FAILED"):
			with self.subTest(status=status):
				artifact = Artifact(
					path="sample.bin",
					detected_type="UNKNOWN",
					size=0,
					analysis_status=status,
					errors=[{"stage": "identify", "message": "unavailable"}],
				)
				self.assertEqual(artifact.analysis_status, status)


if __name__ == "__main__":
	unittest.main()
