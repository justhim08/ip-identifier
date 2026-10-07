"""Orchestrate non-destructive artifact identification, extraction, and intelligence."""

import json
import mimetypes
import socket
from urllib.parse import urlsplit
from typing import Any, Dict, List

from ..intel.models import IntelligenceRecord, IntelligenceRelationship, utc_timestamp
from ..router.findings import make_finding
from ..validation import validate_file_path
from .extractor import (
	MAX_EXTRACTION_BYTES,
	SUPPORTED_FORMATS,
	_extract_indicator_records,
	_extract_text,
	hash_file,
	identify_file,
)
from .models import Artifact


TYPE_SUFFIXES = {
	"CSV text": ".csv",
	"DOCX document": ".docx",
	"Email message": ".eml",
	"HTML document": ".html",
	"JSON document": ".json",
	"Markdown document": ".md",
	"PDF": ".pdf",
	"Plain text": ".txt",
	"RTF document": ".rtf",
	"XML document": ".xml",
}


def _extraction_type(info: Dict[str, Any]) -> str:
	detected = info["detected_type"]
	if detected in TYPE_SUFFIXES:
		return detected
	extension_type = info.get("extension_type")
	if extension_type in TYPE_SUFFIXES:
		return extension_type
	raise ValueError(
		f"Unsupported detected file type '{detected}'. Supported extensions: "
		+ ", ".join(sorted(SUPPORTED_FORMATS))
	)


def _intelligence_records(
	path: str,
	hashes: Dict[str, str],
	indicators: Dict[str, List[Dict[str, Any]]],
) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
	records = []
	relationships = []
	for algorithm, digest in hashes.items():
		records.append(IntelligenceRecord(
			source="local file analysis",
			category="file_hash",
			target=path,
			value={"algorithm": algorithm, "digest": digest, "purpose": "identification"},
			evidence=[{"source": "streaming local hash", "algorithm": algorithm, "value": digest}],
			confidence="HIGH",
			classification="directly_observed",
		).to_dict())
		relationships.append(IntelligenceRelationship(
			source=f"artifact:{path}",
			target=f"{algorithm}:{digest}",
			relationship="has identification hash",
			evidence=[{"source": "streaming local hash", "algorithm": algorithm, "value": digest}],
			source_name="local file analysis",
			confidence="HIGH",
			status="OBSERVED",
		).to_dict())

	for category, items in indicators.items():
		for item in items:
			value = item["normalized_value"]
			evidence = {
				"source": "local file content or metadata",
				"occurrence_count": item["occurrence_count"],
				"observations": item["evidence"],
				"original_values": item["original_values"],
			}
			records.append(IntelligenceRecord(
				source="local file analysis",
				category=category,
				target=path,
				value=value,
				evidence=[evidence],
				confidence="HIGH",
				classification="directly_observed",
			).to_dict())
			relationships.append(IntelligenceRelationship(
				source=f"artifact:{path}",
				target=f"{category}:{value}",
				relationship="contains indicator",
				evidence=[evidence],
				source_name="local file analysis",
				confidence="HIGH",
				status="OBSERVED",
			).to_dict())
			if category == "url":
				try:
					host = urlsplit(value).hostname
				except ValueError:
					host = None
				if host and not _is_ip_address(host):
					relationships.append(IntelligenceRelationship(
						source=value.lower(),
						target=host.lower(),
						relationship="references hostname",
						evidence=[evidence],
						source_name="local file content",
						confidence="HIGH",
						status="OBSERVED",
					).to_dict())
	return records, relationships


def _is_ip_address(value: str) -> bool:
	try:
		socket.inet_pton(socket.AF_INET, value)
		return True
	except OSError:
		try:
			socket.inet_pton(socket.AF_INET6, value)
			return True
		except OSError:
			return False


def _findings(
	path: str,
	info: Dict[str, Any],
	metadata: Dict[str, Any],
	indicators: Dict[str, List[Dict[str, Any]]],
) -> List[Dict[str, Any]]:
	findings = []
	if info["type_mismatch"]:
		findings.append(make_finding(
			"ARTIFACT-TYPE-001",
			"File Extension and Detected Type Differ",
			"LOW",
			path,
			"The detected content type differs from the filename extension; this observation alone does not indicate maliciousness.",
			[{"source": "file signature", "value": info["detected_type"]},
			 {"source": "filename", "value": info["extension"]}],
			"Applications or users may interpret the file differently than its extension suggests.",
			"Confirm the file's expected format and handle it with an application appropriate to the detected type.",
			category="artifact_type_observation",
			confidence=info["confidence"],
			status="OBSERVED",
			source="local file analysis",
		))
	urls = indicators.get("url", [])
	if urls:
		findings.append(make_finding(
			"ARTIFACT-INDICATOR-001",
			"External Network Reference Observed",
			"INFO",
			path,
			"One or more URL indicators were found in file content or metadata. Their presence does not establish that the file is malicious.",
			[{
				"source": "local file content or metadata",
				"value": item["normalized_value"],
				"occurrence_count": item["occurrence_count"],
				"observations": item["evidence"],
			} for item in urls],
			"The references may identify external resources or destinations relevant to the document's intended use.",
			"Review the references in context before opening or following them.",
			category="artifact_external_reference",
			confidence="HIGH",
			status="OBSERVED",
			source="local file analysis",
		))
	metadata_values = {
		key: value for key, value in metadata.items()
		if key.lower() in {"author", "creator", "producer", "application", "title", "subject", "from", "to"}
		and value
	}
	if metadata_values:
		findings.append(make_finding(
			"ARTIFACT-METADATA-001",
			"Document Metadata Observed",
			"INFO",
			path,
			"Document metadata fields were read as stored file properties; their values are not independently verified.",
			[{"source": "observed file metadata", "field": key, "value": value} for key, value in metadata_values.items()],
			"Metadata can disclose document provenance or personal information when files are shared.",
			"Review metadata for accuracy and privacy before distributing the artifact.",
			category="artifact_metadata_observation",
			confidence="HIGH",
			status="OBSERVED",
			source="local file metadata",
		))
	return findings


def analyze_file(filename: str) -> Dict[str, Any]:
	"""Analyze one local file without executing content or sending it to an external service."""
	path = validate_file_path(filename)
	info = identify_file(path)
	extraction_type = _extraction_type(info)
	hashes = hash_file(path)
	errors: List[Dict[str, str]] = []
	metadata: Dict[str, Any] = {}
	text = ""
	status = "COMPLETE"
	if info["size"] > MAX_EXTRACTION_BYTES:
		status = "PARTIAL"
		errors.append({
			"stage": "content_extraction",
			"message": (
				f"Content extraction was skipped because the file exceeds the "
				f"{MAX_EXTRACTION_BYTES // (1024 * 1024)} MB per-file extraction limit; streaming hashes were completed."
			),
		})
	else:
		try:
			if TYPE_SUFFIXES[extraction_type] == path.suffix.lower():
				text, metadata = _extract_text(path)
			else:
				# Dispatch by detected type while preserving the original file on disk.
				if extraction_type == "PDF":
					from .extractor import _extract_pdf
					text, metadata = _extract_pdf(path)
				elif extraction_type == "DOCX document":
					from .extractor import _extract_docx
					text, metadata = _extract_docx(path)
				else:
					text, metadata = _extract_text(path)
		except (OSError, ValueError, RuntimeError, UnicodeError, json.JSONDecodeError) as exc:
			status = "PARTIAL"
			errors.append({"stage": "content_extraction", "message": str(exc)})
		if metadata.get("_extraction_note"):
			status = "PARTIAL"
			errors.append({
				"stage": "content_extraction",
				"message": metadata["_extraction_note"],
			})

	indicators = _extract_indicator_records(text, metadata)
	for category, value in (("filename", info["name"]), ("path", info["path"])):
		identity_evidence = {
			"source": "artifact identity",
			"offset": None,
			"context": value,
		}
		items = indicators.setdefault(category, [])
		item = next(
			(candidate for candidate in items if candidate["normalized_value"] == value),
			None,
		)
		if item is None:
			items.append({
				"value": value,
				"normalized_value": value,
				"original_values": [value],
				"occurrence_count": 1,
				"evidence": [identity_evidence],
			})
		else:
			item["occurrence_count"] += 1
			item["evidence"].append(identity_evidence)
			if value not in item["original_values"]:
				item["original_values"].append(value)
	legacy_indicators = {
		"urls": sorted({item["normalized_value"] for item in indicators.get("url", [])}),
		"domains": sorted({item["normalized_value"] for item in indicators.get("domain", [])}),
		"ip_addresses": sorted({item["normalized_value"] for item in indicators.get("ip_address", [])}),
		"email_addresses": sorted({item["normalized_value"] for item in indicators.get("email", [])}),
	}
	evidence = [
		{"source": "file identification", **item}
		for item in info["evidence"]
	]
	evidence.extend(
		{"source": "observed file metadata", "field": key, "value": value}
		for key, value in metadata.items()
		if value
	)
	evidence.extend(errors)
	intelligence, relationships = _intelligence_records(info["path"], hashes, indicators)
	findings = _findings(info["path"], info, metadata, indicators)
	artifact = Artifact(
		path=info["path"],
		detected_type=info["detected_type"],
		size=info["size"],
		mime_type=info["mime_type"] or mimetypes.guess_type(path.name)[0],
		extension=info["extension"],
		hashes=hashes,
		metadata=metadata,
		indicators=indicators,
		evidence=evidence,
		confidence=info["confidence"],
		analysis_status=status,
		extracted_text=text,
		intelligence=intelligence,
		relationships=relationships,
		findings=findings,
		errors=errors,
	)
	report = artifact.to_dict()
	report.update({
		"file": info["path"],
		"format": info["extension"].lstrip("."),
		"detected_type": info["detected_type"],
		"extension_type": info["extension_type"],
		"type_mismatch": info["type_mismatch"],
		"readable": info["readable"],
		"legacy_indicators": legacy_indicators,
		"text": text,
		"scope": "Local, read-only extraction and hashing. File content, scripts, macros, and attachments are not executed.",
	})
	return {
		"target": info["path"],
		"type": "artifact",
		"analysis_generated_at": utc_timestamp(),
		"artifact": report,
		"findings": findings,
		"intelligence": intelligence,
		"relationships": relationships,
	}
