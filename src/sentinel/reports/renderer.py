"""Render structured SENTINEL results as JSON, CSV, or readable text."""

import csv
import json
from io import StringIO
from pathlib import Path


REPORT_FORMATS = {"json", "csv", "txt"}
REPORT_EXTENSIONS = {".json": "json", ".csv": "csv", ".txt": "txt", ".md": "txt"}


def resolve_format(output_path=None, requested_format=None):
	if requested_format:
		if requested_format not in REPORT_FORMATS:
			raise ValueError(f"Unsupported report format '{requested_format}'. Choose json, csv, or txt.")
		return requested_format
	if output_path:
		path_format = REPORT_EXTENSIONS.get(Path(output_path).suffix.lower())
		if path_format:
			return path_format
	return "json"


def _csv_rows(value, prefix=""):
	rows = []
	if isinstance(value, dict):
		for key, item in value.items():
			path = f"{prefix}.{key}" if prefix else str(key)
			rows.extend(_csv_rows(item, path))
	elif isinstance(value, list):
		for index, item in enumerate(value):
			path = f"{prefix}[{index}]"
			rows.extend(_csv_rows(item, path))
	else:
		rows.append((prefix, json.dumps(value, ensure_ascii=False) if value is None else str(value)))
	return rows


def _render_dns_section(dns):
	lines = ["[+] DNS"]
	for record_type in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA"):
		result = dns.get(record_type)
		if not isinstance(result, dict):
			continue
		records = result.get("records", [])
		if records:
			lines.append(f"{record_type}: " + " | ".join(str(record) for record in records))
		elif result.get("record_status") == "NO_RECORD" or result.get("status") == "NXDOMAIN":
			lines.append(f"{record_type}: No record")
		elif result.get("record_status") == "DNS_ERROR":
			lines.append(f"{record_type}: Resolver returned {result.get('status', 'an error')}")
		else:
			lines.append(f"{record_type}: No answer")
	return lines


def _render_recon_text(report):
	summary = report.get("target_summary", {})
	lines = [
		"SENTINEL RECONNAISSANCE",
		"=======================",
		f"Target: {report.get('target', 'unknown')}",
		f"Type: {summary.get('type', report.get('type', 'unknown'))}",
	]
	addresses = summary.get("resolved_addresses", [])
	if addresses:
		lines.append("Resolved addresses: " + ", ".join(str(address) for address in addresses))

	sources = report.get("sources", {})
	dns = sources.get("dns")
	if isinstance(dns, dict):
		lines.extend(_render_dns_section(dns))
	elif isinstance(sources.get("reverse_dns"), dict):
		reverse = sources["reverse_dns"]
		if "addresses" in reverse:
			lines.append("[+] Reverse DNS")
			for address, result in reverse["addresses"].items():
				records = result.get("records", []) if isinstance(result, dict) else []
				lines.append(f"{address}: " + (", ".join(map(str, records)) if records else "No PTR record"))
		else:
			records = reverse.get("records", [])
			lines.append("[+] Reverse DNS")
			lines.append(", ".join(map(str, records)) if records else "No PTR record found")

	rdap = sources.get("rdap")
	if isinstance(rdap, dict):
		lines.append("[+] RDAP")
		if rdap.get("error"):
			lines.append(f"Unavailable: {rdap['error']}")
		else:
			for label, key in (
				("Network", "network_range"),
				("Organization", "organization"),
				("Country", "country"),
				("ASN", "asn"),
				("Abuse contacts", "abuse_contacts"),
				("Registration", "registration_information"),
			):
				if rdap.get(key):
					lines.append(f"{label}: {rdap[key]}")

	ip_information = sources.get("ip_intelligence")
	if isinstance(ip_information, dict):
		lines.append("[+] IP intelligence")
		if ip_information.get("error"):
			lines.append(f"Unavailable: {ip_information['error']}")
		else:
			for label, key in (("ASN", "asn"), ("Organization", "organization"), ("Country", "country")):
				if ip_information.get(key):
					value = ip_information.get("asn_label") if key == "asn" else ip_information[key]
					lines.append(f"{label}: {value}")
			geo = ip_information.get("geolocation", {})
			if geo:
				lines.append(f"Geolocation: Approximate ({geo.get('provider', 'third-party provider')})")

	certificates = sources.get("certificate_transparency")
	if isinstance(certificates, dict):
		lines.append("[+] Certificate hostnames")
		if certificates.get("error"):
			lines.append(f"Unavailable: {certificates['error']}")
		else:
			hostnames = certificates.get("hostnames", certificates.get("names", []))
			lines.extend(f"  {hostname}" for hostname in hostnames[:50])
			if certificates.get("truncated") or len(hostnames) > 50:
				lines.append("  (display limited; see structured report for the complete saved set)")
	intelligence = report.get("intelligence", [])
	if intelligence:
		lines.extend(("", "INTELLIGENCE RECORDS"))
		for record in intelligence[:100]:
			value = record.get("value")
			if isinstance(value, dict):
				value = value.get("subject") or value.get("hostnames") or json.dumps(value, ensure_ascii=False)
			lines.append(
				f"{record.get('category', 'unknown')}: {value} "
				f"[{record.get('status', 'UNKNOWN')} / {record.get('confidence', 'UNKNOWN')}; "
				f"source: {record.get('source', 'unknown')}; {record.get('classification', 'unclassified')}]"
			)
			if record.get("evidence"):
				lines.append(f"  Evidence: {json.dumps(record['evidence'], ensure_ascii=False)}")
		if len(intelligence) > 100:
			lines.append(f"  (display limited; {len(intelligence) - 100} more records in structured output)")
	relationships = report.get("relationships", [])
	if relationships:
		lines.extend(("", "EVIDENCE-BACKED RELATIONSHIPS"))
		for edge in relationships[:100]:
			lines.append(
				f"{edge.get('source', '?')} --{edge.get('relationship', 'related to')}--> "
				f"{edge.get('target', '?')} [{edge.get('confidence', 'UNKNOWN')}; "
				f"source: {edge.get('source_name', 'unknown')}]"
			)
	errors = report.get("errors", [])
	if errors:
		lines.append("[!] Source errors")
		lines.extend(f"  {item.get('source')}: {item.get('message')}" for item in errors)
	lines.extend(("[+] Completed", ""))
	return "\n".join(lines)


def _render_cve_text(report):
	lines = [
		"SENTINEL VULNERABILITY INTELLIGENCE",
		"====================================",
		f"Query: {report.get('query', report.get('target', 'unknown'))}",
		f"Source: {report.get('source', 'NVD')}",
		f"Status: {str(report.get('status', 'UNKNOWN')).upper()}",
		"",
		"Potential CVE candidates (not confirmed vulnerabilities)",
	]
	results = report.get("results", [])
	if not results:
		lines.append(report.get("error", report.get("assessment_note", "No CVE records were returned.")))
	for cve in results:
		cvss = cve.get("cvss", {}) if isinstance(cve, dict) else {}
		lines.extend((
			"",
			f"{cve.get('id', 'Unknown CVE')} [{cve.get('severity', cvss.get('severity', 'UNKNOWN'))}]",
			f"CVSS: {cvss.get('score', cve.get('cvss_score', 'Unknown'))}",
			f"Published: {cve.get('published', 'Unknown')} | Modified: {cve.get('last_modified', 'Unknown')}",
			f"Status: {cve.get('status', 'POTENTIAL')} | Applicability: {cve.get('applicability', 'requires_verification')}",
			f"Description: {cve.get('description', '')}",
		))
		for reference in cve.get("references", []):
			url = reference.get("url") if isinstance(reference, dict) else reference
			if url:
				lines.append(f"Reference: {url}")
	correlations = report.get("correlations", [])
	if correlations:
		lines.extend(("", "PRODUCT/VERSION CORRELATION"))
		for correlation in correlations:
			lines.append(
				f"{correlation.get('cve_id')}: {correlation.get('status')} / "
				f"{correlation.get('applicability')} ({correlation.get('confidence')})"
			)
			lines.append(f"  {correlation.get('reason', '')}")
	lines.extend((
		"",
		"A keyword or CPE match does not by itself confirm that a system is vulnerable.",
		"",
	))
	return "\n".join(lines)


def _render_artifact_text(report):
	artifact = report.get("artifact", report)
	identity = artifact.get("identity", {})
	file_info = artifact.get("file_info", {})
	lines = [
		"SENTINEL FILE & ARTIFACT ANALYSIS",
		"==================================",
		f"Name: {identity.get('name', Path(artifact.get('path', '')).name)}",
		f"Path: {identity.get('path', artifact.get('path', 'unknown'))}",
		f"Extension: {identity.get('extension', artifact.get('extension', 'unknown'))}",
		f"Detected type: {identity.get('detected_type', artifact.get('detected_type', 'unknown'))}",
		f"MIME type: {identity.get('mime_type', artifact.get('mime_type', 'unknown')) or 'unknown'}",
		f"Size: {file_info.get('size', artifact.get('size', 'unknown'))} bytes",
		f"Analysis status: {file_info.get('analysis_status', artifact.get('analysis_status', 'UNKNOWN'))}",
		"",
		"HASHES (identification only; files were not uploaded)",
	]
	hashes = artifact.get("hashes", {})
	if hashes:
		lines.extend(f"{algorithm.upper()}: {value}" for algorithm, value in hashes.items())
		lines.append("SHA-1 and MD5, if present, are identification hashes and not security guarantees.")
	else:
		lines.append("Unavailable")
	metadata = artifact.get("metadata", {})
	lines.extend(("", "OBSERVED METADATA"))
	if metadata:
		for key, value in metadata.items():
			lines.append(f"{key}: {json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else value}")
		lines.append("Metadata values are stored file properties and are not independently verified.")
	else:
		lines.append("No metadata fields were extracted.")
	indicators = artifact.get("indicators", {})
	lines.extend(("", "INDICATORS"))
	if indicators:
		for category, items in indicators.items():
			for item in items:
				lines.append(
					f"{category}: {item.get('normalized_value', item.get('value'))} "
					f"(occurrences: {item.get('occurrence_count', 1)})"
				)
				for evidence in item.get("evidence", [])[:3]:
					lines.append(
						f"  Evidence: {evidence.get('source', 'unknown')} at offset "
						f"{evidence.get('offset', 'unknown')}: {evidence.get('context', '')}"
					)
	else:
		lines.append("No indicators extracted.")
	lines.extend(("", "FINDINGS"))
	findings = report.get("findings", artifact.get("findings", []))
	if findings:
		for finding in findings:
			lines.extend((
				"",
				f"[{finding.get('severity', 'INFO')}] {finding.get('title', 'Observation')} "
				f"({finding.get('confidence', 'UNKNOWN')} / {finding.get('status', 'OBSERVED')})",
				f"Description: {finding.get('description', '')}",
			))
			for evidence in finding.get("evidence", []):
				lines.append(f"Evidence: {json.dumps(evidence, ensure_ascii=False)}")
			lines.append(f"Recommendation: {finding.get('recommendation', '')}")
	else:
		lines.append("No findings generated from the available observations.")
	relationships = report.get("relationships", artifact.get("relationships", []))
	lines.extend(("", "ARTIFACT RELATIONSHIPS"))
	if relationships:
		for edge in relationships:
			lines.append(
				f"{edge.get('source', '?')} --{edge.get('relationship', 'related to')}--> "
				f"{edge.get('target', '?')} [{edge.get('status', 'UNKNOWN')}; "
				f"{edge.get('confidence', 'UNKNOWN')}; source: {edge.get('source_name', 'unknown')}]"
			)
	else:
		lines.append("No relationships generated.")
	if artifact.get("errors"):
		lines.extend(("", "ANALYSIS ERRORS"))
		lines.extend(f"{item.get('stage')}: {item.get('message')}" for item in artifact["errors"])
	lines.extend(("", "Files, macros, scripts, and attachment payloads were not executed.", ""))
	return "\n".join(lines)


def _render_assessment_text(report):
	lines = [
		"SENTINEL NETWORK ASSESSMENT",
		"===========================",
		f"Target: {report.get('target', 'unknown')}",
		"",
		"PORT  STATE     SERVICE       EVIDENCE",
		"----  --------  ------------  --------",
	]
	for item in report.get("ports", []):
		service = item.get("service", {})
		name = service.get("name", "unknown")
		state = item.get("status", "ERROR")
		evidence = "; ".join(
			str(observation.get("value", ""))
			for observation in service.get("evidence", [])
		) or service.get("method", "")
		lines.append(f"{item.get('port', '?'):<5} {state:<9} {name:<13} {evidence}")
	lines.extend(("", "SERVICE ANALYSIS"))
	for item in report.get("ports", []):
		service = item.get("service", {})
		lines.append(f"{item.get('port', '?')}/tcp")
		lines.append(f"  {'Service' if service.get('identification') == 'evidence_based' else 'Likely'}: {service.get('name', 'unknown')}")
		lines.append(f"  Confidence: {service.get('confidence', 'UNKNOWN')}")
		lines.append(f"  Evidence: " + "; ".join(
			str(observation.get("value", ""))
			for observation in service.get("evidence", [])
		))
		http_result = service.get("http")
		if isinstance(http_result, dict):
			if http_result.get("status_code") is not None:
				lines.append(f"  HTTP status: {http_result['status_code']}")
			for header in (
				"server",
				"content-type",
				"content-length",
				"location",
				"strict-transport-security",
				"content-security-policy",
				"x-content-type-options",
				"x-frame-options",
				"referrer-policy",
			):
				value = http_result.get("headers", {}).get(header)
				if value:
					lines.append(f"  {header}: {value}")
			tls = http_result.get("tls")
			if isinstance(tls, dict):
				lines.append(f"  TLS version: {tls.get('tls_version', 'unavailable')}")
				lines.append(f"  Certificate verification: {tls.get('certificate_verification', 'unavailable')}")
	summary = report.get("summary", {})
	if summary:
		lines.extend(("", "Summary: " + ", ".join(f"{state}: {count}" for state, count in summary.items())))
	if report.get("state_limitations"):
		lines.extend(("", "State limitation: " + str(report["state_limitations"])))
	lines.append("")
	return "\n".join(lines)


def _render_router_text(report):
	identity = report.get("router_identity", {})
	lines = [
		"SENTINEL ROUTER SECURITY ASSESSMENT",
		"===================================",
		f"Target: {report.get('target', 'unknown')}",
		f"Router: {identity.get('model') or identity.get('manufacturer') or 'Unknown'}",
		f"Identification confidence: {identity.get('model_confidence', 'UNKNOWN')}",
		f"Firmware: {identity.get('firmware', 'Unknown')}",
		f"Management transport: {report.get('management_transport', 'Unknown')}",
		"",
		"ROUTER SERVICE EXPOSURE",
		"PORT  STATE       SERVICE",
		"----  ----------  ----------------------",
	]
	for service in report.get("service_assessments", []):
		lines.append(
			f"{service.get('port', '?'):<5} {service.get('state', 'UNKNOWN'):<11} "
			f"{service.get('service', 'unknown')}"
		)
	lines.extend(("", "UPnP/SSDP: " + str(report.get("upnp", "Not assessed"))))
	findings = report.get("findings", [])
	lines.extend(("", "FINDINGS"))
	if not findings:
		lines.append("No findings were generated from the available observations.")
	for finding in findings:
		lines.extend(("", f"[{finding.get('severity', 'INFO')}] {finding.get('title', 'Observation')}"))
		lines.append(f"Evidence: {', '.join(str(item.get('value', '')) for item in finding.get('evidence', []))}")
		lines.append(f"Recommendation: {finding.get('recommendation', '')}")

	advisories = report.get("vulnerability_advisories", {})
	lines.extend(("", "VULNERABILITY INTELLIGENCE"))
	if advisories.get("status") in {"unavailable", "rate_limited"}:
		lines.append(f"Lookup unavailable: {advisories.get('error', 'NVD could not be reached')}")
	elif advisories.get("results"):
		lines.append("Potentially relevant CVEs (applicability requires verification):")
		for cve in advisories["results"]:
			lines.append(f"  {cve.get('id', 'Unknown CVE')}: {cve.get('description', '').strip()}")
	else:
		lines.append(advisories.get("reason", "No candidate CVEs were returned."))
	lines.append("A keyword match does not confirm that this router is vulnerable.")
	lines.append("")
	return "\n".join(lines)


def _render_risk_assessment_text(report):
	assessment = report["assessment"]
	lines = [
		"SENTINEL RISK ASSESSMENT",
		"========================",
		f"Target: {assessment.get('target', 'UNKNOWN')}",
		f"Overall risk: {assessment.get('risk_level', 'UNKNOWN')}",
		f"Overall score: {assessment.get('score') if assessment.get('score') is not None else 'UNRANKED'}",
		f"Findings: {assessment.get('raw_finding_count', 0)} raw; "
		f"{assessment.get('deduplicated_issue_count', 0)} deduplicated issues",
		f"Requires verification: {assessment.get('verification_required_count', 0)}",
		f"Severity counts: {json.dumps(assessment.get('severity_counts', {}), ensure_ascii=False)}",
		f"Confidence counts: {json.dumps(assessment.get('confidence_counts', {}), ensure_ascii=False)}",
		f"Rationale: {assessment.get('rationale', '')}",
		"",
		"PRIORITIZED FINDINGS",
	]
	for item in assessment.get("highest_priority_findings", []):
		lines.append(
			f"{item.get('priority', 'UNRANKED')} | {item.get('risk_level', 'UNKNOWN')} | "
			f"{item.get('score') if item.get('score') is not None else 'UNRANKED'} | "
			f"{item.get('finding_id', 'UNKNOWN')} | {item.get('title', '')}"
		)
		lines.append(f"  Priority rule: {item.get('priority_rationale', '')}")
		lines.append(f"  Recommendation: {item.get('recommendation', '')}")
		lines.append(f"  {item.get('rationale', '')}")
		for factor in item.get("factors", []):
			if factor.get("name") == "calculated_score":
				continue
			lines.append(
				f"  Factor: {factor.get('name')}={factor.get('value')} "
				f"(weight: {factor.get('weight')}, source: {factor.get('source')})"
			)
	if not assessment.get("highest_priority_findings"):
		lines.append("No findings could be assigned a remediation priority.")
	lines.extend(("", "LIMITATIONS"))
	lines.extend(f"- {limitation}" for limitation in assessment.get("limitations", []))
	source_report = {
		key: value for key, value in report.items()
		if key not in {"assessment", "risk_assessments", "risk_context"}
	}
	source_text = render_report(source_report, "txt")
	lines.extend(("", "SOURCE REPORT", "=============", source_text))
	return "\n".join(lines) + "\n"


def render_report(report, output_format="json"):
	"""Serialize a report without losing nested values or list item context."""
	if output_format not in REPORT_FORMATS:
		raise ValueError(f"Unsupported report format '{output_format}'. Choose json, csv, or txt.")
	if output_format == "json":
		return json.dumps(report, indent=2, ensure_ascii=False) + "\n"
	if output_format == "csv":
		buffer = StringIO(newline="")
		writer = csv.writer(buffer)
		writer.writerow(["Field", "Value"])
		writer.writerows(_csv_rows(report))
		return buffer.getvalue()
	if "assessment" in report and "risk_assessments" in report:
		return _render_risk_assessment_text(report)

	if "target_summary" in report and "sources" in report:
		return _render_recon_text(report)
	if report.get("source") == "NVD" and "results" in report:
		return _render_cve_text(report)
	if report.get("type") == "artifact" or "analysis_status" in report and "hashes" in report:
		return _render_artifact_text(report)
	if "service_assessments" in report and "router_identity" in report:
		return _render_router_text(report)
	if "scope" in report and "ports" in report and "summary" in report:
		return _render_assessment_text(report)
	lines = ["SENTINEL - Network & Threat Intelligence Toolkit", "=" * 48]
	for field, value in report.items():
		lines.append("")
		lines.append(str(field.replace("_", " ").title()))
		lines.append("-" * min(len(lines[-1]), 48))
		if isinstance(value, (dict, list)):
			lines.append(json.dumps(value, indent=2, ensure_ascii=False))
		else:
			lines.append(str(value))
	return "\n".join(lines) + "\n"


def export_report(report, output_path=None, output_format=None):
	"""Render a report and optionally write it to a file."""
	selected_format = resolve_format(output_path, output_format)
	serialized = render_report(report, selected_format)
	if output_path:
		path = Path(output_path)
		path.parent.mkdir(parents=True, exist_ok=True)
		path.write_text(serialized, encoding="utf-8")
	return serialized
