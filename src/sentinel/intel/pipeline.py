"""Normalize existing passive collectors into provenance-aware intelligence."""

import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple

from .models import (
	IntelligenceRecord,
	IntelligenceRelationship,
	deduplicate_records,
	deduplicate_relationships,
	utc_timestamp,
)


def _record(
	records: List[IntelligenceRecord],
	relationships: List[IntelligenceRelationship],
	source: str,
	category: str,
	target: str,
	value: Any,
	evidence: Dict[str, Any],
	confidence: str,
	relationship: Optional[Tuple[str, str, str]] = None,
	classification: str = "externally_reported",
	status: str = "OBSERVED",
	relationship_status: str = "CORRELATED",
) -> None:
	records.append(IntelligenceRecord(
		source=source,
		category=category,
		target=target,
		value=value,
		evidence=[evidence],
		confidence=confidence,
		classification=classification,
		status=status,
	))
	if relationship:
		left, right, relation = relationship
		relationships.append(IntelligenceRelationship(
			source=left,
			target=right,
			relationship=relation,
			evidence=[evidence],
			source_name=source,
			confidence=confidence,
			status=relationship_status,
		))


def _collect_dns(
	target: str,
	dns: Dict[str, Any],
	records: List[IntelligenceRecord],
	relationships: List[IntelligenceRelationship],
) -> None:
	for record_type, result in dns.items():
		if not isinstance(result, dict) or result.get("error"):
			continue
		answers = result.get("answers", [])
		if not isinstance(answers, list):
			answers = []
		for answer in answers:
			if not isinstance(answer, dict) or not answer.get("data"):
				continue
			value = str(answer["data"]).rstrip(".")
			normalized_type = str(record_type).upper()
			confidence = "HIGH" if result.get("record_status") == "FOUND" else "UNKNOWN"
			relationship = (target, value, f"DNS {normalized_type}") if normalized_type in {
				"A", "AAAA", "CNAME", "MX", "NS", "PTR"
			} else None
			_record(
				records, relationships, "DNS resolver (Google DNS-over-HTTPS)", "DNS",
				target, value,
				{"record_type": normalized_type, "query": target, "resolver_status": result.get("status")},
				confidence, relationship,
			)
		if not answers and result.get("record_status") == "NO_RECORD":
			_record(
				records, relationships, "DNS resolver (Google DNS-over-HTTPS)", "DNS",
				target, f"No {str(record_type).upper()} record",
				{"record_type": str(record_type).upper(), "query": target, "resolver_status": result.get("status")},
				"HIGH",
			)


def _collect_records(report: Dict[str, Any]) -> Tuple[List[IntelligenceRecord], List[IntelligenceRelationship]]:
	target = str(report.get("target", "unknown"))
	sources = report.get("sources", {})
	records: List[IntelligenceRecord] = []
	relationships: List[IntelligenceRelationship] = []
	if not isinstance(sources, dict):
		sources = {}

	dns = sources.get("dns")
	if isinstance(dns, dict):
		_collect_dns(target, dns, records, relationships)

	reverse_dns = sources.get("reverse_dns")
	if isinstance(reverse_dns, dict):
		by_address = reverse_dns.get("addresses")
		if isinstance(by_address, dict):
			for address, result in by_address.items():
				if isinstance(result, dict):
					_collect_dns(str(address), {"PTR": result}, records, relationships)
		elif report.get("type") == "ip" and isinstance(reverse_dns.get("records"), list):
			_collect_dns(target, {"PTR": reverse_dns}, records, relationships)

	rdap = sources.get("rdap")
	if isinstance(rdap, dict) and not rdap.get("error"):
		for key, category, relation in (
			("network_range", "network", "IP belongs to network"),
			("organization", "organization", "IP associated with organization"),
			("country", "organization", "IP registered in country"),
			("region", "organization", "IP registered in region"),
			("asn", "network", "IP announced by ASN"),
		):
			value = rdap.get(key)
			if value:
				related_value = value
				if key == "network_range" and isinstance(value, dict):
					cidrs = value.get("cidrs", [])
					if isinstance(cidrs, list) and cidrs:
						related_value = ", ".join(
							f"{item.get('v4prefix') or item.get('v6prefix')}/{item['length']}"
							for item in cidrs
							if isinstance(item, dict) and item.get("length") is not None
						) or f"{value.get('start')} - {value.get('end')}"
					else:
						related_value = f"{value.get('start')} - {value.get('end')}"
				_record(
					records, relationships, "RDAP", category, target, value,
					{"field": key, "network_range": rdap.get("network_range")},
					"HIGH" if key in {"network_range", "country"} else "MEDIUM",
					(target, str(related_value), relation),
				)
		registration = rdap.get("registration_information")
		if registration:
			_record(
				records, relationships, "RDAP", "registration", target, registration,
				{"field": "registration_information"}, "HIGH",
			)

	ip_information = sources.get("ip_intelligence")
	if isinstance(ip_information, dict) and not ip_information.get("error"):
		address = str(ip_information.get("ip") or target)
		for key, category, relation in (
			("asn_label", "network", "IP announced by ASN"),
			("organization", "organization", "IP associated with organization"),
		):
			value = ip_information.get(key)
			if value:
				_record(
					records, relationships, "IP intelligence (ipwho.is)", category, address, value,
					{"field": key, "note": ip_information.get("note")},
					"MEDIUM",
					(address, str(value), relation),
				)
		geolocation = ip_information.get("geolocation")
		if isinstance(geolocation, dict):
			_record(
				records, relationships, "IP intelligence (ipwho.is)", "ip_intelligence",
				address, geolocation,
				{"field": "geolocation", "precision": "approximate"},
				"LOW",
			)

	certificates = sources.get("certificate_transparency")
	if isinstance(certificates, dict) and not certificates.get("error"):
		certificate_list = certificates.get("certificates", [])
		if isinstance(certificate_list, list):
			for certificate in certificate_list:
				if not isinstance(certificate, dict):
					continue
				source_id = certificate.get("id") or certificate.get("certificate_id")
				if source_id:
					certificate_id = str(source_id)
				else:
					fingerprint = hashlib.sha256(
						json.dumps(certificate, sort_keys=True, default=str).encode("utf-8")
					).hexdigest()
					certificate_id = f"derived:{fingerprint}"
				certificate_node = f"certificate:{certificate_id}"
				_record(
					records, relationships, "Certificate Transparency", "certificate",
					target, certificate, {"certificate_id": certificate_id},
					"HIGH", (target, certificate_node, "has certificate"),
				)
				names = certificate.get("hostnames", [])
				if isinstance(names, list):
					for hostname in sorted({str(name).lower().rstrip(".") for name in names if name}):
						_record(
							records, relationships, "Certificate Transparency", "hostname",
							target, hostname,
							{"certificate_id": certificate_id, "name_source": "certificate SAN/common name"},
							"HIGH", (certificate_node, hostname, "certificate names hostname"),
							"certificate_derived",
						)
		hostnames = certificates.get("hostnames", [])
		if not certificate_list and isinstance(hostnames, list):
			for hostname in sorted({str(name).lower().rstrip(".") for name in hostnames if name}):
				_record(
					records, relationships, "Certificate Transparency", "hostname",
					target, hostname,
					{"source_field": "hostnames", "source_note": certificates.get("source_note")},
					"MEDIUM", (target, hostname, "certificate-derived hostname"),
					"certificate_derived",
				)

	for port in report.get("ports", []) if isinstance(report.get("ports"), list) else []:
		service = port.get("service", {}) if isinstance(port, dict) else {}
		service_name = service.get("name") if isinstance(service, dict) else None
		port_state = str(port.get("status", "")).upper() if isinstance(port, dict) else ""
		if service_name and service_name != "unknown" and port_state == "OPEN":
			identified = service.get("identification") == "evidence_based"
			confidence = str(service.get("confidence", "LOW")).upper()
			port_number = port.get("port")
			_record(
				records, relationships,
				"Observed service response" if identified else "Well-known TCP port mapping",
				"service", target,
				{"name": service_name, "port": port_number, "protocol": "tcp", "state": port_state},
				{"service_evidence": service.get("evidence", []), "identification": service.get("identification")},
				confidence if identified else "LOW",
				(
					str(service_name),
					f"{port_number}/tcp",
					"observed on port" if identified else "suggested by port mapping",
				),
				"directly_observed" if identified else "inferred",
				"OBSERVED" if identified else "POTENTIAL",
				"CORRELATED" if identified else "POTENTIAL",
			)
		http = service.get("http", {}) if isinstance(service, dict) else {}
		headers = http.get("headers", {}) if isinstance(http, dict) else {}
		if isinstance(headers, dict) and headers.get("server"):
			value = str(headers["server"])
			_record(
				records, relationships, "Observed HTTP response", "technology",
				f"{target}:{port.get('port')}", value,
				{"header": "Server", "response_status": http.get("status_code")},
				"HIGH",
				(f"{target}:{port.get('port')}", value, "service reports technology"),
				"directly_observed",
			)
		for evidence in service.get("evidence", []) if isinstance(service, dict) else []:
			if isinstance(evidence, dict) and evidence.get("source") == "ssh_banner":
				_record(
					records, relationships, "Observed service banner", "technology",
					f"{target}:{port.get('port')}", evidence.get("value"),
					{"banner": evidence.get("value")},
					"HIGH",
					(f"{target}:{port.get('port')}", str(evidence.get("value")), "service presents banner"),
					"directly_observed",
				)

	services = report.get("services")
	if isinstance(services, dict):
		for port, observation in services.items():
			if not isinstance(observation, dict):
				continue
			http = observation.get("http_head", observation.get("http", {}))
			headers = http.get("headers", {}) if isinstance(http, dict) else {}
			endpoint = f"{target}:{port}"
			if isinstance(headers, dict):
				for header_name in ("server", "x-powered-by"):
					value = headers.get(header_name)
					if value:
						_record(
							records, relationships, "Observed HTTP response", "technology",
							endpoint, value,
							{"header": header_name, "status_code": http.get("status_code")},
							"HIGH",
							(endpoint, str(value), "service reports technology"),
							"directly_observed",
						)
			tls = http.get("tls") if isinstance(http, dict) else None
			if isinstance(tls, dict) and not tls.get("error"):
				cert_id = str(tls.get("certificate_sha256") or f"{endpoint}:tls-certificate")
				cert_node = f"certificate:{cert_id}"
				certificate = {
					"subject": tls.get("certificate_subject") or tls.get("subject"),
					"issuer": tls.get("certificate_issuer") or tls.get("issuer"),
					"valid_from": tls.get("valid_from"),
					"valid_until": tls.get("valid_until"),
					"hostnames": sorted({
						str(name).lower().rstrip(".")
						for name in tls.get("hostnames", [])
						if isinstance(name, str) and name
					}),
					"certificate_verification": tls.get("certificate_verification"),
					"tls_version": tls.get("tls_version"),
				}
				_record(
					records, relationships, "Observed TLS certificate", "tls_certificate",
					endpoint, certificate,
					{"endpoint": endpoint, "verification": tls.get("certificate_verification")},
					"HIGH", (endpoint, cert_node, "presents TLS certificate"),
					"directly_observed",
				)
				for hostname in certificate["hostnames"]:
					_record(
						records, relationships, "Observed TLS certificate", "hostname",
						endpoint, hostname,
						{"certificate_id": cert_id, "name_source": "TLS certificate SAN"},
						"HIGH", (cert_node, hostname, "certificate names hostname"),
						"certificate_derived",
					)

	service_assessments = report.get("service_assessments")
	if isinstance(service_assessments, list):
		for service in service_assessments:
			if not isinstance(service, dict) or service.get("state") != "OPEN":
				continue
			name = service.get("service")
			port = service.get("port")
			if not name or port is None:
				continue
			_record(
				records, relationships, "Well-known router TCP port mapping", "service",
				target,
				{"name": name, "port": port, "protocol": "tcp", "state": "OPEN"},
				{"service_evidence": service.get("evidence", [])},
				"LOW",
				(str(name), f"{port}/tcp", "suggested by port mapping"),
				"inferred",
				"POTENTIAL",
				"POTENTIAL",
			)
	advisories = report.get("vulnerability_advisories")
	if isinstance(advisories, dict) and isinstance(advisories.get("results"), list):
		for cve in advisories["results"]:
			if not isinstance(cve, dict) or not cve.get("id"):
				continue
			_record(
				records, relationships, str(cve.get("source", "NVD")), "vulnerability",
				target, cve,
				{"query": advisories.get("query"), "applicability": cve.get("applicability")},
				"HIGH",
				status="POTENTIAL",
			)
		for correlation in advisories.get("correlations", []):
			if not isinstance(correlation, dict) or not correlation.get("cve_id"):
				continue
			product = correlation.get("product", {})
			if not isinstance(product, dict):
				continue
			product_name = " ".join(
				str(product.get(key)).strip()
				for key in ("vendor", "product", "version")
				if product.get(key)
			)
			if not product_name:
				continue
			relationships.append(IntelligenceRelationship(
				source=product_name,
				target=str(correlation["cve_id"]),
				relationship="potentially affected by",
				evidence=[{"source": "NVD", "value": correlation.get("reason", "")}],
				source_name="NVD",
				confidence=str(correlation.get("confidence", "UNKNOWN")),
				status=str(correlation.get("status", "REQUIRES_VERIFICATION")),
			))

	return records, relationships


def enrich_intelligence(report: Dict[str, Any]) -> Dict[str, Any]:
	"""Add deduplicated intelligence records and relationships without discarding source data."""
	records, relationships = _collect_records(report)
	result = dict(report)
	result["intelligence"] = [item.to_dict() for item in deduplicate_records(records)]
	result["relationships"] = [item.to_dict() for item in deduplicate_relationships(relationships)]
	result["intelligence_generated_at"] = utc_timestamp()
	return result
