"""Collect passive DNS, RDAP, certificate, reverse-DNS, and IP intelligence."""

import ipaddress
import json
import socket
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from ..validation import validate_hostname, validate_target

REQUEST_TIMEOUT = 10
MAX_RESPONSE_BYTES = 3 * 1024 * 1024
MAX_REVERSE_LOOKUPS = 32
USER_AGENT = "SENTINEL/1.0 (passive OSINT lookup)"
DNS_STATUS_NAMES = {
	0: "NOERROR",
	1: "FORMERR",
	2: "SERVFAIL",
	3: "NXDOMAIN",
	4: "NOTIMP",
	5: "REFUSED",
}
DNS_RECORD_TYPES = {
	1: "A",
	2: "NS",
	5: "CNAME",
	6: "SOA",
	12: "PTR",
	15: "MX",
	16: "TXT",
	28: "AAAA",
	257: "CAA",
}


def normalize_target(value):
	"""Return a validated domain or globally routable IP from a URL or host."""
	host = validate_target(value)
	try:
		address = ipaddress.ip_address(host)
	except ValueError:
		domain = validate_hostname(host)
		if "." not in domain:
			raise ValueError("Enter a public IP address or a fully qualified domain name.")
		return domain, "domain"

	if address.version == 6 and address.scope_id is not None:
		raise ValueError("Scoped IPv6 addresses are not supported for public OSINT lookups.")
	if not address.is_global:
		raise ValueError("Passive OSINT lookups are limited to globally routable IP addresses.")
	return str(address), "ip"


def _get_json(url, accept="application/json"):
	request = Request(url, headers={"Accept": accept, "User-Agent": USER_AGENT})
	with urlopen(request, timeout=REQUEST_TIMEOUT) as response:
		body = response.read(MAX_RESPONSE_BYTES + 1)
	if len(body) > MAX_RESPONSE_BYTES:
		raise ValueError("The data source response exceeded the 3 MB safety limit.")
	return json.loads(body.decode("utf-8"))


def _source(fetch):
	try:
		return fetch()
	except HTTPError as exc:
		status = "rate_limited" if exc.code == 429 else "unavailable"
		return {"status": status, "error": str(exc)}
	except (URLError, TimeoutError, socket.timeout, OSError, HTTPException, ValueError, TypeError, KeyError, AttributeError, json.JSONDecodeError) as exc:
		return {"error": str(exc)}


def _collect_source_errors(value, source_path, errors):
	if isinstance(value, dict):
		if "error" in value:
			errors.append({"source": source_path, "message": str(value["error"])})
			return
		if value.get("record_status") == "DNS_ERROR":
			errors.append({
				"source": source_path,
				"message": f"DNS resolver returned {value.get('status', 'an error')}.",
			})
		for key, child in value.items():
			_collect_source_errors(child, f"{source_path}.{key}", errors)
	elif isinstance(value, list):
		for index, child in enumerate(value):
			_collect_source_errors(child, f"{source_path}[{index}]", errors)


def _dns_lookup(name, record_type):
	query = urlencode({"name": name, "type": record_type})
	result = _get_json(f"https://dns.google/resolve?{query}", "application/dns-json")
	if not isinstance(result, dict):
		raise ValueError("DNS-over-HTTPS returned an unexpected response.")
	answers = result.get("Answer", [])
	if not isinstance(answers, list):
		raise ValueError("DNS-over-HTTPS returned an invalid answer list.")
	status_code = result.get("Status")
	status_name = DNS_STATUS_NAMES.get(status_code, "UNKNOWN")
	normalized_answers = [
		{
			"name": answer.get("name"),
			"type": DNS_RECORD_TYPES.get(answer.get("type"), answer.get("type"))
			if isinstance(answer.get("type"), int) else answer.get("type"),
			"type_code": answer.get("type"),
			"data": answer.get("data"),
		}
		for answer in answers
		if isinstance(answer, dict)
	]
	if status_name == "NXDOMAIN":
		record_status = "NO_RECORD"
	elif status_name == "NOERROR" and not normalized_answers:
		record_status = "NO_RECORD"
	elif status_name == "NOERROR":
		record_status = "FOUND"
	else:
		record_status = "DNS_ERROR"
	return {
		"status": status_name,
		"status_code": status_code,
		"record_status": record_status,
		"record_type": record_type.upper(),
		"source": "Google DNS-over-HTTPS",
		"confidence": "HIGH" if record_status in {"FOUND", "NO_RECORD"} else "UNKNOWN",
		"status_detail": "Observed DNS resolver response; record existence is not a security conclusion.",
		"answers": normalized_answers,
		"records": [answer["data"] for answer in normalized_answers if answer.get("data") is not None],
	}


def _vcard_fields(entity):
	"""Read simple scalar values from a jCard entity's vCard properties."""
	properties = entity.get("vcardArray")
	if not isinstance(properties, list) or len(properties) < 2 or not isinstance(properties[1], list):
		return {}
	fields = {}
	for item in properties[1]:
		if isinstance(item, list) and len(item) >= 4 and isinstance(item[0], str):
			fields.setdefault(item[0].lower(), []).append(item[3])
	return fields


def _rdap_summary(result):
	keys = (
		"objectClassName",
		"handle",
		"name",
		"country",
		"region",
		"asn",
		"type",
		"ipVersion",
		"startAddress",
		"endAddress",
		"port43",
		"status",
		"cidr0_cidrs",
	)
	summary = {key: result[key] for key in keys if key in result}
	if result.get("objectClassName") == "ip network":
		summary["ip"] = result.get("ipVersion")
		summary["network_range"] = {
			"start": result.get("startAddress"),
			"end": result.get("endAddress"),
			"cidrs": result.get("cidr0_cidrs", []),
		}
	else:
		summary["network_range"] = {
			"start": result.get("startAddress"),
			"end": result.get("endAddress"),
			"cidrs": result.get("cidr0_cidrs", []),
		}
	if isinstance(result.get("events"), list):
		summary["events"] = [
			{"eventAction": event.get("eventAction"), "eventDate": event.get("eventDate")}
			for event in result["events"]
			if isinstance(event, dict)
		]
	if isinstance(result.get("nameservers"), list):
		summary["nameservers"] = [
			server.get("ldhName")
			for server in result["nameservers"]
			if isinstance(server, dict) and server.get("ldhName")
		]
	if isinstance(result.get("entities"), list):
		entities = []
		organizations = []
		abuse_contacts = []
		for entity in result["entities"]:
			if not isinstance(entity, dict):
				continue
			roles = entity.get("roles", [])
			roles = roles if isinstance(roles, list) else []
			fields = _vcard_fields(entity)
			org = fields.get("org", [])
			fn = fields.get("fn", [])
			if org and isinstance(org[0], list):
				org = org[0]
			if org and isinstance(org[0], str):
				organizations.append(org[0])
			elif fn and isinstance(fn[0], str):
				organizations.append(fn[0])
			emails = [email for email in fields.get("email", []) if isinstance(email, str)]
			if "abuse" in [str(role).lower() for role in roles]:
				abuse_contacts.extend(emails)
			entities.append({
				"handle": entity.get("handle"),
				"roles": roles,
				"emails": emails,
				"organization": org[0] if org and isinstance(org[0], str) else None,
			})
		summary["entities"] = entities
		if organizations:
			summary["organization"] = organizations[0]
		if abuse_contacts:
			summary["abuse_contacts"] = sorted(set(abuse_contacts))
	if result.get("name") and "organization" not in summary:
		summary["organization"] = result["name"]
	summary["registration_information"] = {
		"events": summary.get("events", []),
		"status": summary.get("status", []),
	}
	summary["source"] = "RDAP"
	summary["confidence"] = "HIGH" if summary.get("network_range") else "MEDIUM"
	summary["status"] = summary.get("status", [])
	summary["information_note"] = (
		"Registration and network allocation data is externally reported and does not establish ownership "
		"or operational control of the target."
	)
	return summary


def _rdap_lookup(target, target_type):
	if target_type == "ip":
		path = f"ip/{target}"
	else:
		path = f"domain/{target}"
	result = _get_json(f"https://rdap.org/{path}")
	if not isinstance(result, dict):
		raise ValueError("RDAP returned an unexpected response.")
	return _rdap_summary(result)


def _certificate_names(domain):
	query = urlencode({"q": f"%.{domain}", "output": "json"})
	result = _get_json(f"https://crt.sh/?{query}")
	if not isinstance(result, list):
		raise ValueError("Certificate Transparency returned an unexpected response.")
	names = set()
	common_names = set()
	san_names = set()
	certificates = {}
	for certificate in result:
		if not isinstance(certificate, dict):
			continue
		common_name = certificate.get("common_name")
		certificate_names = set()
		if isinstance(common_name, str):
			for value in common_name.splitlines():
				name = _normalize_certificate_hostname(value)
				if name:
					common_names.add(name)
					names.add(name)
					certificate_names.add(name)
		name_value = certificate.get("name_value", "")
		if isinstance(name_value, str):
			for value in name_value.splitlines():
				name = _normalize_certificate_hostname(value)
				if name:
					names.add(name)
					certificate_names.add(name)
		explicit_sans = certificate.get("subject_alt_names", certificate.get("san", []))
		if isinstance(explicit_sans, str):
			explicit_sans = explicit_sans.splitlines()
		if isinstance(explicit_sans, list):
			for value in explicit_sans:
				if isinstance(value, str):
					name = _normalize_certificate_hostname(value)
					if name:
						san_names.add(name)
						names.add(name)
						certificate_names.add(name)
		if certificate_names:
			certificate_id = str(certificate.get("id") or "")
			certificate_key = certificate_id or "|".join(sorted(certificate_names))
			certificates[certificate_key] = {
				"id": certificate_id or None,
				"subject": common_name.strip() if isinstance(common_name, str) else None,
				"issuer": certificate.get("issuer_name"),
				"valid_from": certificate.get("not_before"),
				"valid_until": certificate.get("not_after"),
				"hostnames": sorted(certificate_names),
				"source": "Certificate Transparency",
				"confidence": "HIGH",
				"status": "OBSERVED",
			}
	sorted_names = sorted(names)
	return {
		"count": len(sorted_names),
		"names": sorted_names[:1000],
		"hostnames": sorted_names[:1000],
		"common_names": sorted(common_names)[:1000],
		"subject_alt_names": sorted(san_names)[:1000],
		"certificates": list(certificates.values())[:500],
		"certificates_truncated": len(certificates) > 500,
		"source": "Certificate Transparency",
		"confidence": "HIGH",
		"status": "OBSERVED",
		"truncated": len(sorted_names) > 1000,
		"source_note": (
			"Certificate Transparency name_value entries may combine subject and SAN names; only "
			"explicit common_name or SAN fields are separated below."
		),
	}


def _normalize_certificate_hostname(value):
	value = value.strip().lower().rstrip(".")
	if value.startswith("*."):
		value = value[2:]
	try:
		return validate_hostname(value)
	except ValueError:
		return None


def _ip_intelligence(address):
	result = _get_json(f"https://ipwho.is/{address}")
	if not isinstance(result, dict):
		raise ValueError("IP intelligence service returned an unexpected response.")
	if result.get("success") is False:
		raise ValueError(str(result.get("message", "IP intelligence lookup was unsuccessful.")))
	connection = result.get("connection") if isinstance(result.get("connection"), dict) else {}
	timezone = result.get("timezone") if isinstance(result.get("timezone"), dict) else {}
	asn = connection.get("asn")
	asn_text = str(asn) if asn is not None else ""
	asn_label = asn_text if not asn_text or asn_text.upper().startswith("AS") else f"AS{asn_text}"
	return {
		"ip": result.get("ip"),
		"type": result.get("type"),
		"continent": result.get("continent"),
		"country": result.get("country"),
		"region": result.get("region"),
		"city": result.get("city"),
		"latitude": result.get("latitude"),
		"longitude": result.get("longitude"),
		"asn": asn,
		"asn_label": asn_label or None,
		"organization": connection.get("org"),
		"isp": connection.get("isp"),
		"timezone": timezone.get("id"),
		"geolocation": {
			"precision": "approximate",
			"provider": "ipwho.is",
			"country": result.get("country"),
			"region": result.get("region"),
			"city": result.get("city"),
			"coordinates": {
				"latitude": result.get("latitude"),
				"longitude": result.get("longitude"),
			},
		},
		"note": "Approximate public IP geolocation and network-owner data; may be inaccurate.",
		"source": "ipwho.is",
		"confidence": "MEDIUM",
		"status": "externally_reported",
	}


def lookup_osint(value):
	"""Collect public RDAP, DNS, reverse-DNS, and certificate-log information."""
	from ..recon.models import ReconResult

	target, target_type = normalize_target(value)
	sources = {"rdap": _source(lambda: _rdap_lookup(target, target_type))}
	errors = []
	if target_type == "ip":
		reverse_name = ipaddress.ip_address(target).reverse_pointer
		ptr = _source(lambda: _dns_lookup(reverse_name, "PTR"))
		if isinstance(ptr, dict) and ptr.get("record_status") == "NO_RECORD":
			ptr["result"] = "No PTR record found; this is not inherently suspicious."
		sources["reverse_dns"] = ptr
		sources["ip_intelligence"] = _source(lambda: _ip_intelligence(target))
	else:
		dns_records = {
			record_type: _source(lambda record_type=record_type: _dns_lookup(target, record_type))
			for record_type in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA")
		}
		sources["dns"] = dns_records
		addresses = []
		for record_type in ("A", "AAAA"):
			response = dns_records[record_type]
			if isinstance(response, dict):
				for answer in response.get("answers", []):
					try:
						addresses.append(str(ipaddress.ip_address(answer.get("data", ""))))
					except ValueError:
						continue
		reverse_dns = {}
		unique_addresses = sorted(set(addresses))
		for address in unique_addresses[:MAX_REVERSE_LOOKUPS]:
			reverse_name = ipaddress.ip_address(address).reverse_pointer
			ptr = _source(lambda reverse_name=reverse_name: _dns_lookup(reverse_name, "PTR"))
			if isinstance(ptr, dict) and ptr.get("record_status") == "NO_RECORD":
				ptr["result"] = "No PTR record found; this is not inherently suspicious."
			reverse_dns[address] = ptr
		sources["reverse_dns"] = {
			"addresses": reverse_dns,
			"truncated": len(unique_addresses) > MAX_REVERSE_LOOKUPS,
		}
		sources["certificate_transparency"] = _source(lambda: _certificate_names(target))
	for source_name, source_result in sources.items():
		_collect_source_errors(source_result, source_name, errors)
	rdap_result = sources.get("rdap", {})
	rdap_range = rdap_result.get("network_range") if isinstance(rdap_result, dict) else None
	target_summary = {
		"input": value,
		"type": "IPv4 address" if target_type == "ip" and ipaddress.ip_address(target).version == 4
		else "IPv6 address" if target_type == "ip" else "hostname",
		"resolved_addresses": sorted(set(addresses)) if target_type == "domain" else [target],
		"network": rdap_range,
		"active_scan_performed": False,
	}
	report = ReconResult(
		target=target,
		target_type=target_type,
		sources=sources,
		target_summary=target_summary,
		errors=errors,
	).to_dict()
	from ..intel.pipeline import enrich_intelligence

	return enrich_intelligence(report)
