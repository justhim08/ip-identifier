"""Passive public-source enrichment for public IP addresses and domain names."""

import ipaddress
import json
import socket
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen


REQUEST_TIMEOUT = 10
MAX_RESPONSE_BYTES = 3 * 1024 * 1024
USER_AGENT = "SENTINEL/1.0 (passive OSINT lookup)"


def normalize_target(value):
	"""Return a validated domain or globally routable IP from a URL or host."""
	value = value.strip()
	if not value:
		raise ValueError("Please enter a URL, hostname, or IP address.")

	try:
		parsed = urlsplit(value if "://" in value else f"//{value}")
		host = parsed.hostname
		parsed.port
	except ValueError as exc:
		raise ValueError("That input is not a valid URL, hostname, or IP address.") from exc
	if not host:
		raise ValueError("That input does not contain a hostname or IP address.")

	try:
		address = ipaddress.ip_address(host)
	except ValueError:
		domain = host.rstrip(".").encode("idna").decode("ascii").lower()
		if len(domain) > 253 or "." not in domain:
			raise ValueError("Enter a public IP address or a fully qualified domain name.")
		labels = domain.split(".")
		if any(
			not label
			or len(label) > 63
			or not label[0].isalnum()
			or not label[-1].isalnum()
			or any(not (character.isalnum() or character == "-") for character in label)
			for label in labels
		):
			raise ValueError("The domain name contains an invalid label.")
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
	except (HTTPError, URLError, TimeoutError, socket.timeout, OSError, ValueError, json.JSONDecodeError) as exc:
		return {"error": str(exc)}


def _dns_lookup(name, record_type):
	query = urlencode({"name": name, "type": record_type})
	result = _get_json(f"https://dns.google/resolve?{query}", "application/dns-json")
	if not isinstance(result, dict):
		raise ValueError("DNS-over-HTTPS returned an unexpected response.")
	answers = result.get("Answer", [])
	if not isinstance(answers, list):
		raise ValueError("DNS-over-HTTPS returned an invalid answer list.")
	return {
		"status": result.get("Status"),
		"answers": [
			{"name": answer.get("name"), "type": answer.get("type"), "data": answer.get("data")}
			for answer in answers
			if isinstance(answer, dict)
		],
	}


def _rdap_summary(result):
	keys = (
		"objectClassName",
		"handle",
		"name",
		"country",
		"type",
		"ipVersion",
		"startAddress",
		"endAddress",
		"port43",
		"status",
		"cidr0_cidrs",
	)
	summary = {key: result[key] for key in keys if key in result}
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
		summary["entities"] = [
			{"handle": entity.get("handle"), "roles": entity.get("roles", [])}
			for entity in result["entities"]
			if isinstance(entity, dict)
		]
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
	for certificate in result:
		if isinstance(certificate, dict):
			value = certificate.get("name_value", "")
			if not isinstance(value, str):
				continue
			for name in value.splitlines():
				name = name.strip().lower().lstrip("*.")
				if name:
					names.add(name)
	sorted_names = sorted(names)
	return {"count": len(sorted_names), "names": sorted_names[:1000], "truncated": len(sorted_names) > 1000}


def lookup_osint(value):
	"""Collect public RDAP, DNS, reverse-DNS, and certificate-log information."""
	target, target_type = normalize_target(value)
	report = {
		"target": target,
		"type": target_type,
		"scope": "Passive public-source lookup; does not connect to or scan the target.",
		"sources": {},
	}

	report["sources"]["rdap"] = _source(lambda: _rdap_lookup(target, target_type))
	if target_type == "ip":
		reverse_name = ipaddress.ip_address(target).reverse_pointer
		report["sources"]["reverse_dns"] = _source(lambda: _dns_lookup(reverse_name, "PTR"))
	else:
		report["sources"]["dns"] = {
			record_type: _source(lambda record_type=record_type: _dns_lookup(target, record_type))
			for record_type in ("A", "AAAA", "MX", "NS", "TXT", "CAA")
		}
		report["sources"]["certificate_transparency"] = _source(lambda: _certificate_names(target))
	return report
