"""Non-invasive router inventory for authorized private-network assessments."""

import http.client
import ipaddress
import json
import socket
import ssl
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


ROUTER_TCP_PORTS = {
	22: "SSH",
	23: "Telnet",
	53: "DNS over TCP",
	80: "HTTP administration",
	443: "HTTPS administration",
	7547: "TR-069/CWMP",
	8080: "Alternate HTTP",
	8443: "Alternate HTTPS",
}
HTTP_PORTS = {80: "http", 443: "https", 8080: "http", 8443: "https"}
REQUEST_TIMEOUT = 0.5
NVD_TIMEOUT = 10
MAX_NVD_BYTES = 2 * 1024 * 1024
USER_AGENT = "SENTINEL/1.0 (authorized router inventory)"
ALLOWED_NETWORKS = (
	ipaddress.ip_network("10.0.0.0/8"),
	ipaddress.ip_network("172.16.0.0/12"),
	ipaddress.ip_network("192.168.0.0/16"),
	ipaddress.ip_network("169.254.0.0/16"),
	ipaddress.ip_network("127.0.0.0/8"),
	ipaddress.ip_network("fc00::/7"),
	ipaddress.ip_network("fe80::/10"),
	ipaddress.ip_network("::1/128"),
)


def _validate_router_target(value, network_value=None):
	try:
		address = ipaddress.ip_address(value.strip())
	except ValueError as exc:
		raise ValueError("Router audit requires a literal private-network IP address.") from exc
	if address.version == 6 and address.scope_id is not None:
		raise ValueError("Scoped IPv6 addresses are not supported.")
	allowed_for_address = tuple(
		network for network in ALLOWED_NETWORKS if network.version == address.version
	)
	if not any(address in network for network in allowed_for_address):
		raise ValueError("Router audit is limited to private, link-local, or loopback IP addresses.")

	network = None
	if network_value:
		try:
			network = ipaddress.ip_network(network_value, strict=False)
		except ValueError as exc:
			raise ValueError("Network must be a valid subnet in CIDR notation, such as 192.168.1.0/24.") from exc
		if network.version != address.version or address not in network:
			raise ValueError("The router IP must belong to the supplied subnet.")
		if not any(
			network.version == allowed.version and network.subnet_of(allowed)
			for allowed in ALLOWED_NETWORKS
		):
			raise ValueError("Router audit subnet must be private, link-local, or loopback.")
	return address, network


def _probe_tcp(address, port):
	family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
	target = (str(address), port, 0, 0) if family == socket.AF_INET6 else (str(address), port)
	try:
		with socket.socket(family, socket.SOCK_STREAM) as connection:
			connection.settimeout(REQUEST_TIMEOUT)
			connection.connect(target)
		return "open"
	except ConnectionRefusedError:
		return "closed"
	except (TimeoutError, socket.timeout):
		return "no response"
	except OSError as exc:
		return {"error": str(exc)}


def _http_head(address, port, scheme):
	connection_type = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
	host = f"[{address}]" if address.version == 6 else str(address)
	connection = connection_type(host, port, timeout=REQUEST_TIMEOUT)
	try:
		connection.request("HEAD", "/", headers={"User-Agent": USER_AGENT, "Connection": "close"})
		response = connection.getresponse()
		allowed_headers = (
			"server",
			"www-authenticate",
			"x-router-model",
			"x-firmware-version",
			"x-powered-by",
		)
		return {
			"status_code": response.status,
			"headers": {
				name: response.getheader(name)
				for name in allowed_headers
				if response.getheader(name)
			},
		}
	except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
		return {"error": str(exc)}
	finally:
		connection.close()


def _nvd_advisories(model, firmware):
	search_text = " ".join(value.strip() for value in (model, firmware) if value and value.strip())
	if not search_text:
		return {"status": "not_requested", "reason": "Supply --model and/or --firmware to search public NVD records."}
	if len(search_text) > 200:
		raise ValueError("Combined router model and firmware search text must not exceed 200 characters.")

	query = urlencode({"keywordSearch": search_text, "resultsPerPage": 20})
	request = Request(
		f"https://services.nvd.nist.gov/rest/json/cves/2.0?{query}",
		headers={"Accept": "application/json", "User-Agent": USER_AGENT},
	)
	try:
		with urlopen(request, timeout=NVD_TIMEOUT) as response:
			body = response.read(MAX_NVD_BYTES + 1)
		if len(body) > MAX_NVD_BYTES:
			raise ValueError("NVD response exceeded the 2 MB safety limit.")
		result = json.loads(body.decode("utf-8"))
	except (HTTPError, URLError, TimeoutError, socket.timeout, OSError, ValueError, json.JSONDecodeError) as exc:
		return {"status": "unavailable", "error": str(exc), "query": search_text}

	if not isinstance(result, dict):
		return {"status": "unavailable", "error": "NVD returned an unexpected response.", "query": search_text}
	entries = result.get("vulnerabilities", [])
	if not isinstance(entries, list):
		return {"status": "unavailable", "error": "NVD returned an invalid vulnerability list.", "query": search_text}
	vulnerabilities = []
	for entry in entries:
		if not isinstance(entry, dict):
			continue
		cve = entry.get("cve", {})
		if not isinstance(cve, dict):
			continue
		descriptions = cve.get("descriptions", [])
		if not isinstance(descriptions, list):
			descriptions = []
		description = next(
			(
				item.get("value", "")
				for item in descriptions
				if isinstance(item, dict) and item.get("lang") == "en"
			),
			"",
		)
		vulnerabilities.append({
			"id": cve.get("id"),
			"published": cve.get("published"),
			"description": description,
			"cvss": cve.get("metrics", {}),
		})
	return {
		"status": "candidates",
		"query": search_text,
		"count": result.get("totalResults", len(vulnerabilities)),
		"results": vulnerabilities,
		"assessment_note": (
			"Search results are advisory candidates, not proof of applicability. Verify affected "
			"products, exact hardware revision, firmware version, and vendor guidance before drawing conclusions."
		),
	}


def audit_router(target, model=None, firmware=None, network_value=None):
	"""Inventory a private-network router without authentication or configuration changes."""
	address, network = _validate_router_target(target, network_value)
	services = {}
	for port, name in ROUTER_TCP_PORTS.items():
		status = _probe_tcp(address, port)
		service = {"name": name, "tcp_status": status}
		if status == "open" and port in HTTP_PORTS:
			service["http_head"] = _http_head(address, port, HTTP_PORTS[port])
		services[str(port)] = service

	return {
		"target": str(address),
		"network": str(network) if network else None,
		"router_identity": {
			"model_supplied_by_user": model,
			"firmware_supplied_by_user": firmware,
			"identification_note": (
				"Values are user-provided; HTTP HEAD headers may offer hints but do not independently "
				"verify the model or firmware."
			),
		},
		"scope": (
			"Authorized private-network inventory only. Checks a fixed list of TCP ports and sends "
			"HTTP HEAD requests to detected administration ports. No login attempts, password testing, "
			"packet capture, configuration changes, UDP probing, or exploitation."
		),
		"services": services,
		"udp_services": {
			"status": "not_checked",
			"note": "UDP services such as UPnP/SSDP are not probed by this TCP-only audit.",
		},
		"vulnerability_advisories": _nvd_advisories(model, firmware),
	}
