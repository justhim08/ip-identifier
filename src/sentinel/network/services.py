"""Identify TCP services from registered port mappings and minimal HTTP metadata."""

import ipaddress
import socket

from ..config import COMMON_PORTS as SERVICE_NAMES, DEFAULT_CONFIG
from ..router.audit import _http_head


HTTP_SERVICE_PORTS = {80, 443, 8000, 8080, 8443}


def _ssh_banner(address, port, timeout):
	"""Read a short SSH identification line when the peer presents one."""
	family = socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET
	target = (address, port, 0, 0) if family == socket.AF_INET6 else (address, port)
	try:
		with socket.socket(family, socket.SOCK_STREAM) as connection:
			connection.settimeout(timeout)
			connection.connect(target)
			banner = connection.recv(256).split(b"\n", maxsplit=1)[0].strip(b"\r")
		if not banner:
			return None
		text = banner.decode("ascii", errors="replace")
		return "".join(
			character if character.isprintable() else f"\\u{ord(character):04x}"
			for character in text
		)
	except (OSError, TimeoutError, socket.timeout):
		return None


def identify_service(address, port, status, timeout=None):
	"""Return a port-based guess plus direct evidence where safe and available."""
	normalized_status = status.upper()
	service = SERVICE_NAMES.get(port)
	identified = {
		"name": service or "unknown",
		"method": "well-known TCP port mapping" if service else "no service mapping available",
		"identification": "port_based_guess" if service else "unknown",
		"evidence": [{"source": "tcp_port", "value": f"TCP/{port}"}],
		"confidence": "MEDIUM" if service and normalized_status == "OPEN" else "LOW",
	}
	if service is None:
		try:
			service = socket.getservbyport(port, "tcp")
			identified["name"] = service
			identified["method"] = "local TCP service-name database"
			identified["identification"] = "port_based_guess"
		except OSError:
			pass
	if normalized_status == "OPEN" and port == 22:
		banner = _ssh_banner(address, port, timeout or DEFAULT_CONFIG.connection_timeout)
		if banner and banner.startswith("SSH-"):
			identified.update({
				"name": "SSH",
				"method": "observed SSH identification banner",
				"identification": "evidence_based",
				"evidence": [
					{"source": "tcp_port", "value": "TCP/22 open"},
					{"source": "ssh_banner", "value": banner},
				],
				"confidence": "HIGH",
			})
	if normalized_status == "OPEN" and port in HTTP_SERVICE_PORTS:
		scheme = "https" if port in {443, 8443} else "http"
		if timeout is None:
			http_result = _http_head(ipaddress.ip_address(address), port, scheme)
		else:
			http_result = _http_head(ipaddress.ip_address(address), port, scheme, timeout)
		identified["http"] = http_result
		if "status_code" in http_result:
			evidence = [{"source": "http_response", "value": f"HTTP status {http_result['status_code']}"}]
			if port in {443, 8443}:
				evidence.append({
					"source": "tls",
					"value": http_result.get("tls", {}).get("tls_version", "HTTPS endpoint responded"),
				})
			identified.update({
				"name": "HTTPS" if scheme == "https" else "HTTP",
				"method": "observed HTTP response",
				"identification": "evidence_based",
				"evidence": evidence,
				"confidence": "HIGH",
			})
	return identified
