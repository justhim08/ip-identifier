"""Hostname normalization and DNS resolution for CLI reconnaissance."""

import ipaddress
import socket

from ..validation import validate_target


def normalize_host(value: str) -> str:
	"""Accept a URL, hostname, or IP address and return its normalized host."""
	return validate_target(value)


def resolve_host(host: str) -> list[str]:
	"""Return unique IP addresses for a validated hostname or IP literal."""
	normalized_host = normalize_host(host)
	try:
		literal = ipaddress.ip_address(normalized_host)
	except ValueError:
		results = socket.getaddrinfo(normalized_host, None, type=socket.SOCK_STREAM)
		addresses = list(dict.fromkeys(result[4][0] for result in results))
		if not addresses:
			raise socket.gaierror(f"No IP addresses found for {normalized_host}")
		return addresses
	return [str(literal)]
