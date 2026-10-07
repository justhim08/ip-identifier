"""Controlled TCP port selection and scanning helpers."""

import errno
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..config import DEFAULT_CONFIG
from ..validation import parse_port_ranges, validate_concurrency, validate_timeout


parse_ports = parse_port_ranges


def scan_port(address: str, port: int, timeout: float) -> tuple[int, str]:
	"""Classify one TCP connection without inferring more than the OS reports."""
	family = socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET
	target = (address, port, 0, 0) if family == socket.AF_INET6 else (address, port)
	try:
		with socket.socket(family, socket.SOCK_STREAM) as connection:
			connection.settimeout(timeout)
			connection.connect(target)
		status = "OPEN"
	except ConnectionRefusedError:
		status = "CLOSED"
	except (TimeoutError, socket.timeout):
		status = "TIMEOUT"
	except OSError as exc:
		status = classify_socket_error(exc)
	return port, status


def scan_ports(
	address: str,
	ports: list[int],
	timeout: float = DEFAULT_CONFIG.connection_timeout,
	max_workers: int = DEFAULT_CONFIG.scanner_concurrency,
) -> list[tuple[int, str]]:
	"""Scan the selected TCP ports with bounded concurrency and sort the results."""
	max_workers = validate_concurrency(max_workers)
	timeout = validate_timeout(timeout)
	try:
		ipaddress.ip_address(address)
	except ValueError as exc:
		raise ValueError("TCP scanning requires a literal IP address.") from exc
	if not ports:
		raise ValueError("Select at least one TCP port to scan.")
	if any(not 1 <= port <= 65535 for port in ports):
		raise ValueError("Ports must be between 1 and 65535.")

	results = []
	with ThreadPoolExecutor(max_workers=max_workers) as executor:
		futures = [executor.submit(scan_port, address, port, timeout) for port in ports]
		for future in as_completed(futures):
			results.append(future.result())
	results.sort()
	return results


def classify_socket_error(error: OSError) -> str:
	"""Classify a socket error conservatively for callers and offline tests."""
	if isinstance(error, ConnectionRefusedError) or error.errno == errno.ECONNREFUSED:
		return "CLOSED"
	if isinstance(error, (TimeoutError, socket.timeout)) or error.errno == errno.ETIMEDOUT:
		return "TIMEOUT"
	if isinstance(error, PermissionError) or error.errno in {errno.EACCES, errno.EPERM}:
		return "FILTERED"
	return "ERROR"
