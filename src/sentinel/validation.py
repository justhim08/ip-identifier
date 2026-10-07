"""Reusable validation for command-line values and local input files."""

import ipaddress
import math
from pathlib import Path
from typing import Union
from urllib.parse import urlsplit


MAX_CONCURRENCY = 100
MIN_TIMEOUT_SECONDS = 0.1
MAX_TIMEOUT_SECONDS = 5.0


def validate_ip_address(value: str) -> str:
	"""Return a canonical IPv4 or IPv6 address or raise a useful error."""
	try:
		address = ipaddress.ip_address(value.strip())
	except (AttributeError, ValueError) as exc:
		raise ValueError(f"Invalid IP address: {value}") from exc
	if address.version == 6 and address.scope_id is not None:
		raise ValueError("Scoped IPv6 addresses are not supported.")
	return str(address)


def validate_hostname(value: str) -> str:
	"""Return a normalized hostname after validating DNS label syntax."""
	if not isinstance(value, str):
		raise ValueError(f"Invalid hostname: {value}")
	if value.strip().endswith(".."):
		raise ValueError(f"Invalid hostname: {value}")
	host = value.strip().rstrip(".")
	try:
		ascii_host = host.encode("idna").decode("ascii").lower()
	except UnicodeError as exc:
		raise ValueError(f"Invalid hostname: {value}") from exc

	if not ascii_host or len(ascii_host) > 253:
		raise ValueError(f"Invalid hostname: {value}")
	labels = ascii_host.split(".")
	if any(
		not label
		or len(label) > 63
		or not label[0].isalnum()
		or not label[-1].isalnum()
		or any(not (character.isalnum() or character == "-") for character in label)
		for label in labels
	):
		raise ValueError(f"Invalid hostname: {value}")
	return ascii_host


def validate_target(value: str) -> str:
	"""Validate a hostname, IP address, or URL and return its host component."""
	if not isinstance(value, str):
		raise ValueError("Enter a URL, hostname, or IP address.")
	candidate = value.strip()
	if not candidate:
		raise ValueError("Enter a URL, hostname, or IP address.")
	try:
		return validate_ip_address(candidate)
	except ValueError:
		pass
	try:
		parsed = urlsplit(candidate if "://" in candidate else f"//{candidate}")
		host = parsed.hostname
		parsed_port = parsed.port
	except ValueError as exc:
		raise ValueError(f"Invalid target: {value}") from exc
	if parsed.username is not None or parsed.password is not None:
		raise ValueError("Do not include credentials in target URLs.")
	if not host:
		raise ValueError(f"Invalid target: {value}")
	if parsed_port is not None:
		validate_port(parsed_port)
	try:
		return validate_ip_address(host)
	except ValueError as exc:
		if "Scoped IPv6" in str(exc):
			raise
		if all(character.isdigit() or character == "." for character in host) and "." in host:
			raise ValueError(f"Invalid IP address: {host}")
		return validate_hostname(host)


def validate_port(value: Union[int, str]) -> int:
	"""Return an integer TCP port in the valid range."""
	try:
		port = int(value)
	except (TypeError, ValueError) as exc:
		raise ValueError("Port must be between 1 and 65535.") from exc
	if isinstance(value, bool) or (isinstance(value, float) and not value.is_integer()):
		raise ValueError("Port must be between 1 and 65535.")
	if not 1 <= port <= 65535:
		raise ValueError("Port must be between 1 and 65535.")
	return port


def parse_port_ranges(value: str) -> list[int]:
	"""Parse comma-separated ports and ranges such as ``22,80,8000-8010``."""
	if not isinstance(value, str) or not value.strip():
		raise ValueError("Specify ports as numbers or ranges, for example 22,80,8000-8010.")
	ports = set()
	for item in value.split(","):
		token = item.strip()
		if not token:
			raise ValueError("Specify ports as numbers or ranges, for example 22,80,8000-8010.")
		if "-" in token:
			if token.count("-") != 1:
				raise ValueError("Specify ports as numbers or ranges, for example 22,80,8000-8010.")
			start_text, end_text = token.split("-", maxsplit=1)
			start, end = validate_port(start_text), validate_port(end_text)
			if start > end:
				raise ValueError("Port range start must not exceed its end.")
			ports.update(range(start, end + 1))
		else:
			ports.add(validate_port(token))
	return sorted(ports)


def validate_timeout(value: Union[float, str]) -> float:
	"""Validate the bounded connection timeout used for TCP checks."""
	try:
		timeout = float(value)
	except (TypeError, ValueError) as exc:
		raise ValueError(
			f"Timeout must be a number between {MIN_TIMEOUT_SECONDS:g} and {MAX_TIMEOUT_SECONDS:g} seconds."
		) from exc
	if not math.isfinite(timeout) or not MIN_TIMEOUT_SECONDS <= timeout <= MAX_TIMEOUT_SECONDS:
		raise ValueError(
			f"Timeout must be between {MIN_TIMEOUT_SECONDS:g} and {MAX_TIMEOUT_SECONDS:g} seconds."
		)
	return timeout


def validate_concurrency(value: Union[int, str]) -> int:
	"""Validate worker count to keep scans within a conservative limit."""
	try:
		concurrency = int(value)
	except (TypeError, ValueError) as exc:
		raise ValueError(f"Concurrency must be an integer between 1 and {MAX_CONCURRENCY}.") from exc
	if isinstance(value, bool) or (isinstance(value, float) and not value.is_integer()):
		raise ValueError(f"Concurrency must be an integer between 1 and {MAX_CONCURRENCY}.")
	if not 1 <= concurrency <= MAX_CONCURRENCY:
		raise ValueError(f"Concurrency must be between 1 and {MAX_CONCURRENCY}.")
	return concurrency


def validate_file_path(value: Union[str, Path]) -> Path:
	"""Resolve and validate an existing regular file supplied for local analysis."""
	path = Path(value).expanduser()
	if not path.exists():
		raise ValueError(f"File does not exist: {path}")
	if not path.is_file():
		raise ValueError(f"Path is not a file: {path}")
	return path


def validate_log_level(value: str) -> str:
	"""Normalize and validate one of SENTINEL's supported log levels."""
	if not isinstance(value, str):
		raise ValueError("Log level must be DEBUG, INFO, WARNING, or ERROR.")
	level = value.upper()
	if level not in {"DEBUG", "INFO", "WARNING", "ERROR"}:
		raise ValueError("Log level must be DEBUG, INFO, WARNING, or ERROR.")
	return level
