"""Validated defaults and optional TOML configuration for SENTINEL."""

from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple

from .validation import (
	parse_port_ranges,
	validate_concurrency,
	validate_log_level,
	validate_port,
	validate_timeout,
)


COMMON_PORTS = {
	20: "FTP-data",
	21: "FTP",
	22: "SSH",
	23: "Telnet",
	25: "SMTP",
	53: "DNS",
	80: "HTTP",
	110: "POP3",
	143: "IMAP",
	443: "HTTPS",
	445: "SMB",
	587: "SMTP-submission",
	993: "IMAPS",
	995: "POP3S",
	1433: "MS-SQL",
	3306: "MySQL",
	3389: "RDP",
	5432: "PostgreSQL",
	8080: "HTTP-alt",
	8443: "HTTPS-alt",
}
DEFAULT_PORTS = tuple(sorted(COMMON_PORTS))
DEFAULT_TIMEOUT = 0.5
DEFAULT_CONCURRENCY = 100
REPORT_DIRECTORY = Path(".")
LOG_LEVEL = "INFO"
DEFAULT_OUTPUT_FORMAT = "json"
class ConfigurationError(ValueError):
	"""Raised when a SENTINEL configuration value is invalid or unavailable."""


@dataclass(frozen=True)
class SentinelConfig:
	"""Small validated set of scanner, reporting, and logging preferences."""

	connection_timeout: float = DEFAULT_TIMEOUT
	scanner_concurrency: int = DEFAULT_CONCURRENCY
	default_ports: Tuple[int, ...] = DEFAULT_PORTS
	report_directory: Path = REPORT_DIRECTORY
	log_level: str = LOG_LEVEL
	output_format: str = DEFAULT_OUTPUT_FORMAT
	common_ports: Dict[int, str] = field(default_factory=lambda: COMMON_PORTS.copy())

	def __post_init__(self) -> None:
		try:
			object.__setattr__(self, "connection_timeout", validate_timeout(self.connection_timeout))
			object.__setattr__(self, "scanner_concurrency", validate_concurrency(self.scanner_concurrency))
			object.__setattr__(
				self,
				"default_ports",
				tuple(sorted({validate_port(port) for port in self.default_ports})),
			)
			if not self.default_ports:
				raise ValueError("At least one default TCP port must be configured.")
			object.__setattr__(self, "report_directory", Path(self.report_directory).expanduser())
			object.__setattr__(self, "log_level", validate_log_level(self.log_level))
			if not isinstance(self.output_format, str):
				raise ValueError("Output format must be json, csv, or text.")
			output_format = self.output_format.lower()
			output_format = "txt" if output_format == "text" else output_format
			if output_format not in {"json", "csv", "txt"}:
				raise ValueError("Output format must be json, csv, or text.")
			object.__setattr__(self, "output_format", output_format)
		except (TypeError, ValueError) as exc:
			raise ConfigurationError(str(exc)) from exc

	@property
	def timeout(self) -> float:
		"""Expose the short CLI spelling while retaining the Phase 1 name."""
		return self.connection_timeout

	@property
	def concurrency(self) -> int:
		"""Expose the short CLI spelling while retaining the Phase 1 name."""
		return self.scanner_concurrency

	@property
	def ports(self) -> Tuple[int, ...]:
		"""Return the configured ports in ascending order."""
		return self.default_ports


DEFAULT_CONFIG = SentinelConfig()


def _read_toml(path: Path) -> Mapping[str, Any]:
	try:
		import tomllib
	except ImportError:
		try:
			import tomli as tomllib  # type: ignore[no-redef]
		except ImportError as exc:
			raise ConfigurationError(
				"TOML configuration on Python 3.9 or 3.10 requires the tomli package."
			) from exc

	try:
		with path.open("rb") as config_file:
			parsed = tomllib.load(config_file)
	except OSError as exc:
		raise ConfigurationError(f"Could not read configuration file '{path}': {exc}") from exc
	except (ValueError, TypeError) as exc:
		raise ConfigurationError(f"Invalid TOML configuration in '{path}': {exc}") from exc
	if not isinstance(parsed, dict):
		raise ConfigurationError("Configuration file must contain TOML tables.")
	return parsed


def _config_values(data: Mapping[str, Any], config_path: Optional[Path]) -> Dict[str, Any]:
	allowed_sections = {"scanner", "reports", "logging"}
	unexpected = set(data) - allowed_sections
	if unexpected:
		raise ConfigurationError(f"Unknown configuration section: {sorted(unexpected)[0]}")
	sections = {
		"scanner": {"timeout": "connection_timeout", "concurrency": "scanner_concurrency", "ports": "default_ports"},
		"reports": {"directory": "report_directory", "format": "output_format"},
		"logging": {"level": "log_level"},
	}
	values = {}
	for section_name, allowed_keys in sections.items():
		section = data.get(section_name, {})
		if not isinstance(section, dict):
			raise ConfigurationError(f"Configuration section [{section_name}] must be a table.")
		unexpected_keys = set(section) - set(allowed_keys)
		if unexpected_keys:
			raise ConfigurationError(
				f"Unknown key in [{section_name}]: {sorted(unexpected_keys)[0]}"
			)
		for key, value in section.items():
			field_name = allowed_keys[key]
			if field_name == "default_ports":
				if isinstance(value, str):
					try:
						value = parse_port_ranges(value)
					except ValueError as exc:
						raise ConfigurationError(f"Invalid [scanner].ports: {exc}") from exc
				elif isinstance(value, list):
					value = tuple(value)
				else:
					raise ConfigurationError("[scanner].ports must be a string or an array of port numbers.")
			if field_name == "report_directory":
				if not isinstance(value, str) or not value.strip():
					raise ConfigurationError("[reports].directory must be a non-empty path.")
				directory = Path(value).expanduser()
				if config_path is not None and not directory.is_absolute():
					directory = config_path.parent / directory
				value = directory
			values[field_name] = value
	return values


def load_config(
	config_path: Optional[str] = None,
	cli_overrides: Optional[Mapping[str, Any]] = None,
) -> SentinelConfig:
	"""Load defaults, optional TOML settings, then validated CLI overrides."""
	values: Dict[str, Any] = {}
	path = None
	if config_path is not None:
		path = Path(config_path).expanduser()
		if not path.is_file():
			raise ConfigurationError(f"Configuration file does not exist or is not a file: {path}")
		values.update(_config_values(_read_toml(path), path))

	overrides = dict(cli_overrides or {})
	aliases = {
		"timeout": "connection_timeout",
		"concurrency": "scanner_concurrency",
		"ports": "default_ports",
		"report_directory": "report_directory",
		"log_level": "log_level",
		"output_format": "output_format",
	}
	for key, value in overrides.items():
		if value is None:
			continue
		if key not in aliases:
			raise ConfigurationError(f"Unsupported configuration override: {key}")
		field_name = aliases[key]
		if field_name == "default_ports":
			try:
				value = parse_port_ranges(value) if isinstance(value, str) else tuple(value)
			except (TypeError, ValueError) as exc:
				raise ConfigurationError(f"Invalid port override: {exc}") from exc
		values[field_name] = value
	try:
		return replace(DEFAULT_CONFIG, **values)
	except (TypeError, ValueError) as exc:
		raise ConfigurationError(str(exc)) from exc
