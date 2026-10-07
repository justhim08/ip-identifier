"""Reusable structured findings for router security assessments."""

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
SEVERITY_LEVELS = frozenset((*SEVERITY_ORDER, "UNKNOWN"))


def normalize_severity(value: Any = None) -> str:
	"""Return the canonical shared severity label, preserving missingness as UNKNOWN."""
	if value is None or value == "":
		return "UNKNOWN"
	if not isinstance(value, str):
		raise ValueError(f"Unsupported finding severity: {value!r}")
	normalized = value.strip().upper()
	if normalized not in SEVERITY_LEVELS:
		raise ValueError(f"Unsupported finding severity: {value}")
	return normalized


@dataclass(frozen=True)
class SecurityFinding:
	"""Evidence-backed observation with a recommendation and optional references."""

	id: str
	title: str
	severity: str
	target: str
	description: str
	evidence: List[Dict[str, Any]]
	impact: str
	recommendation: str
	port: Optional[int] = None
	service: Optional[str] = None
	references: List[str] = field(default_factory=list)
	category: str = "security_observation"
	confidence: str = "UNKNOWN"
	status: str = "OBSERVED"
	source: str = "assessment"

	def to_dict(self) -> Dict[str, Any]:
		"""Return a plain data structure suitable for report serialization."""
		return asdict(self)


def make_finding(
	finding_id: str,
	title: str,
	severity: str,
	target: str,
	description: str,
	evidence: List[Dict[str, Any]],
	impact: str,
	recommendation: str,
	port: Optional[int] = None,
	service: Optional[str] = None,
	references: Optional[List[str]] = None,
	category: str = "security_observation",
	confidence: str = "UNKNOWN",
	status: str = "OBSERVED",
	source: str = "assessment",
) -> Dict[str, Any]:
	"""Create a normalized finding dictionary for report consumers."""
	return SecurityFinding(
		id=finding_id,
		title=title,
		severity=severity,
		target=target,
		port=port,
		service=service,
		description=description,
		evidence=evidence,
		impact=impact,
		recommendation=recommendation,
		references=references or [],
		category=category,
		confidence=confidence,
		status=status,
		source=source,
	).to_dict()
