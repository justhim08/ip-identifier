"""Structured risk assessments without replacing source findings."""

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from ..intel.models import CONFIDENCE_LEVELS, INTELLIGENCE_STATES
from ..router.findings import SEVERITY_LEVELS


RISK_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN")
PRIORITIES = ("P0", "P1", "P2", "P3", "P4", "UNRANKED")
EXPOSURE_STATES = {"PUBLIC_TARGET", "PRIVATE_TARGET", "EXPOSURE_UNKNOWN"}


@dataclass(frozen=True)
class RiskAssessment:
	"""Risk ranking for one underlying issue, retaining every supporting finding."""

	target: str
	finding_id: str
	finding_ids: List[str]
	title: str
	severity: str
	confidence: str
	status: str
	risk_level: str
	priority: str
	score: Optional[int]
	factors: List[Dict[str, Any]]
	rationale: str
	priority_rationale: str
	recommendation: str
	source_findings: List[Dict[str, Any]] = field(default_factory=list)

	def __post_init__(self) -> None:
		if not self.target.strip() or not self.finding_id.strip():
			raise ValueError("Risk assessment target and finding ID are required.")
		if self.severity not in SEVERITY_LEVELS:
			raise ValueError(f"Unsupported risk severity: {self.severity}")
		if self.confidence not in CONFIDENCE_LEVELS:
			raise ValueError(f"Unsupported risk confidence: {self.confidence}")
		if self.status not in INTELLIGENCE_STATES:
			raise ValueError(f"Unsupported risk status: {self.status}")
		if self.risk_level not in RISK_LEVELS:
			raise ValueError(f"Unsupported risk level: {self.risk_level}")
		if self.priority not in PRIORITIES:
			raise ValueError(f"Unsupported risk priority: {self.priority}")
		if self.score is not None and not 0 <= self.score <= 100:
			raise ValueError("Risk score must be between 0 and 100.")
		if self.score is None and (self.risk_level != "UNKNOWN" or self.priority != "UNRANKED"):
			raise ValueError("Unscored risk assessments must be UNKNOWN and UNRANKED.")
		if self.score is not None and (self.risk_level == "UNKNOWN" or self.priority == "UNRANKED"):
			raise ValueError("Scored risk assessments cannot be UNKNOWN or UNRANKED.")

	def to_dict(self) -> Dict[str, Any]:
		return asdict(self)


@dataclass(frozen=True)
class AssessmentSummary:
	"""Overall risk summary calculated from deduplicated issue assessments."""

	target: str
	risk_level: str
	score: Optional[int]
	raw_finding_count: int
	deduplicated_issue_count: int
	severity_counts: Dict[str, int]
	confidence_counts: Dict[str, int]
	verification_required_count: int
	priority_counts: Dict[str, int]
	highest_priority_findings: List[Dict[str, Any]]
	remediation_priorities: List[Dict[str, Any]]
	limitations: List[str]
	rationale: str

	def __post_init__(self) -> None:
		if self.risk_level not in RISK_LEVELS:
			raise ValueError(f"Unsupported assessment risk level: {self.risk_level}")
		if self.score is not None and not 0 <= self.score <= 100:
			raise ValueError("Assessment score must be between 0 and 100.")
		if self.score is None and self.risk_level != "UNKNOWN":
			raise ValueError("An unscored assessment must have UNKNOWN risk level.")
		if min(
			self.raw_finding_count,
			self.deduplicated_issue_count,
			self.verification_required_count,
			*self.severity_counts.values(),
			*self.confidence_counts.values(),
			*self.priority_counts.values(),
		) < 0:
			raise ValueError("Assessment counts cannot be negative.")

	def to_dict(self) -> Dict[str, Any]:
		return asdict(self)
