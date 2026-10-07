"""Provenance-preserving models for passive intelligence and relationships."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional


CONFIDENCE_LEVELS = {"CONFIRMED", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
INTELLIGENCE_STATES = {
	"OBSERVED",
	"CORRELATED",
	"POTENTIAL",
	"REQUIRES_VERIFICATION",
	"CONFIRMED",
	"UNKNOWN",
}


def utc_timestamp() -> str:
	"""Return a timezone-aware UTC timestamp in stable ISO-8601 form."""
	return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass
class IntelligenceRecord:
	"""One sourced observation or correlation suitable for JSON serialization."""

	source: str
	category: str
	target: str
	value: Any
	evidence: List[Dict[str, Any]]
	confidence: str = "UNKNOWN"
	timestamp: str = field(default_factory=utc_timestamp)
	relationship: Optional[str] = None
	status: str = "OBSERVED"
	classification: str = "externally_reported"
	provenance: List[str] = field(default_factory=list)

	def __post_init__(self) -> None:
		self.confidence = self.confidence.upper()
		self.status = self.status.upper()
		if self.confidence not in CONFIDENCE_LEVELS:
			raise ValueError(f"Unsupported intelligence confidence: {self.confidence}")
		if self.status not in INTELLIGENCE_STATES:
			raise ValueError(f"Unsupported intelligence status: {self.status}")
		if not self.source.strip() or not self.category.strip() or not self.target.strip():
			raise ValueError("Intelligence source, category, and target are required.")
		if not self.provenance:
			self.provenance = [self.source]

	def to_dict(self) -> Dict[str, Any]:
		"""Return a JSON-ready representation without losing provenance."""
		return asdict(self)


@dataclass(frozen=True)
class IntelligenceRelationship:
	"""An evidence-backed directional relationship between two known values."""

	source: str
	target: str
	relationship: str
	evidence: List[Dict[str, Any]]
	source_name: str
	confidence: str = "UNKNOWN"
	status: str = "CORRELATED"
	timestamp: str = field(default_factory=utc_timestamp)

	def __post_init__(self) -> None:
		confidence = self.confidence.upper()
		status = self.status.upper()
		if confidence not in CONFIDENCE_LEVELS:
			raise ValueError(f"Unsupported relationship confidence: {confidence}")
		if status not in INTELLIGENCE_STATES:
			raise ValueError(f"Unsupported relationship status: {status}")
		if not self.source or not self.target or not self.relationship or not self.source_name:
			raise ValueError("Relationship endpoints, type, and source are required.")
		object.__setattr__(self, "confidence", confidence)
		object.__setattr__(self, "status", status)

	def to_dict(self) -> Dict[str, Any]:
		"""Return a JSON-ready representation."""
		return asdict(self)


def deduplicate_records(records: List[IntelligenceRecord]) -> List[IntelligenceRecord]:
	"""Merge duplicate facts while preserving all evidence and contributing sources."""
	merged: Dict[tuple, IntelligenceRecord] = {}
	for record in records:
		key = (
			record.category.casefold(),
			record.target.casefold(),
			json.dumps(record.value, sort_keys=True, default=str).casefold(),
			(record.relationship or "").casefold(),
		)
		current = merged.get(key)
		if current is None:
			merged[key] = record
			continue
		current.evidence.extend(
			evidence for evidence in record.evidence if evidence not in current.evidence
		)
		current.provenance = sorted(set(current.provenance + record.provenance))
		if current.source != record.source:
			current.source = "Multiple sources"
		if current.confidence != record.confidence:
			current.confidence = "UNKNOWN"
		if current.status != record.status:
			current.status = "CORRELATED"
	return list(merged.values())


def deduplicate_relationships(
	relationships: List[IntelligenceRelationship],
) -> List[IntelligenceRelationship]:
	"""Deduplicate edges without discarding source or evidence provenance."""
	merged: Dict[tuple, IntelligenceRelationship] = {}
	for edge in relationships:
		key = (edge.source.casefold(), edge.target.casefold(), edge.relationship.casefold())
		current = merged.get(key)
		if current is None:
			merged[key] = edge
			continue
		sources = sorted(set(current.source_name.split("; ") + edge.source_name.split("; ")))
		evidence = current.evidence + [
			item for item in edge.evidence if item not in current.evidence
		]
		merged[key] = IntelligenceRelationship(
			source=current.source,
			target=current.target,
			relationship=current.relationship,
			evidence=evidence,
			source_name="; ".join(sources),
			confidence=current.confidence if current.confidence == edge.confidence else "UNKNOWN",
			status="CORRELATED",
		)
	return list(merged.values())
