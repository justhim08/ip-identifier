"""Structured results for safe, local file and artifact analysis."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


ARTIFACT_STATUSES = {"COMPLETE", "PARTIAL", "FAILED"}
CONFIDENCE_LEVELS = {"CONFIRMED", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}


def _timestamp() -> str:
	return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass
class Artifact:
	"""Serialization-ready artifact identity, observations, indicators, and conclusions."""

	path: str
	detected_type: str
	size: int
	mime_type: Optional[str] = None
	extension: Optional[str] = None
	hashes: Dict[str, str] = field(default_factory=dict)
	metadata: Dict[str, Any] = field(default_factory=dict)
	indicators: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
	evidence: List[Dict[str, Any]] = field(default_factory=list)
	source: str = "local file analysis"
	confidence: str = "UNKNOWN"
	analysis_status: str = "COMPLETE"
	timestamp: str = field(default_factory=_timestamp)
	extracted_text: str = ""
	intelligence: List[Dict[str, Any]] = field(default_factory=list)
	relationships: List[Dict[str, Any]] = field(default_factory=list)
	findings: List[Dict[str, Any]] = field(default_factory=list)
	errors: List[Dict[str, str]] = field(default_factory=list)

	def __post_init__(self) -> None:
		self.path = str(Path(self.path).expanduser())
		self.confidence = self.confidence.upper()
		self.analysis_status = self.analysis_status.upper()
		if not self.path.strip():
			raise ValueError("Artifact path is required.")
		if self.size < 0:
			raise ValueError("Artifact size cannot be negative.")
		if self.analysis_status not in ARTIFACT_STATUSES:
			raise ValueError(f"Unsupported artifact analysis status: {self.analysis_status}")
		if self.confidence not in CONFIDENCE_LEVELS:
			raise ValueError(f"Unsupported artifact confidence: {self.confidence}")
		if not self.detected_type.strip():
			raise ValueError("Detected file type is required.")

	@property
	def name(self) -> str:
		"""Return the artifact's basename."""
		return Path(self.path).name

	def to_dict(self) -> Dict[str, Any]:
		"""Return the complete structured artifact report."""
		result = asdict(self)
		result["identity"] = {
			"path": self.path,
			"name": self.name,
			"extension": self.extension,
			"detected_type": self.detected_type,
			"mime_type": self.mime_type,
		}
		result["file_info"] = {
			"size": self.size,
			"source": self.source,
			"confidence": self.confidence,
			"analysis_status": self.analysis_status,
			"timestamp": self.timestamp,
		}
		return result
