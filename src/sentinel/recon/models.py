"""Small structured result model for passive reconnaissance."""

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class ReconResult:
	"""Reusable, serialization-ready result of a passive reconnaissance lookup."""

	target: str
	target_type: str
	sources: Dict[str, Any] = field(default_factory=dict)
	target_summary: Dict[str, Any] = field(default_factory=dict)
	errors: List[Dict[str, str]] = field(default_factory=list)
	scope: str = "Passive public-source lookup; does not connect to or scan discovered hosts."

	def to_dict(self) -> Dict[str, Any]:
		"""Return a plain dictionary suitable for JSON, reports, and later analysis."""
		return {
			"target": self.target,
			"type": self.target_type,
			"target_summary": self.target_summary,
			"scope": self.scope,
			"sources": self.sources,
			"errors": self.errors,
		}
