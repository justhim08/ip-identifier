"""Pure, deterministic risk calculations over existing structured findings."""

import math
import re
from dataclasses import asdict, is_dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from ..intel.models import CONFIDENCE_LEVELS, INTELLIGENCE_STATES
from ..router.findings import SecurityFinding, SEVERITY_ORDER, normalize_severity
from .models import AssessmentSummary, EXPOSURE_STATES, PRIORITIES, RiskAssessment


SEVERITY_POINTS = {
	"CRITICAL": 100,
	"HIGH": 75,
	"MEDIUM": 50,
	"LOW": 25,
	"INFO": 5,
}
CONFIDENCE_WEIGHTS = {
	"CONFIRMED": 1.0,
	"HIGH": 0.85,
	"MEDIUM": 0.65,
	"LOW": 0.35,
}
STATUS_WEIGHTS = {
	"CONFIRMED": 1.0,
	"OBSERVED": 0.9,
	"CORRELATED": 0.75,
	"POTENTIAL": 0.6,
	"REQUIRES_VERIFICATION": 0.4,
}
EXPOSURE_WEIGHTS = {
	"PUBLIC_TARGET": 1.05,
	"PRIVATE_TARGET": 0.95,
	"EXPOSURE_UNKNOWN": 1.0,
}
RISK_THRESHOLDS = (
	(85, "CRITICAL"),
	(65, "HIGH"),
	(40, "MEDIUM"),
	(15, "LOW"),
)
PRIORITY_ORDER = {priority: index for index, priority in enumerate(PRIORITIES)}
def _canonical_level(value: Any, levels: Iterable[str], field: str) -> str:
	if value is None or value == "":
		return "UNKNOWN"
	if not isinstance(value, str):
		raise ValueError(f"Unsupported finding {field}: {value!r}")
	normalized = value.strip().upper()
	if normalized not in levels:
		raise ValueError(f"Unsupported finding {field}: {value}")
	return normalized


def _as_finding_dict(finding: Any) -> Dict[str, Any]:
	if isinstance(finding, SecurityFinding):
		return finding.to_dict()
	if is_dataclass(finding):
		finding = asdict(finding)
	if not isinstance(finding, Mapping):
		raise TypeError("Each finding must be a mapping or a SecurityFinding.")
	return dict(finding)


def _normalized_finding(finding: Any, index: int, target: Optional[str]) -> Dict[str, Any]:
	source = _as_finding_dict(finding)
	normalized = dict(source)
	normalized["id"] = str(source.get("id") or f"FINDING-{index + 1:04d}")
	normalized["target"] = str(source.get("target") or target or "UNKNOWN")
	normalized["source_severity"] = source.get("severity")
	normalized["severity"] = normalize_severity(source.get("severity"))
	normalized["confidence"] = _canonical_level(
		source.get("confidence"), CONFIDENCE_LEVELS, "confidence",
	)
	normalized["status"] = _canonical_level(
		source.get("status"), INTELLIGENCE_STATES, "status",
	)
	normalized["category"] = str(source.get("category") or "security_observation")
	normalized["source"] = str(source.get("source") or "unknown")
	normalized["title"] = str(source.get("title") or normalized["id"])
	normalized["evidence"] = source.get("evidence") or []
	if not isinstance(normalized["evidence"], list):
		raise ValueError(f"Finding {normalized['id']} evidence must be a list.")
	normalized["recommendation"] = str(source.get("recommendation") or "")
	return normalized


def _deduplication_key(finding: Mapping[str, Any]) -> Tuple[str, ...]:
	explicit_key = finding.get("risk_key")
	if explicit_key:
		return (
			"explicit",
			str(finding["target"]).strip().casefold(),
			str(explicit_key).strip().casefold(),
		)
	cve = finding.get("cve")
	if cve:
		issue = str(cve).strip().casefold()
	else:
		issue = re.sub(r"\s+", " ", str(finding["title"]).strip().casefold())
	port = finding.get("port")
	return (
		str(finding["target"]).strip().casefold(),
		str(finding["category"]).strip().casefold(),
		str(port) if port is not None else "",
		issue,
	)


def _score_finding(
	finding: Mapping[str, Any],
	exposure: str,
	exposure_source: str,
) -> Tuple[Optional[int], str, str, List[Dict[str, Any]]]:
	severity = finding["severity"]
	confidence = finding["confidence"]
	status = finding["status"]
	factors: List[Dict[str, Any]] = [
		{
			"name": "finding_severity",
			"value": severity,
			"source_value": finding.get("source_severity"),
			"weight": SEVERITY_POINTS.get(severity),
			"source": finding["source"],
			"evidence": finding["evidence"],
		},
		{
			"name": "finding_confidence",
			"value": confidence,
			"weight": CONFIDENCE_WEIGHTS.get(confidence),
			"source": finding["source"],
			"evidence": finding["evidence"],
		},
		{
			"name": "finding_status",
			"value": status,
			"weight": STATUS_WEIGHTS.get(status),
			"source": finding["source"],
			"evidence": finding["evidence"],
		},
		{
			"name": "target_exposure",
			"value": exposure,
			"weight": EXPOSURE_WEIGHTS[exposure],
			"source": exposure_source,
			"confidence": "LOW" if exposure_source == "operator-provided context" else (
				"UNKNOWN" if exposure == "EXPOSURE_UNKNOWN" else "HIGH"
			),
			"evidence": [],
		},
	]
	if severity == "UNKNOWN" or confidence == "UNKNOWN" or status == "UNKNOWN":
		return None, "UNKNOWN", "UNRANKED", factors

	raw_score = (
		SEVERITY_POINTS[severity]
		* CONFIDENCE_WEIGHTS[confidence]
		* STATUS_WEIGHTS[status]
		* EXPOSURE_WEIGHTS[exposure]
	)
	score = max(0, min(100, math.floor(raw_score + 0.5)))
	risk_level = next(
		(level for threshold, level in RISK_THRESHOLDS if score >= threshold),
		"INFO",
	)
	priority = _priority_for(score, severity, confidence, status, exposure)
	factors.append({
		"name": "calculated_score",
		"value": score,
		"formula": (
			f"clamp(round_half_up({SEVERITY_POINTS[severity]} * "
			f"{CONFIDENCE_WEIGHTS[confidence]:.2f} * {STATUS_WEIGHTS[status]:.2f} * "
			f"{EXPOSURE_WEIGHTS[exposure]:.2f}), 0, 100)"
		),
		"source": "SENTINEL deterministic risk formula",
		"evidence": [],
	})
	return score, risk_level, priority, factors


def _priority_for(
	score: int,
	severity: str,
	confidence: str,
	status: str,
	exposure: str,
) -> str:
	if (
		score >= 85
		and severity == "CRITICAL"
		and confidence in {"CONFIRMED", "HIGH"}
		and status == "CONFIRMED"
		and exposure == "PUBLIC_TARGET"
	):
		return "P0"
	if (
		score >= 60
		and severity in {"CRITICAL", "HIGH"}
		and confidence in {"CONFIRMED", "HIGH"}
		and status in {"CONFIRMED", "OBSERVED", "CORRELATED"}
	):
		return "P1"
	if (
		score >= 40
		and severity in {"CRITICAL", "HIGH", "MEDIUM"}
		and confidence in {"CONFIRMED", "HIGH", "MEDIUM"}
		and status in {"CONFIRMED", "OBSERVED", "CORRELATED"}
	):
		return "P2"
	if score >= 15:
		return "P3"
	return "P4"


def _rationale(
	finding: Mapping[str, Any],
	score: Optional[int],
	risk_level: str,
	exposure: str,
	supporting_count: int,
	members: List[Mapping[str, Any]],
) -> str:
	unknown_support = sorted({
		field
		for member in members
		for field in ("severity", "confidence", "status")
		if member[field] == "UNKNOWN"
	})
	if score is None:
		return (
			"Risk is unranked because " + ", ".join(unknown_support)
			+ " is UNKNOWN; no score or priority was manufactured."
		)
	rationale = (
		f"Score {score}/100 maps to {risk_level}: severity {finding['severity']} "
		f"({SEVERITY_POINTS[finding['severity']]} base), confidence {finding['confidence']} "
		f"({CONFIDENCE_WEIGHTS[finding['confidence']]:.2f}), status {finding['status']} "
		f"({STATUS_WEIGHTS[finding['status']]:.2f}), and exposure {exposure} "
		f"({EXPOSURE_WEIGHTS[exposure]:.2f})."
	)
	if supporting_count > 1:
		rationale += (
			f" {supporting_count} source findings support this deduplicated issue; "
			"the highest individual score represents it and the issue contributes once "
			"to the overall score."
		)
	if finding.get("applicability") in {"requires_verification", "unknown"} or finding["status"] == "REQUIRES_VERIFICATION":
		rationale += " CVE or product applicability remains unverified."
	if exposure == "EXPOSURE_UNKNOWN":
		rationale += " Exposure was not supplied and was not inferred from the target address."
	if unknown_support:
		rationale += (
			" Supporting findings also contain UNKNOWN "
			+ ", ".join(unknown_support)
			+ " values; see the preserved source findings."
		)
	return rationale


def _priority_rationale(priority: str) -> str:
	rules = {
		"P0": (
			"P0 requires score >=85, CRITICAL severity, HIGH or CONFIRMED confidence, "
			"CONFIRMED status, and explicitly supplied public exposure."
		),
		"P1": (
			"P1 requires score >=60, CRITICAL or HIGH severity, HIGH or CONFIRMED confidence, "
			"and CONFIRMED, OBSERVED, or CORRELATED status."
		),
		"P2": (
			"P2 requires score >=40, CRITICAL/HIGH/MEDIUM severity, MEDIUM-or-higher confidence, "
			"and CONFIRMED, OBSERVED, or CORRELATED status."
		),
		"P3": "P3 is a known score >=15 that does not meet P0, P1, or P2 criteria.",
		"P4": "P4 is a known score below 15; it is informational and is not an unranked result.",
		"UNRANKED": "UNRANKED means severity, confidence, or status is UNKNOWN; no priority was assigned.",
	}
	return rules[priority]


def assess_findings(
	findings: Iterable[Any],
	target: Optional[str] = None,
	exposure: str = "EXPOSURE_UNKNOWN",
	exposure_source: str = "not supplied",
) -> Dict[str, Any]:
	"""Assess existing findings only; this function performs no collection or I/O."""
	exposure = _canonical_level(exposure, EXPOSURE_STATES, "exposure")
	if exposure not in EXPOSURE_WEIGHTS:
		raise ValueError(f"Unsupported finding exposure: {exposure}")
	normalized_findings = [
		_normalized_finding(item, index, target)
		for index, item in enumerate(findings)
	]
	target_value = str(target or next(
		(item["target"] for item in normalized_findings if item["target"] != "UNKNOWN"),
		"UNKNOWN",
	))
	groups: Dict[Tuple[str, ...], List[Dict[str, Any]]] = {}
	for finding in normalized_findings:
		groups.setdefault(_deduplication_key(finding), []).append(finding)

	assessments: List[RiskAssessment] = []
	for members in groups.values():
		candidates = []
		for finding in members:
			score, risk_level, priority, factors = _score_finding(finding, exposure, exposure_source)
			candidates.append((finding, score, risk_level, priority, factors))
		selected = max(
			candidates,
			key=lambda item: (
				item[1] is not None,
				item[1] if item[1] is not None else -1,
				-SEVERITY_ORDER.index(item[0]["severity"])
				if item[0]["severity"] in SEVERITY_ORDER else -len(SEVERITY_ORDER),
				item[0]["id"],
			),
		)
		finding, score, risk_level, priority, factors = selected
		finding_ids = sorted({item["id"] for item in members})
		evidence_by_source = []
		seen_evidence = set()
		for item in members:
			for evidence_item in item["evidence"]:
				key = repr(sorted(evidence_item.items())) if isinstance(evidence_item, dict) else repr(evidence_item)
				if key not in seen_evidence:
					seen_evidence.add(key)
					evidence_by_source.append({
						"finding_id": item["id"],
						"source": item["source"],
						"evidence": evidence_item,
					})
		if factors and evidence_by_source:
			factors = [dict(factor) for factor in factors]
			for factor in factors:
				if factor["name"] in {"finding_severity", "finding_confidence", "finding_status"}:
					factor["supporting_evidence"] = evidence_by_source
		recommendations = sorted({
			item["recommendation"] for item in members if item["recommendation"]
		})
		assessment = RiskAssessment(
			target=finding["target"],
			finding_id=finding["id"],
			finding_ids=finding_ids,
			title=finding["title"],
			severity=finding["severity"],
			confidence=finding["confidence"],
			status=finding["status"],
			risk_level=risk_level,
			priority=priority,
			score=score,
			factors=factors,
			rationale=_rationale(
				finding,
				score,
				risk_level,
				exposure,
				len(members),
				members,
			),
			priority_rationale=_priority_rationale(priority),
			recommendation=" | ".join(recommendations),
			source_findings=[dict(item) for item in members],
		)
		assessments.append(assessment)

	assessments.sort(key=lambda item: (
		PRIORITY_ORDER[item.priority],
		-(item.score if item.score is not None else -1),
		item.target.casefold(),
		item.finding_id,
	))
	summary = _summarize(target_value, normalized_findings, assessments)
	return {
		"assessment": summary.to_dict(),
		"risk_assessments": [item.to_dict() for item in assessments],
	}


def _summarize(
	target: str,
	findings: List[Dict[str, Any]],
	assessments: List[RiskAssessment],
) -> AssessmentSummary:
	severity_counts = {level: 0 for level in (*SEVERITY_ORDER, "UNKNOWN")}
	confidence_counts = {level: 0 for level in ("CONFIRMED", "HIGH", "MEDIUM", "LOW", "UNKNOWN")}
	priority_counts = {priority: 0 for priority in PRIORITIES}
	for assessment in assessments:
		severity_counts[assessment.severity] += 1
		confidence_counts[assessment.confidence] += 1
		priority_counts[assessment.priority] += 1
	scores = [item.score for item in assessments if item.score is not None]
	overall_score = None
	if scores:
		# A max-plus-mean aggregate limits severity while preserving issue breadth.
		overall_score = max(0, min(100, math.floor(0.7 * max(scores) + 0.3 * (sum(scores) / len(scores)) + 0.5)))
	overall_level = "UNKNOWN"
	if overall_score is not None:
		overall_level = next(
			(level for threshold, level in RISK_THRESHOLDS if overall_score >= threshold),
			"INFO",
		)
	verification_count = sum(
		any(item["status"] == "REQUIRES_VERIFICATION" for item in assessment.source_findings)
		for assessment in assessments
	)
	priority_items = [
		{
			"priority": priority,
			"count": priority_counts[priority],
			"finding_ids": [
				item.finding_id for item in assessments if item.priority == priority
			],
		}
		for priority in PRIORITIES if priority_counts[priority]
	]
	highest_priority = [
		item.to_dict() for item in assessments if item.priority != "UNRANKED"
	][:10]
	limitations = [
		"Assessment uses only findings present in the supplied report; it performs no scans, lookups, or file inspection.",
		"Exploitability, compromise, attacker intent, and missing asset context are not inferred.",
	]
	if any(item.status == "REQUIRES_VERIFICATION" for item in assessments):
		limitations.append("One or more findings require verification; their status remains uncertain.")
	if any(
		finding[field] == "UNKNOWN"
		for finding in findings
		for field in ("severity", "confidence", "status")
	):
		limitations.append(
			"Findings with UNKNOWN severity, confidence, or status remain unranked or are "
			"preserved as uncertain supporting evidence."
		)
	if any(
		factor["name"] == "target_exposure" and factor["value"] == "EXPOSURE_UNKNOWN"
		for item in assessments for factor in item.factors
	):
		limitations.append("Target exposure was unknown unless explicitly supplied by the operator.")
	if not findings:
		rationale = "No findings were supplied; this is not evidence that the target is risk-free."
	elif overall_score is None:
		rationale = "No finding had sufficient known severity, confidence, and status to calculate a score."
	else:
		rationale = (
			f"Overall score {overall_score}/100 is 70% of the highest deduplicated issue score "
			"plus 30% of the mean score across deduplicated issues; issue scores are not summed."
		)
	return AssessmentSummary(
		target=target,
		risk_level=overall_level,
		score=overall_score,
		raw_finding_count=len(findings),
		deduplicated_issue_count=len(assessments),
		severity_counts=severity_counts,
		confidence_counts=confidence_counts,
		verification_required_count=verification_count,
		priority_counts=priority_counts,
		highest_priority_findings=highest_priority,
		remediation_priorities=priority_items,
		limitations=limitations,
		rationale=rationale,
	)


def assess_report(
	report: Mapping[str, Any],
	exposure: str = "EXPOSURE_UNKNOWN",
	exposure_source: str = "not supplied",
) -> Dict[str, Any]:
	"""Return the source report with a risk summary, without modifying its findings."""
	if not isinstance(report, Mapping):
		raise TypeError("A SENTINEL report must be a mapping.")
	original = dict(report)
	findings = original.get("findings")
	if findings is None:
		artifact = original.get("artifact")
		findings = artifact.get("findings", []) if isinstance(artifact, Mapping) else []
	if not isinstance(findings, list):
		raise ValueError("Report findings must be a list.")
	artifact = original.get("artifact")
	target = original.get("target")
	if target is None and isinstance(artifact, Mapping):
		target = artifact.get("path")
	assessment = assess_findings(
		findings,
		target=str(target) if target is not None else None,
		exposure=exposure,
		exposure_source=exposure_source,
	)
	result = dict(original)
	result.update(assessment)
	result["risk_context"] = {
		"exposure": exposure,
		"source": exposure_source,
	}
	return result
