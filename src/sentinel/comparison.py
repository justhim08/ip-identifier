"""Deterministic baseline and posture comparison for saved SENTINEL assessments."""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


CHANGE_TYPES = ("NEW", "RESOLVED", "NOT_OBSERVED", "CHANGED", "UNCHANGED", "UNKNOWN")
RISK_IMPACT_LEVELS = ("POSITIVE", "NEGATIVE", "NEUTRAL", "UNKNOWN")
VOLATILE_KEYS = {
    "timestamp",
    "generated_at",
    "created_at",
    "updated_at",
    "last_updated",
    "saved_at",
    "report_timestamp",
    "assessment_time",
    "run_time",
}


def normalize_assessment(report: Mapping[str, Any]) -> Dict[str, Any]:
    """Return a canonical, ordering-stable view of a SENTINEL assessment."""
    normalized = _normalize_value(report)
    if isinstance(normalized, dict):
        normalized.pop("comparison_metadata", None)
    return normalized


def normalize_finding(finding: Mapping[str, Any]) -> Dict[str, Any]:
    """Normalize the relevant fields for reproducible finding comparisons."""
    if not isinstance(finding, Mapping):
        raise TypeError("A finding must be a mapping or dictionary.")
    normalized = dict(finding)
    for key in ("target", "title", "category", "service", "risk_key", "id", "finding_id", "cve", "cve_id"):
        if key in normalized and normalized[key] is not None:
            normalized[key] = str(normalized[key]).strip()
    if "target" in normalized:
        normalized["target"] = _canonical_text(normalized["target"]) or "UNKNOWN"
    if "title" in normalized:
        normalized["title"] = _canonical_text(normalized["title"]) or "UNKNOWN"
    if "service" in normalized:
        normalized["service"] = _canonical_text(normalized["service"]) or "UNKNOWN"
    if "category" in normalized:
        normalized["category"] = _canonical_text(normalized["category"]) or "security_observation"
    if "severity" in normalized:
        normalized["severity"] = _canonical_text(normalized["severity"]) or "UNKNOWN"
    if "confidence" in normalized:
        normalized["confidence"] = _canonical_text(normalized["confidence"]) or "UNKNOWN"
    if "status" in normalized:
        normalized["status"] = _canonical_text(normalized["status"]) or "UNKNOWN"
    return _normalize_value(normalized)


@dataclass(frozen=True)
class Baseline:
    """Explicit saved assessment used as the comparison baseline."""

    baseline_id: str
    target: str
    source_report: Dict[str, Any]
    assessment: Dict[str, Any]
    findings: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    comparison_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["finding_count"] = len(self.findings)
        return data


def create_baseline(report: Mapping[str, Any], baseline_id: Optional[str] = None) -> Baseline:
    """Create a deterministic baseline representation from a saved assessment."""
    source = copy.deepcopy(dict(report))
    target = str(source.get("target") or source.get("assessment", {}).get("target") or "UNKNOWN").strip() or "UNKNOWN"
    findings = _iter_findings(source)
    baseline_key = baseline_id or source.get("baseline_id") or _stable_hash(source)
    timestamp_value = source.get("timestamp") or source.get("generated_at") or "UNKNOWN"
    return Baseline(
        baseline_id=str(baseline_key),
        target=target,
        source_report=source,
        assessment=normalize_assessment(source),
        findings=findings,
        metadata={
            "target": target,
            "assessment_timestamp": timestamp_value,
            "recorded_at": timestamp_value,
            "source_report": source.get("source_report") if isinstance(source.get("source_report"), dict) else "UNKNOWN",
        },
        comparison_metadata={
            "normalization_version": "1.0",
            "identity_strategy": "risk_key -> id -> cve -> port/service/title",
            "volatile_fields_stripped": sorted(VOLATILE_KEYS),
        },
    )


@dataclass(frozen=True)
class ComparisonChange:
    """A single change between the current assessment and the baseline."""

    change_type: str
    target: str
    finding_identity: str
    previous_state: Dict[str, Any]
    current_state: Dict[str, Any]
    changed_fields: List[str]
    evidence: List[Dict[str, Any]]
    confidence: str
    risk_impact: str
    priority: str
    rationale: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ComparisonResult:
    """Structured posture comparison output."""

    baseline_id: str
    baseline_target: str
    current_target: str
    baseline_assessment: Dict[str, Any]
    current_assessment: Dict[str, Any]
    changes: List[ComparisonChange]
    counts: Dict[str, int]
    posture_summary: Dict[str, Any]
    score_delta: Optional[int]
    previous_score: Optional[int]
    current_score: Optional[int]
    previous_risk_level: Optional[str]
    current_risk_level: Optional[str]
    risk_impact: str

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["changes"] = [change.to_dict() for change in self.changes]
        return payload


def compare_assessments(current: Mapping[str, Any], baseline: Union[Mapping[str, Any], Baseline]) -> ComparisonResult:
    """Compare a current assessment against a saved baseline.

    The comparison is deterministic, preserves source data, and never mutates the
    original baseline or current report structures.
    """
    baseline_item = baseline if isinstance(baseline, Baseline) else create_baseline(baseline)
    current_report = copy.deepcopy(dict(current))
    baseline_findings = baseline_item.findings
    current_findings = _iter_findings(current_report)
    baseline_by_identity = { _finding_identity(item): item for item in baseline_findings }
    current_by_identity = { _finding_identity(item): item for item in current_findings }

    changes: List[ComparisonChange] = []

    for identity, current_finding in current_by_identity.items():
        if identity in baseline_by_identity:
            previous_finding = baseline_by_identity[identity]
            changed_fields = _changed_fields(previous_finding, current_finding)
            if changed_fields:
                changes.append(
                    ComparisonChange(
                        change_type="CHANGED",
                        target=current_finding.get("target") or baseline_item.target,
                        finding_identity=identity,
                        previous_state=previous_finding,
                        current_state=current_finding,
                        changed_fields=changed_fields,
                        evidence=_evidence(previous_finding, current_finding),
                        confidence=_confidence_for_change(previous_finding, current_finding),
                        risk_impact=_risk_impact_for_change(previous_finding, current_finding, "CHANGED"),
                        priority=_priority_for_change(previous_finding, current_finding),
                        rationale=_rationale_for_change(previous_finding, current_finding, "CHANGED", changed_fields),
                    )
                )
            else:
                changes.append(
                    ComparisonChange(
                        change_type="UNCHANGED",
                        target=current_finding.get("target") or baseline_item.target,
                        finding_identity=identity,
                        previous_state=previous_finding,
                        current_state=current_finding,
                        changed_fields=[],
                        evidence=_evidence(previous_finding, current_finding),
                        confidence=_confidence_for_change(previous_finding, current_finding),
                        risk_impact="NEUTRAL",
                        priority=_priority_for_change(previous_finding, current_finding),
                        rationale=_rationale_for_change(previous_finding, current_finding, "UNCHANGED", []),
                    )
                )
        else:
            changes.append(
                ComparisonChange(
                    change_type="NEW",
                    target=current_finding.get("target") or baseline_item.target,
                    finding_identity=identity,
                    previous_state={},
                    current_state=current_finding,
                    changed_fields=[_first_changed_field(current_finding)],
                    evidence=current_finding.get("evidence", []),
                    confidence=_value_for(current_finding, "confidence", "UNKNOWN"),
                    risk_impact=_risk_impact_for_change({}, current_finding, "NEW"),
                    priority=_priority_for_change({}, current_finding),
                    rationale=_rationale_for_change({}, current_finding, "NEW", ["newly observed"]),
                )
            )

    for identity, baseline_finding in baseline_by_identity.items():
        if identity not in current_by_identity:
            change_type = _missing_finding_status(baseline_finding, current_report)
            changes.append(
                ComparisonChange(
                    change_type=change_type,
                    target=baseline_finding.get("target") or baseline_item.target,
                    finding_identity=identity,
                    previous_state=baseline_finding,
                    current_state={},
                    changed_fields=["missing_from_current_assessment"],
                    evidence=baseline_finding.get("evidence", []),
                    confidence=_value_for(baseline_finding, "confidence", "UNKNOWN"),
                    risk_impact=_risk_impact_for_change(baseline_finding, {}, change_type),
                    priority=_priority_for_change(baseline_finding, {}),
                    rationale=_rationale_for_change(baseline_finding, {}, change_type, ["missing_from_current_assessment"]),
                )
            )

    counts = {change_type: 0 for change_type in CHANGE_TYPES}
    for change in changes:
        counts[change.change_type] = counts.get(change.change_type, 0) + 1

    score_delta, previous_score, current_score, previous_risk_level, current_risk_level = _risk_summary(
        baseline_item.source_report,
        current_report,
    )
    posture_summary = {
        "baseline_target": baseline_item.target,
        "current_target": str(current_report.get("target") or current_report.get("assessment", {}).get("target") or baseline_item.target),
        "previous_score": previous_score,
        "current_score": current_score,
        "score_delta": score_delta,
        "previous_risk_level": previous_risk_level,
        "current_risk_level": current_risk_level,
        "overall_posture_change": _overall_posture_change(score_delta, counts),
        "new_findings_count": counts["NEW"],
        "resolved_findings_count": counts["RESOLVED"],
        "not_observed_count": counts["NOT_OBSERVED"],
        "changed_findings_count": counts["CHANGED"],
        "unchanged_findings_count": counts["UNCHANGED"],
        "unknown_count": counts["UNKNOWN"],
        "limitations": [
            "This comparison is based on saved assessment data and does not infer compromise, remediation, or attacker activity.",
            "Missing observations are treated conservatively as NOT_OBSERVED unless a clear corresponding assessment is present.",
        ],
    }

    result = ComparisonResult(
        baseline_id=baseline_item.baseline_id,
        baseline_target=baseline_item.target,
        current_target=str(current_report.get("target") or current_report.get("assessment", {}).get("target") or baseline_item.target),
        baseline_assessment=baseline_item.assessment,
        current_assessment=normalize_assessment(current_report),
        changes=sorted(changes, key=lambda item: (item.change_type, item.finding_identity)),
        counts=counts,
        posture_summary=posture_summary,
        score_delta=score_delta,
        previous_score=previous_score,
        current_score=current_score,
        previous_risk_level=previous_risk_level,
        current_risk_level=current_risk_level,
        risk_impact=_overall_risk_impact(score_delta, counts),
    )
    return result


def compare_reports(baseline_report: Mapping[str, Any], current_report: Mapping[str, Any]) -> Dict[str, Any]:
    """Convenience wrapper returning a serializable comparison payload."""
    return compare_assessments(current_report, baseline_report).to_dict()


def _normalize_value(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            if key in VOLATILE_KEYS:
                continue
            cleaned[key] = _normalize_value(item)
        return {key: cleaned[key] for key in sorted(cleaned)}
    if isinstance(value, list):
        normalized = [_normalize_value(item) for item in value]
        try:
            return sorted(normalized, key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
        except TypeError:
            return normalized
    if isinstance(value, tuple):
        return [_normalize_value(item) for item in value]
    if isinstance(value, str):
        return value.strip()
    return value


def _canonical_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().casefold()


def _stable_hash(value: Any) -> str:
    digest = hashlib.sha256(json.dumps(_normalize_value(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()[:16]
    return f"baseline-{digest}"


def _iter_findings(report: Mapping[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for key in ("findings", "issues", "observations", "results"):
        candidates = report.get(key, [])
        if isinstance(candidates, list):
            for item in candidates:
                if isinstance(item, Mapping):
                    findings.append(dict(item))
    if not findings:
        for key in ("risk_assessments", "risk_assessment"):
            candidates = report.get(key, [])
            if isinstance(candidates, list):
                for item in candidates:
                    if isinstance(item, Mapping):
                        source_findings = item.get("source_findings", [])
                        if isinstance(source_findings, list):
                            for finding in source_findings:
                                if isinstance(finding, Mapping):
                                    findings.append(dict(finding))
    return [normalize_finding(item) for item in findings]


def _finding_identity(finding: Mapping[str, Any]) -> str:
    target = str(finding.get("target") or "UNKNOWN").strip().casefold()
    category = str(finding.get("category") or "security_observation").strip().casefold()
    risk_key = str(finding.get("risk_key") or "").strip().casefold()
    if risk_key:
        return f"risk_key:{target}:{category}:{risk_key}"
    finding_id = str(finding.get("id") or finding.get("finding_id") or "").strip().casefold()
    if finding_id:
        return f"id:{target}:{category}:{finding_id}"
    cve = str(finding.get("cve") or finding.get("cve_id") or "").strip().casefold()
    if cve:
        return f"cve:{target}:{category}:{cve}"
    service = str(finding.get("service") or "").strip().casefold()
    port = str(finding.get("port") or "").strip().casefold()
    title = str(finding.get("title") or "").strip().casefold()
    return f"title:{target}:{category}:{port}:{service}:{title}"


def _changed_fields(previous: Mapping[str, Any], current: Mapping[str, Any]) -> List[str]:
    candidate_fields = (
        "severity",
        "confidence",
        "status",
        "exposure",
        "service",
        "port",
        "product",
        "version",
        "cve",
        "risk_level",
        "risk_score",
        "priority",
        "title",
    )
    changed: List[str] = []
    for field_name in candidate_fields:
        previous_value = _value_for(previous, field_name, "UNKNOWN")
        current_value = _value_for(current, field_name, "UNKNOWN")
        if previous_value != current_value:
            changed.append(field_name)
    return changed


def _value_for(payload: Mapping[str, Any], key: str, default: Any = None) -> Any:
    value = payload.get(key)
    if value is None:
        value = payload.get("risk_assessment", {}).get(key)
    return str(value).strip() if isinstance(value, str) else (default if value is None else value)


def _confidence_for_change(previous: Mapping[str, Any], current: Mapping[str, Any]) -> str:
    if current:
        return _value_for(current, "confidence", "UNKNOWN")
    if previous:
        return _value_for(previous, "confidence", "UNKNOWN")
    return "UNKNOWN"


def _first_changed_field(current: Mapping[str, Any]) -> str:
    for field_name in ("severity", "confidence", "status", "service", "port", "title"):
        if field_name in current:
            return field_name
    return "new_observation"


def _evidence(previous: Mapping[str, Any], current: Mapping[str, Any]) -> List[Dict[str, Any]]:
    evidence: List[Dict[str, Any]] = []
    for mapping in (previous, current):
        item = mapping.get("evidence")
        if isinstance(item, list):
            evidence.extend([dict(entry) if isinstance(entry, dict) else {"value": entry} for entry in item])
    return evidence or [{"source": "comparison", "value": "evidence retained from both assessments"}]


def _risk_impact_for_change(previous: Mapping[str, Any], current: Mapping[str, Any], change_type: str) -> str:
    if change_type == "RESOLVED":
        return "POSITIVE"
    if change_type == "NEW":
        severity = _value_for(current, "severity", "UNKNOWN")
        return "NEGATIVE" if severity in {"HIGH", "CRITICAL", "MEDIUM"} else "NEUTRAL"
    if change_type == "CHANGED":
        previous_severity = _value_for(previous, "severity", "UNKNOWN")
        current_severity = _value_for(current, "severity", "UNKNOWN")
        if previous_severity in {"HIGH", "CRITICAL"} and current_severity in {"LOW", "INFO", "UNKNOWN"}:
            return "POSITIVE"
        if current_severity in {"HIGH", "CRITICAL"} and previous_severity in {"LOW", "INFO", "UNKNOWN"}:
            return "NEGATIVE"
        return "NEUTRAL"
    if change_type == "UNCHANGED":
        return "NEUTRAL"
    if change_type == "NOT_OBSERVED":
        return "UNKNOWN"
    return "UNKNOWN"


def _priority_for_change(previous: Mapping[str, Any], current: Mapping[str, Any]) -> str:
    if current:
        priority = _value_for(current, "priority", "")
        if priority:
            return str(priority).upper()
        severity = _value_for(current, "severity", "UNKNOWN")
        if severity in {"CRITICAL", "HIGH"}:
            return "P1"
        if severity == "MEDIUM":
            return "P2"
        if severity == "LOW":
            return "P3"
        return "P4"
    if previous:
        priority = _value_for(previous, "priority", "")
        if priority:
            return str(priority).upper()
    return "UNRANKED"


def _rationale_for_change(previous: Mapping[str, Any], current: Mapping[str, Any], change_type: str, changed_fields: Sequence[str]) -> str:
    if change_type == "NEW":
        return f"A new observation was detected in the current assessment: {', '.join(changed_fields) or 'new issue'}"
    if change_type == "RESOLVED":
        return "The baseline finding is no longer present in the current assessment and is treated as resolved only when the current evidence supports that conclusion."
    if change_type == "NOT_OBSERVED":
        return "The prior observation is absent from the current assessment, but comparable evidence is insufficient to claim resolution."
    if change_type == "CHANGED":
        changed = ", ".join(changed_fields) if changed_fields else "observed attributes"
        return f"The finding remained comparable but the following fields changed: {changed}."
    if change_type == "UNCHANGED":
        return "The finding remains materially unchanged in both assessments."
    return "The relationship between the findings could not be determined with enough confidence."


def _missing_finding_status(baseline_finding: Mapping[str, Any], current_report: Mapping[str, Any]) -> str:
    """Treat missing findings conservatively: only claim resolution when explicit negative evidence is present."""
    port = baseline_finding.get("port")
    service = baseline_finding.get("service")
    current_service_map = _service_port_map(current_report)

    if port is not None:
        port_key = str(port)
        if port_key in current_service_map:
            service_state = current_service_map[port_key].get("state") if isinstance(current_service_map[port_key], Mapping) else None
            if isinstance(service_state, str) and service_state.lower() in {"closed", "not_observed", "filtered", "disabled", "offline"}:
                return "RESOLVED"
            if isinstance(service_state, str) and service_state.lower() in {"open", "listen", "observed"}:
                return "NOT_OBSERVED"

    service_values = []
    for container in (current_report.get("services"), current_report.get("observed_services"), current_report.get("tcp_services")):
        if isinstance(container, dict):
            service_values.extend(str(item).lower() for item in container.values())
        elif isinstance(container, list):
            for item in container:
                if isinstance(item, str):
                    service_values.append(item.lower())
                elif isinstance(item, Mapping):
                    service_values.append(str(item.get("service") or item.get("name") or "").lower())

    if service and service.lower() in service_values:
        return "NOT_OBSERVED"

    if port is not None and str(port) in {str(k).lower() for k in current_service_map.keys()}:
        return "NOT_OBSERVED"

    if not current_report.get("findings") and not current_report.get("risk_assessments") and not current_report.get("services") and not current_report.get("observed_services"):
        return "NOT_OBSERVED"

    return "NOT_OBSERVED"


def _service_port_map(report: Mapping[str, Any]) -> Dict[str, Any]:
    ports: Dict[str, Any] = {}
    for field in ("services", "observed_services", "open_ports", "tcp_services"):
        value = report.get(field)
        if isinstance(value, dict):
            for key, item in value.items():
                ports[str(key)] = item
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    ports[item] = {"service": item}
                elif isinstance(item, Mapping):
                    port = item.get("port") or item.get("service") or item.get("name")
                    if port is not None:
                        ports[str(port)] = item
    return ports


def _risk_summary(baseline_report: Mapping[str, Any], current_report: Mapping[str, Any]) -> Tuple[Optional[int], Optional[int], Optional[int], Optional[str], Optional[str]]:
    baseline_score = _summary_score(baseline_report)
    current_score = _summary_score(current_report)
    baseline_level = _summary_risk_level(baseline_report)
    current_level = _summary_risk_level(current_report)
    if baseline_score is None or current_score is None:
        score_delta = None
    else:
        score_delta = current_score - baseline_score
    return score_delta, baseline_score, current_score, baseline_level, current_level


def _summary_score(report: Mapping[str, Any]) -> Optional[int]:
    for field in ("score", "risk_score", "overall_score"):
        value = report.get(field)
        if isinstance(value, int):
            return value
    summary = report.get("summary") or report.get("assessment_summary") or report.get("risk_summary")
    if isinstance(summary, Mapping):
        value = summary.get("score")
        if isinstance(value, int):
            return value
    risk_assessments = report.get("risk_assessments", [])
    if isinstance(risk_assessments, list):
        total = 0
        for item in risk_assessments:
            if isinstance(item, Mapping):
                score = item.get("score")
                if isinstance(score, int):
                    total += score
        if total:
            return total
    return None


def _summary_risk_level(report: Mapping[str, Any]) -> Optional[str]:
    for field in ("risk_level", "overall_risk_level"):
        value = report.get(field)
        if isinstance(value, str):
            return value.upper()
    summary = report.get("summary") or report.get("assessment_summary") or report.get("risk_summary")
    if isinstance(summary, Mapping):
        value = summary.get("risk_level")
        if isinstance(value, str):
            return value.upper()
    return None


def _overall_posture_change(score_delta: Optional[int], counts: Mapping[str, int]) -> str:
    if score_delta is not None:
        return "NEGATIVE" if score_delta > 0 else "POSITIVE" if score_delta < 0 else "NEUTRAL"
    if counts.get("NEW", 0) > counts.get("RESOLVED", 0):
        return "NEGATIVE"
    if counts.get("RESOLVED", 0) > counts.get("NEW", 0):
        return "POSITIVE"
    if counts.get("CHANGED", 0):
        return "NEGATIVE" if counts.get("CHANGED", 0) else "NEUTRAL"
    return "NEUTRAL"


def _overall_risk_impact(score_delta: Optional[int], counts: Mapping[str, int]) -> str:
    if score_delta is not None:
        if score_delta > 0:
            return "NEGATIVE"
        if score_delta < 0:
            return "POSITIVE"
        return "NEUTRAL"
    if counts.get("NEW", 0):
        return "NEGATIVE"
    if counts.get("RESOLVED", 0):
        return "POSITIVE"
    return "NEUTRAL"
