import contextlib
import csv
import io
import json
import tempfile
import unittest
from pathlib import Path

from sentinel.cli import main, run_assessment
from sentinel.reports.renderer import render_report
from sentinel.risk.engine import assess_findings, assess_report
from sentinel.risk.models import RiskAssessment
from sentinel.router.findings import (
	SecurityFinding,
	SEVERITY_LEVELS,
	SEVERITY_ORDER,
	normalize_severity,
)


def finding(
	finding_id="F-1",
	title="Router administration exposed",
	severity="HIGH",
	confidence="HIGH",
	status="CONFIRMED",
	**fields,
):
	return {
		"id": finding_id,
		"title": title,
		"severity": severity,
		"target": "192.0.2.10",
		"description": "Observed issue.",
		"evidence": [{"source": "test fixture", "value": "observed"}],
		"recommendation": "Review the configuration.",
		"category": "management_interface_observation",
		"confidence": confidence,
		"status": status,
		"source": "test",
		**fields,
	}


class SeverityAndValidationTests(unittest.TestCase):
	def test_severity_levels_and_order_are_shared_and_deterministic(self):
		self.assertEqual(SEVERITY_ORDER, ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))
		self.assertEqual(
			SEVERITY_LEVELS,
			frozenset(("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN")),
		)
		self.assertEqual(normalize_severity(" high "), "HIGH")
		self.assertEqual(normalize_severity(None), "UNKNOWN")
		with self.assertRaisesRegex(ValueError, "Unsupported finding severity"):
			normalize_severity("SEVERE")

	def test_source_severity_is_preserved_while_assessment_uses_canonical_value(self):
		source = finding(severity=" high ")
		report = assess_report({"target": source["target"], "findings": [source]})
		risk = report["risk_assessments"][0]
		factor = next(item for item in risk["factors"] if item["name"] == "finding_severity")
		self.assertEqual(report["findings"][0]["severity"], " high ")
		self.assertEqual(risk["severity"], "HIGH")
		self.assertEqual(factor["source_value"], " high ")

	def test_unknown_severity_is_not_scored_or_converted(self):
		result = assess_findings([finding(severity="UNKNOWN")])
		risk = result["risk_assessments"][0]
		self.assertIsNone(risk["score"])
		self.assertEqual(risk["risk_level"], "UNKNOWN")
		self.assertEqual(risk["priority"], "UNRANKED")
		self.assertIn("severity is UNKNOWN", risk["rationale"])

	def test_missing_confidence_and_status_remain_unknown(self):
		for removed in ("confidence", "status"):
			item = finding()
			item.pop(removed)
			with self.subTest(field=removed):
				risk = assess_findings([item])["risk_assessments"][0]
				self.assertIsNone(risk["score"])
				self.assertEqual(risk["risk_level"], "UNKNOWN")
				self.assertEqual(risk["priority"], "UNRANKED")
		unknown_status = assess_findings([finding(status="UNKNOWN")])["risk_assessments"][0]
		self.assertIsNone(unknown_status["score"])
		self.assertEqual(unknown_status["status"], "UNKNOWN")

	def test_invalid_confidence_status_and_exposure_fail_clearly(self):
		with self.assertRaisesRegex(ValueError, "confidence"):
			assess_findings([finding(confidence="CERTAIN")])
		with self.assertRaisesRegex(ValueError, "status"):
			assess_findings([finding(status="EXPLOITED")])
		with self.assertRaisesRegex(ValueError, "exposure"):
			assess_findings([finding()], exposure="INTERNET")

	def test_shared_finding_model_is_accepted_without_replacement(self):
		original = SecurityFinding(
			id="MODEL-1",
			title="Observed finding",
			severity="HIGH",
			target="192.0.2.10",
			description="Stored finding model",
			evidence=[{"source": "fixture"}],
			impact="Potential impact",
			recommendation="Review it",
			confidence="HIGH",
			status="OBSERVED",
		)
		risk = assess_findings([original])["risk_assessments"][0]
		self.assertEqual(risk["finding_id"], original.id)
		self.assertEqual(risk["source_findings"][0]["evidence"], original.evidence)
		self.assertEqual(original.severity, "HIGH")

	def test_risk_model_validates_score_and_canonical_input_levels(self):
		with self.assertRaisesRegex(ValueError, "between 0 and 100"):
			RiskAssessment(
				target="test",
				finding_id="F-1",
				finding_ids=["F-1"],
				title="Out of range",
				severity="HIGH",
				confidence="HIGH",
				status="OBSERVED",
				risk_level="HIGH",
				priority="P1",
				score=101,
				factors=[],
				rationale="",
				priority_rationale="",
				recommendation="",
			)


class RiskCalculationTests(unittest.TestCase):
	def test_formula_is_deterministic_bounded_and_explainable(self):
		first = assess_findings([finding()])
		second = assess_findings([finding()])
		self.assertEqual(first, second)
		risk = first["risk_assessments"][0]
		self.assertEqual(risk["score"], 64)
		self.assertEqual(risk["risk_level"], "MEDIUM")
		self.assertEqual(risk["priority"], "P1")
		formula = next(item for item in risk["factors"] if item["name"] == "calculated_score")
		self.assertIn("75 * 0.85 * 1.00 * 1.00", formula["formula"])
		self.assertTrue(all(0 <= item["score"] <= 100 for item in first["risk_assessments"] if item["score"] is not None))

	def test_documented_worked_example_matches_risk_level_and_priority(self):
		risk = assess_findings([
			finding(severity="HIGH", confidence="HIGH", status="OBSERVED")
		])["risk_assessments"][0]
		self.assertEqual(risk["score"], 57)
		self.assertEqual(risk["risk_level"], "MEDIUM")
		self.assertEqual(risk["priority"], "P2")

	def test_all_known_severities_have_explicit_base_values(self):
		expected_points = {"CRITICAL": 100, "HIGH": 75, "MEDIUM": 50, "LOW": 25, "INFO": 5}
		for severity, points in expected_points.items():
			with self.subTest(severity=severity):
				result = assess_findings([finding(severity=severity, confidence="CONFIRMED", status="CONFIRMED")])
				factor = next(
					item for item in result["risk_assessments"][0]["factors"]
					if item["name"] == "finding_severity"
				)
				self.assertEqual(factor["weight"], points)

	def test_known_score_boundaries_include_one_and_one_hundred(self):
		minimum = assess_findings([
			finding(severity="INFO", confidence="LOW", status="REQUIRES_VERIFICATION")
		])["risk_assessments"][0]
		maximum = assess_findings(
			[finding(severity="CRITICAL", confidence="CONFIRMED", status="CONFIRMED")],
			exposure="PUBLIC_TARGET",
		)["risk_assessments"][0]
		self.assertEqual(minimum["score"], 1)
		self.assertEqual(maximum["score"], 100)

	def test_confidence_changes_risk_without_changing_severity(self):
		scores = {}
		for confidence in ("CONFIRMED", "HIGH", "MEDIUM", "LOW"):
			result = assess_findings([finding(severity="HIGH", confidence=confidence)])
			scores[confidence] = result["risk_assessments"][0]["score"]
		self.assertGreater(scores["CONFIRMED"], scores["HIGH"])
		self.assertGreater(scores["HIGH"], scores["MEDIUM"])
		self.assertGreater(scores["MEDIUM"], scores["LOW"])

	def test_status_weights_keep_potential_and_verification_uncertain(self):
		scores = {}
		for status in (
			"CONFIRMED", "OBSERVED", "CORRELATED", "POTENTIAL", "REQUIRES_VERIFICATION",
		):
			result = assess_findings([finding(status=status)])
			scores[status] = result["risk_assessments"][0]["score"]
		self.assertGreater(scores["CONFIRMED"], scores["OBSERVED"])
		self.assertGreater(scores["OBSERVED"], scores["CORRELATED"])
		self.assertGreater(scores["CORRELATED"], scores["POTENTIAL"])
		self.assertGreater(scores["POTENTIAL"], scores["REQUIRES_VERIFICATION"])
		risk = assess_findings([finding(status="REQUIRES_VERIFICATION")])["risk_assessments"][0]
		self.assertEqual(risk["status"], "REQUIRES_VERIFICATION")
		self.assertIn("remains unverified", risk["rationale"])

	def test_explicit_exposure_is_limited_and_unknown_is_not_inferred(self):
		unknown = assess_findings([finding(severity="HIGH", confidence="HIGH")])["risk_assessments"][0]
		private = assess_findings(
			[finding(severity="HIGH", confidence="HIGH")],
			exposure="PRIVATE_TARGET",
			exposure_source="operator-provided context",
		)["risk_assessments"][0]
		public = assess_findings(
			[finding(severity="HIGH", confidence="HIGH")],
			exposure="PUBLIC_TARGET",
			exposure_source="operator-provided context",
		)["risk_assessments"][0]
		self.assertEqual(unknown["score"], 64)
		self.assertLess(private["score"], unknown["score"])
		self.assertGreater(public["score"], unknown["score"])
		self.assertIn("not supplied", unknown["rationale"])
		self.assertEqual(
			next(item for item in public["factors"] if item["name"] == "target_exposure")["source"],
			"operator-provided context",
		)
		critical_without_exposure = assess_findings([
			finding(severity="CRITICAL", confidence="CONFIRMED", status="CONFIRMED")
		])["risk_assessments"][0]
		self.assertEqual(critical_without_exposure["priority"], "P1")

	def test_priority_rules_cover_p0_through_p4_and_unranked(self):
		cases = (
			(finding(severity="CRITICAL", confidence="CONFIRMED", status="CONFIRMED"), "PUBLIC_TARGET", "P0"),
			(finding(severity="HIGH", confidence="HIGH", status="CONFIRMED"), "EXPOSURE_UNKNOWN", "P1"),
			(finding(severity="MEDIUM", confidence="CONFIRMED", status="CONFIRMED"), "EXPOSURE_UNKNOWN", "P2"),
			(finding(severity="LOW", confidence="HIGH", status="CONFIRMED"), "EXPOSURE_UNKNOWN", "P3"),
			(finding(severity="INFO", confidence="HIGH", status="OBSERVED"), "EXPOSURE_UNKNOWN", "P4"),
			(finding(confidence="UNKNOWN"), "EXPOSURE_UNKNOWN", "UNRANKED"),
		)
		for item, exposure, expected in cases:
			with self.subTest(expected=expected):
				risk = assess_findings([item], exposure=exposure)["risk_assessments"][0]
				self.assertEqual(risk["priority"], expected)


class AggregationAndSummaryTests(unittest.TestCase):
	def test_duplicates_are_counted_once_and_keep_all_evidence_and_sources(self):
		first = finding(finding_id="F-A", source="router audit")
		second = finding(
			finding_id="F-B",
			source="service assessment",
			evidence=[{"source": "TCP connect", "value": "reachable"}],
			recommendation="Disable unnecessary administration.",
		)
		original = json.loads(json.dumps([first, second]))
		result = assess_findings([first, second])
		risk = result["risk_assessments"][0]
		self.assertEqual(result["assessment"]["raw_finding_count"], 2)
		self.assertEqual(result["assessment"]["deduplicated_issue_count"], 1)
		self.assertEqual(set(risk["finding_ids"]), {"F-A", "F-B"})
		self.assertEqual(len(risk["source_findings"]), 2)
		support = next(item for item in risk["factors"] if item["name"] == "finding_status")
		self.assertEqual(len(support["supporting_evidence"]), 2)
		self.assertIn("Disable unnecessary administration.", risk["recommendation"])
		self.assertEqual([first, second], original)
		self.assertEqual(first["source"], "router audit")
		self.assertEqual(second["source"], "service assessment")

	def test_findings_on_same_target_are_not_merged_without_same_issue_identity(self):
		result = assess_findings([
			finding(finding_id="F-1", title="Telnet service exposed", category="service_exposure"),
			finding(finding_id="F-2", title="HTTP management interface observed", category="management_interface_observation"),
		])
		self.assertEqual(result["assessment"]["deduplicated_issue_count"], 2)

	def test_explicit_risk_key_merges_related_findings_across_modules(self):
		result = assess_findings([
			finding(finding_id="F-1", risk_key="router:telnet", source="router audit"),
			finding(finding_id="F-2", risk_key="router:telnet", source="tcp service assessment"),
		])
		self.assertEqual(result["assessment"]["deduplicated_issue_count"], 1)
		self.assertEqual(len(result["risk_assessments"][0]["source_findings"]), 2)

	def test_empty_summary_and_unknown_limits_are_explicit(self):
		empty = assess_findings([])["assessment"]
		self.assertEqual(empty["risk_level"], "UNKNOWN")
		self.assertIsNone(empty["score"])
		self.assertIn("not evidence that the target is risk-free", empty["rationale"])
		unknown = assess_findings([finding(confidence="UNKNOWN")])["assessment"]
		self.assertEqual(unknown["risk_level"], "UNKNOWN")
		self.assertTrue(any("remain unranked" in item for item in unknown["limitations"]))

	def test_unknown_supporting_duplicates_are_retained_and_disclosed(self):
		result = assess_findings([
			finding(finding_id="F-KNOWN"),
			finding(finding_id="F-UNKNOWN", confidence="UNKNOWN"),
		])
		risk = result["risk_assessments"][0]
		self.assertEqual(risk["score"], 64)
		self.assertIn("Supporting findings also contain UNKNOWN confidence", risk["rationale"])
		self.assertEqual(len(risk["source_findings"]), 2)
		self.assertTrue(any("preserved as uncertain supporting evidence" in item for item in result["assessment"]["limitations"]))

	def test_explicit_risk_key_does_not_merge_separate_targets(self):
		result = assess_findings([
			finding(finding_id="F-A", target="192.0.2.10", risk_key="same-key"),
			finding(finding_id="F-B", target="192.0.2.11", risk_key="same-key"),
		])
		self.assertEqual(result["assessment"]["deduplicated_issue_count"], 2)

	def test_overall_aggregation_uses_deduplicated_max_and_mean_not_a_sum(self):
		result = assess_findings([
			finding(finding_id="F-1", title="Critical issue", severity="CRITICAL", confidence="HIGH"),
			finding(finding_id="F-2", title="Medium issue", severity="MEDIUM", confidence="HIGH"),
		])
		summary = result["assessment"]
		scores = [item["score"] for item in result["risk_assessments"]]
		expected = int(0.7 * max(scores) + 0.3 * (sum(scores) / len(scores)) + 0.5)
		self.assertEqual(summary["score"], expected)
		self.assertNotEqual(summary["score"], sum(scores))
		self.assertEqual(summary["severity_counts"]["CRITICAL"], 1)
		self.assertEqual(summary["severity_counts"]["MEDIUM"], 1)

	def test_verification_count_and_severity_confidence_priority_counts(self):
		result = assess_findings([
			finding(finding_id="F-1", title="Confirmed", status="CONFIRMED"),
			finding(finding_id="F-2", title="Potential", status="REQUIRES_VERIFICATION", confidence="MEDIUM"),
		])
		summary = result["assessment"]
		self.assertEqual(summary["verification_required_count"], 1)
		self.assertEqual(summary["severity_counts"]["HIGH"], 2)
		self.assertEqual(summary["confidence_counts"]["HIGH"], 1)
		self.assertEqual(summary["confidence_counts"]["MEDIUM"], 1)
		self.assertTrue(summary["remediation_priorities"])


class ReportAndCliTests(unittest.TestCase):
	def test_assess_report_preserves_original_data_and_supports_artifact_nested_findings(self):
		source = {
			"target": "document.pdf",
			"type": "artifact",
			"artifact": {"path": "document.pdf", "findings": [finding()]},
			"metadata": {"keep": True},
		}
		result = assess_report(source)
		self.assertEqual(source["metadata"], {"keep": True})
		self.assertNotIn("findings", source)
		self.assertEqual(result["metadata"], {"keep": True})
		self.assertEqual(result["assessment"]["raw_finding_count"], 1)
		self.assertEqual(result["assessment"]["target"], "document.pdf")

	def test_json_csv_and_text_reports_preserve_risk_and_source_data(self):
		report = assess_report({
			"target": "192.0.2.10",
			"findings": [finding()],
			"services": [{"port": 23, "state": "OPEN"}],
		})
		json_report = json.loads(render_report(report, "json"))
		self.assertIn("risk_assessments", json_report)
		self.assertEqual(json_report["services"][0]["state"], "OPEN")
		csv_rows = list(csv.reader(io.StringIO(render_report(report, "csv"))))
		csv_fields = {row[0] for row in csv_rows[1:]}
		self.assertIn("assessment.rationale", csv_fields)
		self.assertIn("risk_assessments[0].factors[0].name", csv_fields)
		self.assertIn("services[0].state", csv_fields)
		text = render_report(report, "txt")
		self.assertIn("SENTINEL RISK ASSESSMENT", text)
		self.assertIn("PRIORITIZED FINDINGS", text)
		self.assertIn("SOURCE REPORT", text)
		self.assertIn("Router administration exposed", text)
		self.assertIn("LIMITATIONS", text)

	def test_assess_cli_uses_saved_input_and_emits_all_formats(self):
		with tempfile.TemporaryDirectory() as directory:
			source = Path(directory) / "source.json"
			source.write_text(json.dumps({
				"target": "192.0.2.10",
				"findings": [finding()],
				"scope": "saved evidence only",
			}), encoding="utf-8")
			result = run_assessment(str(source))
			self.assertEqual(result["scope"], "saved evidence only")
			self.assertEqual(result["assessment"]["raw_finding_count"], 1)
			with_public_context = run_assessment(str(source), "public")
			self.assertEqual(with_public_context["risk_context"]["exposure"], "PUBLIC_TARGET")
			self.assertEqual(
				next(
					factor for factor in with_public_context["risk_assessments"][0]["factors"]
					if factor["name"] == "target_exposure"
				)["confidence"],
				"LOW",
			)
			for output_format in ("json", "csv", "text"):
				output = Path(directory) / f"result.{output_format}"
				with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
					status = main([
						"assess", str(source),
						"--output-format", output_format,
						"--output", str(output),
					])
				self.assertEqual(status, 0)
				content = output.read_text(encoding="utf-8")
				self.assertTrue(content)
				if output_format == "json":
					self.assertIn("risk_assessments", json.loads(content))
				elif output_format == "text":
					self.assertIn("SENTINEL RISK ASSESSMENT", content)
				else:
					self.assertIn("assessment.risk_level", content)

	def test_assess_cli_documents_pure_workflow_and_explicit_exposure(self):
		with contextlib.redirect_stdout(io.StringIO()) as output:
			status = main(["assess", "--help"])
		self.assertEqual(status, 0)
		self.assertIn("not scan targets", " ".join(output.getvalue().split()))
		self.assertIn("--exposure", output.getvalue())
		with contextlib.redirect_stdout(io.StringIO()) as output:
			status = main(["--help"])
		self.assertEqual(status, 0)
		self.assertIn("assess", output.getvalue())

	def test_assess_cli_invalid_report_returns_existing_validation_exit_code(self):
		with tempfile.TemporaryDirectory() as directory:
			missing = Path(directory) / "absent.json"
			with contextlib.redirect_stderr(io.StringIO()) as stderr:
				status = main(["assess", str(missing)])
		self.assertEqual(status, 3)
		self.assertIn("does not exist", stderr.getvalue())


if __name__ == "__main__":
	unittest.main()
