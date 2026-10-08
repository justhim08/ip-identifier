import unittest

from sentinel.baseline import compare_reports, create_baseline


class Phase8BaselineTests(unittest.TestCase):
    def test_baseline_preserves_source_data_and_finding_count(self):
        report = {
            "target": "192.0.2.10",
            "summary": {"score": 42, "risk_level": "MEDIUM"},
            "findings": [{
                "id": "F-1",
                "title": "Telnet exposed",
                "severity": "HIGH",
                "confidence": "HIGH",
                "status": "OBSERVED",
                "target": "192.0.2.10",
                "port": 23,
                "service": "telnet",
                "category": "service_observation",
                "evidence": [{"source": "fixture", "value": "open"}],
            }],
        }

        baseline = create_baseline(report, baseline_id="baseline-001")

        self.assertEqual(baseline.baseline_id, "baseline-001")
        self.assertEqual(baseline.source_report["target"], "192.0.2.10")
        self.assertEqual(baseline.to_dict()["finding_count"], 1)

    def test_compare_reports_detects_new_resolved_and_changed_findings(self):
        baseline = {
            "target": "192.0.2.10",
            "findings": [
                {
                    "id": "F-1",
                    "title": "Telnet exposed",
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "status": "OBSERVED",
                    "target": "192.0.2.10",
                    "port": 23,
                    "service": "telnet",
                    "category": "service_observation",
                    "evidence": [{"source": "fixture", "value": "open"}],
                },
                {
                    "id": "F-2",
                    "title": "HTTP exposed",
                    "severity": "LOW",
                    "confidence": "LOW",
                    "status": "OBSERVED",
                    "target": "192.0.2.10",
                    "port": 80,
                    "service": "http",
                    "category": "service_observation",
                    "evidence": [{"source": "fixture", "value": "open"}],
                },
            ],
        }
        current = {
            "target": "192.0.2.10",
            "findings": [
                {
                    "id": "F-1",
                    "title": "Telnet exposed",
                    "severity": "CRITICAL",
                    "confidence": "HIGH",
                    "status": "OBSERVED",
                    "target": "192.0.2.10",
                    "port": 23,
                    "service": "telnet",
                    "category": "service_observation",
                    "evidence": [{"source": "fixture", "value": "open"}],
                },
                {
                    "id": "F-3",
                    "title": "SSH exposed",
                    "severity": "MEDIUM",
                    "confidence": "MEDIUM",
                    "status": "OBSERVED",
                    "target": "192.0.2.10",
                    "port": 22,
                    "service": "ssh",
                    "category": "service_observation",
                    "evidence": [{"source": "fixture", "value": "open"}],
                },
            ],
        }

        result = compare_reports(baseline, current)

        self.assertEqual(result["counts"]["CHANGED"], 1)
        self.assertEqual(result["counts"]["NEW"], 1)
        self.assertEqual(result["counts"]["NOT_OBSERVED"], 1)
        self.assertEqual(result["posture_summary"]["overall_posture_change"], "NEGATIVE")

    def test_missing_finding_is_resolved_only_with_explicit_negative_evidence(self):
        baseline = {
            "target": "192.0.2.10",
            "findings": [{
                "id": "F-1",
                "title": "Telnet exposed",
                "severity": "HIGH",
                "confidence": "HIGH",
                "status": "OBSERVED",
                "target": "192.0.2.10",
                "port": 23,
                "service": "telnet",
                "category": "service_observation",
            }],
        }
        current = {
            "target": "192.0.2.10",
            "services": {"23": {"state": "closed", "service": "telnet"}},
            "findings": [{
                "id": "F-2",
                "title": "No telnet",
                "severity": "INFO",
                "confidence": "LOW",
                "status": "OBSERVED",
                "target": "192.0.2.10",
                "port": 23,
                "service": "telnet",
                "category": "service_observation",
            }],
        }

        result = compare_reports(baseline, current)

        self.assertEqual(result["counts"]["RESOLVED"], 1)

    def test_compare_reports_treats_missing_service_as_not_observed_when_coverage_is_missing(self):
        baseline = {
            "target": "192.0.2.10",
            "services": {"23": {"state": "open", "service": "telnet"}},
            "findings": [{
                "id": "F-1",
                "title": "Telnet service",
                "severity": "MEDIUM",
                "confidence": "MEDIUM",
                "status": "OBSERVED",
                "target": "192.0.2.10",
                "port": 23,
                "service": "telnet",
                "category": "service_observation",
            }],
        }
        current = {
            "target": "192.0.2.10",
            "services": {"80": {"state": "open", "service": "http"}},
            "findings": [{
                "id": "F-2",
                "title": "HTTP service",
                "severity": "LOW",
                "confidence": "LOW",
                "status": "OBSERVED",
                "target": "192.0.2.10",
                "port": 80,
                "service": "http",
                "category": "service_observation",
            }],
        }

        result = compare_reports(baseline, current)

        self.assertEqual(result["counts"]["NOT_OBSERVED"], 1)

    def test_baseline_ids_are_deterministic_and_missing_metadata_is_unknown(self):
        report = {
            "target": "192.0.2.10",
            "findings": [{
                "id": "F-1",
                "title": "Telnet exposed",
                "severity": "HIGH",
                "confidence": "HIGH",
                "status": "OBSERVED",
                "target": "192.0.2.10",
                "port": 23,
                "service": "telnet",
                "category": "service_observation",
            }],
        }

        first = create_baseline(report)
        second = create_baseline({**report})

        self.assertEqual(first.baseline_id, second.baseline_id)
        self.assertEqual(first.metadata["assessment_timestamp"], "UNKNOWN")
        self.assertEqual(first.metadata["source_report"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
