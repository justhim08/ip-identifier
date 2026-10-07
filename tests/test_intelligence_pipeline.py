import contextlib
import io
import unittest
from unittest.mock import patch

from sentinel.cli import main, run_cve_lookup
from sentinel.intel.models import (
	IntelligenceRecord,
	IntelligenceRelationship,
	deduplicate_records,
	deduplicate_relationships,
)
from sentinel.intel.pipeline import enrich_intelligence
from sentinel.intel.vulnerability import (
	correlate_product_version,
	findings_for_cves,
	lookup_nvd,
	normalize_cve,
	normalize_severity,
)
from sentinel.osint.intelligence import _certificate_names, _dns_lookup, _rdap_summary, lookup_osint
from sentinel.reports.renderer import render_report


class IntelligenceModelTests(unittest.TestCase):
	def test_record_creation_validates_confidence_and_has_provenance(self):
		record = IntelligenceRecord(
			source="DNS resolver",
			category="DNS",
			target="example.com",
			value="203.0.113.10",
			evidence=[{"record_type": "A"}],
			confidence="high",
		)
		self.assertEqual(record.confidence, "HIGH")
		self.assertEqual(record.status, "OBSERVED")
		self.assertEqual(record.provenance, ["DNS resolver"])
		self.assertTrue(record.timestamp.endswith("Z"))
		with self.assertRaisesRegex(ValueError, "confidence"):
			IntelligenceRecord("DNS", "DNS", "example.com", "x", [], "certain")

	def test_relationship_requires_source_and_supported_status(self):
		edge = IntelligenceRelationship(
			"example.com", "203.0.113.10", "resolves to", [{"record_type": "A"}],
			"DNS resolver", "high",
		)
		self.assertEqual(edge.status, "CORRELATED")
		self.assertEqual(edge.confidence, "HIGH")
		with self.assertRaisesRegex(ValueError, "source"):
			IntelligenceRelationship("a", "b", "c", [], "")

	def test_duplicate_records_merge_provenance_and_evidence(self):
		first = IntelligenceRecord("DNS-A", "DNS", "example.com", "203.0.113.10", [{"type": "A"}], "HIGH")
		second = IntelligenceRecord("DNS-B", "dns", "EXAMPLE.COM", "203.0.113.10", [{"type": "AAAA"}], "HIGH")
		merged = deduplicate_records([first, second])
		self.assertEqual(len(merged), 1)
		self.assertEqual(merged[0].source, "Multiple sources")
		self.assertEqual(merged[0].provenance, ["DNS-A", "DNS-B"])
		self.assertEqual(len(merged[0].evidence), 2)

	def test_duplicate_relationships_keep_each_source_and_evidence(self):
		edges = [
			IntelligenceRelationship("example.com", "203.0.113.10", "resolves to", [{"type": "A"}], "DNS A"),
			IntelligenceRelationship("example.com", "203.0.113.10", "resolves to", [{"type": "A"}], "DNS B"),
		]
		merged = deduplicate_relationships(edges)
		self.assertEqual(len(merged), 1)
		self.assertEqual(merged[0].source_name, "DNS A; DNS B")


class SourceNormalizationTests(unittest.TestCase):
	def test_dns_result_carries_normalized_record_type_and_confidence(self):
		with patch("sentinel.osint.intelligence._get_json", return_value={
			"Status": 0,
			"Answer": [{"name": "example.com.", "type": 1, "data": "203.0.113.10"}],
		}):
			result = _dns_lookup("example.com", "A")
		self.assertEqual(result["answers"][0]["type"], "A")
		self.assertEqual(result["record_type"], "A")
		self.assertEqual(result["source"], "Google DNS-over-HTTPS")
		self.assertEqual(result["confidence"], "HIGH")

	def test_dns_records_become_provenance_and_relationship_records(self):
		enriched = enrich_intelligence({
			"target": "example.com",
			"type": "domain",
			"sources": {"dns": {
				"A": {"record_status": "FOUND", "status": "NOERROR", "answers": [
					{"type": "A", "data": "203.0.113.10"},
				]},
				"MX": {"record_status": "NO_RECORD", "status": "NOERROR", "answers": []},
			}},
		})
		self.assertEqual(len(enriched["relationships"]), 1)
		self.assertEqual(enriched["relationships"][0]["relationship"], "DNS A")
		self.assertEqual(enriched["intelligence"][0]["source"], "DNS resolver (Google DNS-over-HTTPS)")
		self.assertEqual(enriched["intelligence"][1]["value"], "No MX record")

	def test_rdap_normalizes_network_organization_country_source(self):
		result = _rdap_summary({
			"objectClassName": "ip network",
			"startAddress": "203.0.113.0",
			"endAddress": "203.0.113.255",
			"country": "US",
			"cidr0_cidrs": [{"v4prefix": "203.0.113.0", "length": 24}],
			"name": "Example Network",
		})
		self.assertEqual(result["source"], "RDAP")
		self.assertEqual(result["confidence"], "HIGH")
		self.assertEqual(result["organization"], "Example Network")
		self.assertIn("does not establish ownership", result["information_note"])

	def test_certificate_records_preserve_subject_issuer_validity_and_hostnames(self):
		with patch("sentinel.osint.intelligence._get_json", return_value=[{
			"id": 19,
			"common_name": "WWW.Example.com",
			"name_value": "www.example.com\napi.example.com",
			"subject_alt_names": ["API.Example.com"],
			"issuer_name": "Example CA",
			"not_before": "2026-01-01T00:00:00",
			"not_after": "2027-01-01T00:00:00",
		}]):
			result = _certificate_names("example.com")
		self.assertEqual(result["hostnames"], ["api.example.com", "www.example.com"])
		certificate = result["certificates"][0]
		self.assertEqual(certificate["issuer"], "Example CA")
		self.assertEqual(certificate["valid_until"], "2027-01-01T00:00:00")

	def test_lookup_continues_when_individual_sources_are_unavailable(self):
		with patch("sentinel.osint.intelligence._rdap_lookup", side_effect=OSError("RDAP offline")), patch(
			"sentinel.osint.intelligence._dns_lookup",
			side_effect=lambda *args: {
				"status": "NOERROR", "record_status": "NO_RECORD", "answers": [], "records": [],
				"record_type": args[1],
			},
		), patch("sentinel.osint.intelligence._certificate_names", side_effect=OSError("CT offline")):
			report = lookup_osint("example.com")
		self.assertIn("rdap", report["sources"])
		self.assertTrue(any(error["source"] == "rdap" for error in report["errors"]))
		self.assertTrue(any(error["source"] == "certificate_transparency" for error in report["errors"]))
		self.assertIn("intelligence", report)
		self.assertIn("relationships", report)


class TechnologyEvidenceTests(unittest.TestCase):
	def test_only_observed_headers_and_banners_identify_technology(self):
		report = enrich_intelligence({
			"target": "192.0.2.1",
			"ports": [
				{"port": 22, "status": "OPEN", "service": {
					"name": "SSH", "evidence": [
						{"source": "tcp_port", "value": "TCP/22"},
						{"source": "ssh_banner", "value": "SSH-2.0-Example"},
					],
				}},
				{"port": 9000, "status": "OPEN", "service": {
					"name": "unknown", "evidence": [{"source": "tcp_port", "value": "TCP/9000"}],
				}},
			],
		})
		technologies = [item for item in report["intelligence"] if item["category"] == "technology"]
		self.assertEqual(len(technologies), 1)
		self.assertEqual(technologies[0]["value"], "SSH-2.0-Example")
		self.assertEqual(technologies[0]["classification"], "directly_observed")
		self.assertEqual(technologies[0]["confidence"], "HIGH")
		port_guess = next(item for item in report["intelligence"] if item["category"] == "service")
		self.assertEqual(port_guess["classification"], "inferred")
		self.assertEqual(port_guess["status"], "POTENTIAL")
		self.assertFalse(any(item["category"] == "technology" and item["value"] == "SSH" for item in report["intelligence"]))

	def test_tls_metadata_is_separated_as_direct_observation_and_certificate_derivation(self):
		report = enrich_intelligence({
			"target": "example.com",
			"services": {"443": {"http_head": {"status_code": 200, "headers": {"server": "ExampleServer"},
				"tls": {"certificate_sha256": "abc", "certificate_subject": "CN=example.com",
					"certificate_issuer": "CN=Example CA", "valid_from": "2026-01-01",
					"valid_until": "2027-01-01", "hostnames": ["WWW.Example.com", "www.example.com"],
					"certificate_verification": "valid", "tls_version": "TLSv1.3"}}}},
		})
		self.assertTrue(any(
			item["category"] == "tls_certificate" and item["classification"] == "directly_observed"
			for item in report["intelligence"]
		))
		hostname_records = [item for item in report["intelligence"] if item["category"] == "hostname"]
		self.assertEqual(len(hostname_records), 1)
		self.assertEqual(hostname_records[0]["value"], "www.example.com")
		self.assertEqual(hostname_records[0]["classification"], "certificate_derived")


class VulnerabilityIntelligenceTests(unittest.TestCase):
	def cve(self, cpe_match=None):
		configurations = [{"nodes": [{"cpeMatch": [cpe_match]}]}] if cpe_match else []
		return normalize_cve({
			"id": "CVE-2026-12345",
			"descriptions": [{"lang": "en", "value": "Example router issue."}],
			"published": "2026-01-01T00:00:00Z",
			"lastModified": "2026-02-01T00:00:00Z",
			"metrics": {"cvssMetricV31": [{"cvssData": {
				"baseScore": 9.1, "baseSeverity": "CRITICAL", "version": "3.1",
			}}]},
			"references": [{"url": "https://vendor.example/advisory", "tags": ["Vendor Advisory"]}],
			"configurations": configurations,
		})

	def test_cve_normalizes_metrics_severity_dates_references_and_source_data(self):
		cve = self.cve()
		self.assertEqual(cve["source"], "NVD")
		self.assertEqual(cve["severity"], "CRITICAL")
		self.assertEqual(cve["cvss_score"], 9.1)
		self.assertEqual(cve["published"], "2026-01-01T00:00:00Z")
		self.assertIn("metrics", cve["source_data"])
		self.assertEqual(cve["status"], "POTENTIAL")

	def test_severity_normalization_handles_unknown_and_numeric_values(self):
		self.assertEqual(normalize_severity("critical"), "CRITICAL")
		self.assertEqual(normalize_severity(score=7.5), "HIGH")
		self.assertEqual(normalize_severity(score=5.0), "MEDIUM")
		self.assertEqual(normalize_severity(score=2.0), "LOW")
		self.assertEqual(normalize_severity(), "UNKNOWN")

	def test_exact_reliable_version_correlation_stays_unconfirmed(self):
		cve = self.cve({
			"criteria": "cpe:2.3:o:example:router:1.2.3:*:*:*:*:*:*:*",
			"vulnerable": True,
		})
		correlated = correlate_product_version(
			{"vendor": "example", "product": "router", "version": "1.2.3", "confidence": "HIGH"},
			[cve],
		)[0]
		self.assertEqual(correlated["status"], "CORRELATED")
		self.assertEqual(correlated["applicability"], "potentially_affected")
		self.assertIn("vendor verification is still required", correlated["reason"])

	def test_unreliable_or_missing_version_requires_verification(self):
		cve = self.cve({"criteria": "cpe:2.3:o:example:router:*:*:*:*:*:*:*:*", "vulnerable": True})
		correlated = correlate_product_version(
			{"vendor": "example", "product": "router", "version": "", "confidence": "LOW"},
			[cve],
		)[0]
		self.assertEqual(correlated["status"], "REQUIRES_VERIFICATION")
		self.assertEqual(correlated["applicability"], "requires_verification")

	def test_version_range_correlation_obeys_inclusive_and_exclusive_bounds(self):
		cve = self.cve({
			"criteria": "cpe:2.3:o:example:router:*:*:*:*:*:*:*:*",
			"vulnerable": True,
			"versionStartIncluding": "1.0",
			"versionEndExcluding": "2.0",
		})
		in_range = correlate_product_version(
			{"vendor": "example", "product": "router", "version": "1.5", "confidence": "HIGH"}, [cve],
		)[0]
		out_of_range = correlate_product_version(
			{"vendor": "example", "product": "router", "version": "2.0", "confidence": "HIGH"}, [cve],
		)[0]
		self.assertEqual(in_range["status"], "CORRELATED")
		self.assertEqual(out_of_range["status"], "UNKNOWN")

	def test_finding_contains_source_evidence_and_requires_verification(self):
		cve = self.cve()
		finding = findings_for_cves(
			"Example Router",
			[cve],
			[{"cve_id": cve["id"], "status": "REQUIRES_VERIFICATION", "confidence": "MEDIUM",
				"applicability": "requires_verification", "reason": "Administrator input needs verification."}],
		)[0]
		self.assertEqual(finding["severity"], "CRITICAL")
		self.assertEqual(finding["source"], "NVD")
		self.assertEqual(finding["status"], "REQUIRES_VERIFICATION")
		self.assertEqual(finding["confidence"], "MEDIUM")
		self.assertEqual(finding["references"], ["https://vendor.example/advisory"])
		self.assertIn("potentially relevant", finding["title"].lower())

	def test_unmatched_cve_candidate_has_low_confidence_and_requires_verification(self):
		finding = findings_for_cves("Example Router", [self.cve()])[0]
		self.assertEqual(finding["confidence"], "LOW")
		self.assertEqual(finding["status"], "REQUIRES_VERIFICATION")

	def test_nvd_failures_and_rate_limits_are_explicit(self):
		with patch("sentinel.intel.vulnerability.urlopen", side_effect=OSError("offline")):
			unavailable = lookup_nvd("example router")
		self.assertEqual(unavailable["status"], "unavailable")
		self.assertIn("offline", unavailable["error"])

		from urllib.error import HTTPError
		with patch("sentinel.intel.vulnerability.urlopen", side_effect=HTTPError(
			"https://nvd.example", 429, "slow down", {}, None,
		)):
			rate_limited = lookup_nvd("example router")
		self.assertEqual(rate_limited["status"], "rate_limited")

	def test_malformed_nvd_payload_is_an_explicit_unavailable_result(self):
		with patch("sentinel.intel.vulnerability.urlopen", return_value=io.BytesIO(b"not-json")):
			result = lookup_nvd("example router")
		self.assertEqual(result["status"], "unavailable")
		self.assertTrue(result["error"])

	def test_non_vulnerable_cpe_context_is_not_listed_as_affected_product(self):
		cve = self.cve({"criteria": "cpe:2.3:o:example:router:1.2.3:*:*:*:*:*:*:*", "vulnerable": False})
		self.assertEqual(cve["affected_products"], [])
		correlation = correlate_product_version(
			{"vendor": "example", "product": "router", "version": "1.2.3", "confidence": "HIGH"},
			[cve],
		)[0]
		self.assertEqual(correlation["status"], "UNKNOWN")

	def test_cve_text_report_keeps_source_and_applicability_clear(self):
		cve = self.cve()
		text = render_report({
			"source": "NVD", "query": "example router", "status": "candidates",
			"results": [cve],
			"correlations": [{"cve_id": cve["id"], "status": "REQUIRES_VERIFICATION",
				"applicability": "requires_verification", "confidence": "MEDIUM",
				"reason": "Version applicability unknown."}],
		}, "txt")
		self.assertIn("Potential CVE candidates", text)
		self.assertIn("NVD", text)
		self.assertIn("requires_verification", text)
		self.assertIn("does not by itself confirm", text)


class IntelCliTests(unittest.TestCase):
	def test_intel_command_uses_passive_recon_path(self):
		with patch("sentinel.cli.run_recon", return_value={"target": "example.com"}) as run_recon, \
			contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
			self.assertEqual(main(["intel", "example.com"]), 0)
		run_recon.assert_called_once_with("example.com")

	def test_cve_cli_normalizes_candidates_and_exposes_correlations(self):
		cve = VulnerabilityIntelligenceTests().cve({
			"criteria": "cpe:2.3:o:example:router:1.2.3:*:*:*:*:*:*:*",
			"vulnerable": True,
		})
		with patch("sentinel.cli.lookup_nvd", return_value={
			"source": "NVD", "status": "candidates", "query": "Example Router", "results": [cve],
		}):
			report = run_cve_lookup(
				"Example Router", vendor="example", product="router", version="1.2.3",
			)
		self.assertEqual(report["correlations"][0]["status"], "REQUIRES_VERIFICATION")
		self.assertEqual(report["findings"][0]["source"], "NVD")
		self.assertIn("intelligence", report)
		self.assertIn("relationships", report)
		self.assertEqual(report["relationships"][0]["relationship"], "potentially affected by")
		self.assertEqual(report["relationships"][0]["status"], "REQUIRES_VERIFICATION")

	def test_cve_command_dispatches_and_renders_text(self):
		output = io.StringIO()
		with patch("sentinel.cli.run_cve_lookup", return_value={
			"source": "NVD",
			"query": "Example Router",
			"status": "candidates",
			"results": [],
			"assessment_note": "Potentially relevant CVEs require verification.",
		}) as lookup, contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
			status = main(["cve", "Example Router", "--output-format", "text"])
		self.assertEqual(status, 0)
		lookup.assert_called_once_with("Example Router", vendor=None, product=None, version=None)
		self.assertIn("Potential CVE candidates", output.getvalue())

	def test_csv_report_retains_intelligence_provenance_fields(self):
		text = render_report({
			"target": "example.com",
			"intelligence": [{
				"source": "DNS resolver",
				"evidence": [{"record_type": "A"}],
				"confidence": "HIGH",
				"status": "OBSERVED",
			}],
			"relationships": [{
				"source": "example.com",
				"target": "203.0.113.10",
				"source_name": "DNS resolver",
			}],
		}, "csv")
		self.assertIn("intelligence[0].source,DNS resolver", text)
		self.assertIn("relationships[0].source_name,DNS resolver", text)


if __name__ == "__main__":
	unittest.main()
