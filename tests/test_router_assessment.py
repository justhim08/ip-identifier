import contextlib
import io
import unittest
from unittest.mock import patch

from sentinel.cli import main
from sentinel.reports.renderer import render_report
from sentinel.router.audit import (
	ROUTER_TCP_PORTS,
	_certificate_names,
	_certificate_subject_name,
	_nvd_advisories,
	_tls_findings,
	_validate_router_target,
	audit_router,
)
from sentinel.intel.vulnerability import normalize_cve


class RouterTargetTests(unittest.TestCase):
	def test_accepts_private_ipv4_and_ipv6_targets(self):
		for target in ("10.0.0.1", "172.16.0.1", "192.168.1.1", "fd00::1", "fe80::1"):
			with self.subTest(target=target):
				address, _ = _validate_router_target(target)
				self.assertEqual(str(address), target)

	def test_rejects_public_ip_and_hostname(self):
		for target in ("8.8.8.8", "example.com"):
			with self.subTest(target=target), self.assertRaisesRegex(ValueError, "private"):
				_validate_router_target(target)


class RouterFindingTests(unittest.TestCase):
	def assess(self, open_ports=(), http_responses=None, advisories=None):
		http_responses = http_responses or {}
		with patch(
			"sentinel.router.audit._probe_tcp",
			side_effect=lambda *args: "open" if args[1] in open_ports else "closed",
		), patch(
			"sentinel.router.audit._http_head",
			side_effect=lambda *args: http_responses.get(args[1], {"error": "mocked"}),
		), patch(
			"sentinel.router.audit._nvd_advisories",
			return_value=advisories or {"status": "not_requested", "reason": "No lookup requested."},
		):
			return audit_router("192.168.1.1")

	def test_service_assessments_include_port_protocol_evidence_and_confidence(self):
		report = self.assess(open_ports=(22,))
		ssh = next(item for item in report["service_assessments"] if item["port"] == 22)
		self.assertEqual(ssh["protocol"], "tcp")
		self.assertEqual(ssh["state"], "OPEN")
		self.assertEqual(ssh["service"], ROUTER_TCP_PORTS[22])
		self.assertEqual(ssh["confidence"], "HIGH")
		self.assertIn("Connection accepted", ssh["evidence"][0]["value"])

	def test_telnet_open_creates_standard_high_finding(self):
		report = self.assess(open_ports=(23,))
		finding = next(item for item in report["findings"] if item["id"] == "ROUTER-TELNET-001")
		self.assertEqual(finding["severity"], "HIGH")
		self.assertEqual(finding["confidence"], "HIGH")
		self.assertEqual(finding["status"], "OBSERVED")
		self.assertEqual(finding["port"], 23)
		self.assertIn("TCP/23 is reachable", finding["evidence"][0]["value"])
		self.assertIn("SSH", finding["recommendation"])
		for field in ("target", "description", "impact", "recommendation", "references", "evidence"):
			self.assertIn(field, finding)

	def test_http_response_creates_careful_management_observation(self):
		report = self.assess(open_ports=(80,), http_responses={80: {"status_code": 200, "headers": {}}})
		finding = next(item for item in report["findings"] if item["id"] == "ROUTER-HTTP-MGMT-001")
		self.assertEqual(finding["severity"], "MEDIUM")
		self.assertEqual(finding["confidence"], "MEDIUM")
		self.assertEqual(finding["status"], "POTENTIAL")
		self.assertIn("does not establish", finding["description"])
		self.assertEqual(report["management_transport"], "HTTP only")

	def test_https_only_and_http_plus_https_are_distinguished(self):
		https_only = self.assess(open_ports=(443,), http_responses={443: {"status_code": 200}})
		both = self.assess(
			open_ports=(80, 443),
			http_responses={80: {"status_code": 301}, 443: {"status_code": 200}},
		)
		self.assertEqual(https_only["management_transport"], "HTTPS only")
		self.assertEqual(both["management_transport"], "HTTP + HTTPS")

	def test_tr069_is_informational_and_not_claimed_vulnerable(self):
		report = self.assess(open_ports=(7547,))
		finding = next(item for item in report["findings"] if item["id"] == "ROUTER-TR069-001")
		self.assertEqual(finding["severity"], "INFO")
		self.assertEqual(finding["confidence"], "LOW")
		self.assertEqual(finding["status"], "POTENTIAL")
		self.assertIn("does not establish a vulnerability", finding["description"])

	def test_certificate_sans_are_normalized(self):
		certificate = {"subjectAltName": (("DNS", "router.local"), ("IP Address", "192.168.1.1"), ("DNS", "router.local"))}
		self.assertEqual(_certificate_names(certificate), ["192.168.1.1", "router.local"])
		self.assertEqual(
			_certificate_subject_name({"subject": ((("commonName", "router.local"),),)}, "subject"),
			"router.local",
		)

	def test_tls_certificate_findings_are_evidence_based(self):
		findings = _tls_findings(
			"192.168.1.1",
			443,
			"HTTPS",
			{
				"hostname_verification": "mismatch",
				"verification_note": "IP address mismatch",
				"tls_version": "TLSv1.1",
			},
		)
		self.assertEqual(
			{finding["id"] for finding in findings},
			{"ROUTER-TLS-HOSTNAME-443", "ROUTER-TLS-LEGACY-443"},
		)
		expired = _tls_findings(
			"192.168.1.1",
			443,
			"HTTPS",
			{"certificate_verification": "not trusted", "verification_note": "certificate has expired"},
		)
		self.assertEqual(expired[0]["id"], "ROUTER-TLS-EXPIRED-443")

	def test_router_identity_header_is_a_potential_match_not_confirmation(self):
		report = self.assess(
			open_ports=(80,),
			http_responses={
				80: {
					"status_code": 200,
					"headers": {"x-router-model": "TP-Link Archer", "x-firmware-version": "1.0"},
				}
			},
		)
		identity = report["router_identity"]
		self.assertEqual(identity["manufacturer"], "TP-Link")
		self.assertEqual(identity["model_confidence"], "POTENTIAL MATCH")
		self.assertEqual(identity["firmware"], "1.0")
		self.assertIn("unverified hints", identity["identification_note"])

	def test_unknown_firmware_and_udp_scope_are_explicit(self):
		report = self.assess()
		self.assertEqual(report["router_identity"]["firmware"], "Unknown")
		self.assertEqual(report["router_identity"]["model_confidence"], "UNKNOWN")
		self.assertEqual(report["upnp"], "Not assessed by current TCP scanner")
		self.assertEqual(report["udp_services"]["status"], "not_checked")

	def test_incomplete_service_and_nvd_data_do_not_stop_assessment(self):
		with patch(
			"sentinel.router.audit._probe_tcp",
			return_value={"error": "probe failed"},
		), patch(
			"sentinel.router.audit._nvd_advisories",
			return_value={"status": "unavailable", "error": "offline"},
		):
			report = audit_router("192.168.1.1", model="Example Router")
		self.assertEqual(len(report["service_assessments"]), len(ROUTER_TCP_PORTS))
		self.assertEqual(report["vulnerability_advisories"]["status"], "unavailable")
		self.assertEqual(report["router_identity"]["firmware"], "Unknown")


class NvdNormalizationTests(unittest.TestCase):
	def test_cve_fields_are_normalized_and_labeled_as_candidates(self):
		cve = normalize_cve({
			"id": "CVE-2025-12345",
			"descriptions": [{"lang": "en", "value": "Example issue."}],
			"published": "2025-01-01T00:00:00.000",
			"lastModified": "2025-01-02T00:00:00.000",
			"metrics": {
				"cvssMetricV31": [{
					"cvssData": {"baseScore": 8.1, "baseSeverity": "HIGH", "version": "3.1"}
				}]
			},
			"references": [{"url": "https://example.test/advisory", "tags": ["Vendor Advisory"]}],
			"configurations": [{
				"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:o:vendor:router:1.0:*:*:*:*:*:*:*"}]}]
			}],
		})
		self.assertEqual(cve["cvss"], {"score": 8.1, "severity": "HIGH", "version": "3.1"})
		self.assertEqual(cve["affected_products"], ["cpe:2.3:o:vendor:router:1.0:*:*:*:*:*:*:*"])
		self.assertEqual(cve["applicability"], "requires_verification")
		self.assertIn("Potentially relevant", cve["assessment_note"])

	def test_nvd_response_is_normalized_offline(self):
		payload = b'{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2025-0001","descriptions":[{"lang":"en","value":"Candidate."}],"published":"2025-01-01","lastModified":"2025-01-02","metrics":{},"references":[]}}]}'
		with patch("sentinel.router.audit.urlopen", return_value=io.BytesIO(payload)):
			result = _nvd_advisories("Example Router", "1.2.3")
		self.assertEqual(result["status"], "candidates")
		self.assertEqual(result["results"][0]["id"], "CVE-2025-0001")
		self.assertEqual(result["results"][0]["applicability"], "requires_verification")

	def test_router_report_never_treats_keyword_candidate_as_confirmed(self):
		report = {
			"target": "192.168.1.1",
			"router_identity": {"model": "Example Router", "model_confidence": "POTENTIAL MATCH", "firmware": "Unknown"},
			"service_assessments": [],
			"findings": [],
			"vulnerability_advisories": {
				"status": "candidates",
				"results": [{"id": "CVE-2025-12345", "description": "Example issue."}],
			},
		}
		text = render_report(report, "txt")
		self.assertIn("Potentially relevant CVEs", text)
		self.assertIn("does not confirm", text)


class RouterAuthorizationTests(unittest.TestCase):
	def test_router_command_requires_authorization_confirmation(self):
		output = io.StringIO()
		with patch("builtins.input", return_value="I AM AUTHORIZED"), patch(
			"sentinel.cli.run_router_audit", return_value={"target": "192.168.1.1"}
		) as run_audit, contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
			status = main(["router-audit", "192.168.1.1"])
		self.assertEqual(status, 0)
		run_audit.assert_called_once()
		self.assertIn("explicit permission", output.getvalue())

	def test_router_command_requires_explicit_noninteractive_flag(self):
		with patch("builtins.input", side_effect=AssertionError("must not prompt")), patch(
			"sentinel.cli.run_router_audit", return_value={"target": "192.168.1.1"}
		) as run_audit, contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
			status = main(["router-audit", "192.168.1.1", "--authorized"])
		self.assertEqual(status, 0)
		run_audit.assert_called_once()

	def test_authorization_flag_before_command_is_preserved(self):
		with patch("builtins.input", side_effect=AssertionError("must not prompt")), patch(
			"sentinel.cli.run_router_audit", return_value={"target": "192.168.1.1"}
		) as run_audit, contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
			status = main(["--authorized", "router-audit", "192.168.1.1"])
		self.assertEqual(status, 0)
		run_audit.assert_called_once()

	def test_wrong_authorization_confirmation_stops_audit(self):
		with patch("builtins.input", return_value="yes"), patch(
			"sentinel.cli.run_router_audit"
		) as run_audit, contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
			status = main(["router-audit", "192.168.1.1"])
		self.assertEqual(status, 3)
		run_audit.assert_not_called()
if __name__ == "__main__":
	unittest.main()
