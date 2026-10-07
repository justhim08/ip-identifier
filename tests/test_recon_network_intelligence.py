import ipaddress
import socket
import unittest
from unittest.mock import Mock, patch

from sentinel.network.inventory import (
	_parse_linux_interfaces,
	_parse_macos_interfaces,
	_parse_windows_interfaces,
)
from sentinel.network.scanner import classify_socket_error, scan_port
from sentinel.network.services import identify_service
from sentinel.osint.intelligence import (
	_certificate_names,
	_dns_lookup,
	_ip_intelligence,
	_rdap_summary,
	lookup_osint,
)
from sentinel.recon.models import ReconResult
from sentinel.reports.renderer import render_report


class DnsReconTests(unittest.TestCase):
	def test_dns_normalizes_cname_records(self):
		with patch(
			"sentinel.osint.intelligence._get_json",
			return_value={
				"Status": 0,
				"Answer": [
					{"name": "api.example.com.", "type": 5, "data": "edge.example.net."},
				],
			},
		):
			result = _dns_lookup("api.example.com", "CNAME")
		self.assertEqual(result["status"], "NOERROR")
		self.assertEqual(result["record_status"], "FOUND")
		self.assertEqual(result["records"], ["edge.example.net."])

	def test_dns_nxdomain_is_a_no_record_result_not_an_error(self):
		with patch(
			"sentinel.osint.intelligence._get_json",
			return_value={"Status": 3, "Answer": []},
		):
			result = _dns_lookup("missing.example.com", "A")
		self.assertEqual(result["status"], "NXDOMAIN")
		self.assertEqual(result["record_status"], "NO_RECORD")
		self.assertEqual(result["records"], [])

	def test_dns_server_failures_are_distinguished_from_missing_records(self):
		with patch(
			"sentinel.osint.intelligence._get_json",
			return_value={"Status": 2, "Answer": []},
		):
			result = _dns_lookup("example.com", "AAAA")
		self.assertEqual(result["status"], "SERVFAIL")
		self.assertEqual(result["record_status"], "DNS_ERROR")

	def test_ip_target_reports_ptr_absence_without_treating_it_as_suspicious(self):
		with patch("sentinel.osint.intelligence._rdap_lookup", return_value={"organization": "Example"}), patch(
			"sentinel.osint.intelligence._dns_lookup",
			return_value={"status": "NXDOMAIN", "record_status": "NO_RECORD", "answers": [], "records": []},
		), patch("sentinel.osint.intelligence._ip_intelligence", return_value={"ip": "8.8.8.8"}):
			result = lookup_osint("8.8.8.8")
		self.assertIn("No PTR record found", result["sources"]["reverse_dns"]["result"])
		self.assertEqual(result["target_summary"]["resolved_addresses"], ["8.8.8.8"])
		self.assertFalse(result["target_summary"]["active_scan_performed"])


class RdapAndCertificateTests(unittest.TestCase):
	def test_rdap_summary_normalizes_range_organization_registration_and_abuse(self):
		rdap = _rdap_summary({
			"objectClassName": "ip network",
			"startAddress": "8.8.8.0",
			"endAddress": "8.8.8.255",
			"country": "US",
			"events": [{"eventAction": "registration", "eventDate": "2000-01-01"}],
			"entities": [{
				"handle": "ABUSE",
				"roles": ["abuse"],
				"vcardArray": ["vcard", [
					["org", {}, "text", ["Example Networks"]],
					["email", {}, "text", "abuse@example.net"],
				]],
			}],
		})
		self.assertEqual(rdap["network_range"]["start"], "8.8.8.0")
		self.assertEqual(rdap["organization"], "Example Networks")
		self.assertEqual(rdap["abuse_contacts"], ["abuse@example.net"])
		self.assertEqual(rdap["registration_information"]["events"][0]["eventAction"], "registration")

	def test_certificate_hostnames_are_normalized_deduplicated_and_separated_when_known(self):
		with patch(
			"sentinel.osint.intelligence._get_json",
			return_value=[
				{
					"common_name": "*.Example.com",
					"name_value": "www.example.com\nAPI.Example.com.\nwww.example.com",
					"subject_alt_names": ["api.example.com", "DEV.example.com"],
				},
				{"name_value": "invalid..example.com\nwww.example.com"},
			],
		):
			result = _certificate_names("example.com")
		self.assertEqual(result["common_names"], ["example.com"])
		self.assertEqual(result["subject_alt_names"], ["api.example.com", "dev.example.com"])
		self.assertEqual(result["hostnames"], ["api.example.com", "dev.example.com", "example.com", "www.example.com"])

	def test_ip_intelligence_marks_geolocation_approximate(self):
		with patch(
			"sentinel.osint.intelligence._get_json",
			return_value={
				"ip": "8.8.8.8",
				"country": "United States",
				"latitude": 37.4,
				"longitude": -122.0,
				"connection": {"asn": 15169, "org": "Example"},
			},
		):
			result = _ip_intelligence("8.8.8.8")
		self.assertEqual(result["geolocation"]["precision"], "approximate")
		self.assertEqual(result["organization"], "Example")


class ReconDataModelTests(unittest.TestCase):
	def test_recon_result_serializes_for_reports(self):
		result = ReconResult(
			target="example.com",
			target_type="domain",
			sources={"dns": {"A": {"records": ["203.0.113.1"]}}},
			target_summary={"resolved_addresses": ["203.0.113.1"]},
		).to_dict()
		self.assertEqual(result["sources"]["dns"]["A"]["records"], ["203.0.113.1"])
		self.assertEqual(result["target_summary"]["resolved_addresses"], ["203.0.113.1"])

	def test_recon_text_report_summarizes_sources_without_dumping_raw_json(self):
		text = render_report({
			"target": "example.com",
			"type": "domain",
			"target_summary": {"type": "hostname", "resolved_addresses": ["203.0.113.1"]},
			"sources": {
				"dns": {"A": {"records": ["203.0.113.1"]}, "CNAME": {"records": []}},
				"rdap": {"organization": "Example ISP"},
				"certificate_transparency": {"hostnames": ["api.example.com"]},
			},
			"errors": [],
		}, "txt")
		self.assertIn("SENTINEL RECONNAISSANCE", text)
		self.assertIn("A: 203.0.113.1", text)
		self.assertIn("Organization: Example ISP", text)
		self.assertIn("api.example.com", text)
		self.assertNotIn('"sources":', text)


class PortStateTests(unittest.TestCase):
	def test_socket_error_classification_distinguishes_states(self):
		self.assertEqual(classify_socket_error(ConnectionRefusedError()), "CLOSED")
		self.assertEqual(classify_socket_error(socket.timeout()), "TIMEOUT")
		self.assertEqual(classify_socket_error(PermissionError()), "FILTERED")
		self.assertEqual(classify_socket_error(OSError("unexpected")), "ERROR")

	def test_scan_port_reports_timeout_state(self):
		connection = Mock()
		connection.__enter__ = Mock(return_value=connection)
		connection.__exit__ = Mock(return_value=False)
		connection.connect.side_effect = socket.timeout()
		with patch("sentinel.network.scanner.socket.socket", return_value=connection):
			result = scan_port("192.168.1.1", 443, 0.2)
		self.assertEqual(result, (443, "TIMEOUT"))


class ServiceEvidenceTests(unittest.TestCase):
	def test_port_guess_is_not_labeled_as_confirmed_service(self):
		service = identify_service("192.168.1.1", 22, "CLOSED")
		self.assertEqual(service["name"], "SSH")
		self.assertEqual(service["identification"], "port_based_guess")
		self.assertEqual(service["confidence"], "LOW")
		self.assertEqual(service["evidence"][0]["value"], "TCP/22")
		self.assertNotIn("version", service)

	def test_observed_ssh_banner_is_stronger_evidence(self):
		with patch("sentinel.network.services._ssh_banner", return_value="SSH-2.0-Example"):
			service = identify_service("192.168.1.1", 22, "OPEN", timeout=0.5)
		self.assertEqual(service["identification"], "evidence_based")
		self.assertEqual(service["confidence"], "HIGH")
		self.assertEqual(service["evidence"][1]["source"], "ssh_banner")
		self.assertNotIn("version", service)

	def test_http_response_confirms_http_service(self):
		with patch(
			"sentinel.network.services._http_head",
			return_value={
				"status_code": 200,
				"headers": {"content-type": "text/html", "x-frame-options": "DENY"},
			},
		):
			service = identify_service("192.168.1.1", 80, "OPEN")
		self.assertEqual(service["identification"], "evidence_based")
		self.assertEqual(service["confidence"], "HIGH")
		self.assertEqual(service["name"], "HTTP")


class HttpAndTlsTests(unittest.TestCase):
	def test_http_head_returns_security_and_content_headers(self):
		from sentinel.router.audit import _http_head

		response = Mock(status=200)
		headers = {
			"server": "Example",
			"content-type": "text/html",
			"content-length": "123",
			"location": "/login",
			"strict-transport-security": "max-age=31536000",
			"content-security-policy": "default-src 'self'",
			"x-content-type-options": "nosniff",
			"x-frame-options": "DENY",
			"referrer-policy": "no-referrer",
		}
		response.getheader.side_effect = lambda name: headers.get(name)
		connection = Mock()
		connection.getresponse.return_value = response
		with patch("sentinel.router.audit.http.client.HTTPConnection", return_value=connection):
			result = _http_head(ipaddress.ip_address("192.168.1.1"), 80, "http", 1.0)
		self.assertEqual(result["status_code"], 200)
		self.assertEqual(result["headers"]["content-security-policy"], "default-src 'self'")
		self.assertEqual(result["headers"]["content-length"], "123")

	def test_tls_metadata_includes_subject_issuer_dates_sans_and_version(self):
		from sentinel.router.audit import _tls_inspect

		certificate = {
			"subject": ((("commonName", "router.example"),),),
			"issuer": ((("organizationName", "Example CA"),),),
			"notBefore": "Jan  1 00:00:00 2026 GMT",
			"notAfter": "Jan  1 00:00:00 2027 GMT",
			"subjectAltName": (("DNS", "router.example"), ("IP Address", "192.168.1.1")),
		}
		tls_socket = Mock()
		tls_socket.getpeercert.side_effect = lambda **kwargs: b"certificate-der" if kwargs.get("binary_form") else certificate
		tls_socket.version.return_value = "TLSv1.3"
		tls_socket.cipher.return_value = ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)
		context = Mock()
		context.wrap_socket.return_value = tls_socket
		with patch("sentinel.router.audit.ssl.create_default_context", return_value=context), patch(
			"sentinel.router.audit.socket.create_connection", return_value=Mock()
		):
			result = _tls_inspect(ipaddress.ip_address("192.168.1.1"), 443, 1.0)
		self.assertEqual(result["tls_version"], "TLSv1.3")
		self.assertEqual(result["subject"], certificate["subject"])
		self.assertEqual(result["issuer"], certificate["issuer"])
		self.assertEqual(result["hostnames"], ["192.168.1.1", "router.example"])
		self.assertEqual(result["certificate_verification"], "valid")


class LocalInventoryParsingTests(unittest.TestCase):
	def test_linux_interface_parser_includes_address_and_subnet(self):
		interfaces = _parse_linux_interfaces(
			"2: eth0 inet 192.168.1.12/24 brd 192.168.1.255 scope global eth0\n"
			"2: eth0 inet6 fe80::1/64 scope link\n"
		)
		self.assertEqual(interfaces[0]["name"], "eth0")
		self.assertEqual(
			{item["network"] for item in interfaces[0]["addresses"]},
			{"192.168.1.0/24", "fe80::/64"},
		)

	def test_windows_interface_parser_reads_local_adapter_details(self):
		interfaces = _parse_windows_interfaces(
			"Ethernet adapter Ethernet:\n"
			"   Physical Address. . . . . . . . . : AA-BB-CC-DD-EE-FF\n"
			"   IPv4 Address. . . . . . . . . . . : 192.168.1.12(Preferred)\n"
			"   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n"
		)
		self.assertEqual(interfaces[0]["mac"], "aa:bb:cc:dd:ee:ff")
		self.assertEqual(interfaces[0]["addresses"][0]["network"], "192.168.1.0/24")

	def test_macos_interface_parser_reads_ipv4_subnet_and_mac(self):
		interfaces = _parse_macos_interfaces(
			"en0: flags=8863<UP,BROADCAST,RUNNING>\n"
			"\tether aa:bb:cc:dd:ee:ff\n"
			"\tinet 192.168.1.12 netmask 0xffffff00 broadcast 192.168.1.255\n"
		)
		self.assertEqual(interfaces[0]["name"], "en0")
		self.assertEqual(interfaces[0]["mac"], "aa:bb:cc:dd:ee:ff")
		self.assertEqual(interfaces[0]["addresses"][0]["network"], "192.168.1.0/24")


if __name__ == "__main__":
	unittest.main()
