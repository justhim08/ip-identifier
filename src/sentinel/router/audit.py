"""Perform a bounded, non-invasive inventory of an authorized private router."""

import hashlib
import http.client
import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from urllib.request import urlopen

from ..config import DEFAULT_CONFIG
from ..intel.vulnerability import (
	findings_for_cves,
	lookup_nvd,
)
from ..validation import validate_timeout
from .findings import make_finding


ROUTER_TCP_PORTS = {
	22: "SSH",
	23: "Telnet",
	53: "DNS over TCP",
	80: "HTTP administration",
	443: "HTTPS administration",
	7547: "TR-069/CWMP",
	8080: "Alternate HTTP",
	8443: "Alternate HTTPS",
}
HTTP_PORTS = {80: "http", 443: "https", 8080: "http", 8443: "https"}
REQUEST_TIMEOUT = DEFAULT_CONFIG.connection_timeout
NVD_TIMEOUT = 10
USER_AGENT = "SENTINEL/1.0 (authorized router inventory)"
ALLOWED_NETWORKS = (
	ipaddress.ip_network("10.0.0.0/8"),
	ipaddress.ip_network("172.16.0.0/12"),
	ipaddress.ip_network("192.168.0.0/16"),
	ipaddress.ip_network("169.254.0.0/16"),
	ipaddress.ip_network("127.0.0.0/8"),
	ipaddress.ip_network("fc00::/7"),
	ipaddress.ip_network("fe80::/10"),
	ipaddress.ip_network("::1/128"),
)


def _validate_router_target(value, network_value=None):
	try:
		address = ipaddress.ip_address(value.strip())
	except ValueError as exc:
		raise ValueError("Router audit requires a literal private-network IP address.") from exc
	if address.version == 6 and address.scope_id is not None:
		raise ValueError("Scoped IPv6 addresses are not supported.")
	allowed_for_address = tuple(
		network for network in ALLOWED_NETWORKS if network.version == address.version
	)
	if not any(address in network for network in allowed_for_address):
		raise ValueError("Router audit is limited to private, link-local, or loopback IP addresses.")

	network = None
	if network_value:
		try:
			network = ipaddress.ip_network(network_value, strict=False)
		except ValueError as exc:
			raise ValueError("Network must be a valid subnet in CIDR notation, such as 192.168.1.0/24.") from exc
		if network.version != address.version or address not in network:
			raise ValueError("The router IP must belong to the supplied subnet.")
		if not any(
			network.version == allowed.version and network.subnet_of(allowed)
			for allowed in ALLOWED_NETWORKS
		):
			raise ValueError("Router audit subnet must be private, link-local, or loopback.")
	return address, network


def _probe_tcp(address, port, timeout=REQUEST_TIMEOUT):
	family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
	target = (str(address), port, 0, 0) if family == socket.AF_INET6 else (str(address), port)
	try:
		with socket.socket(family, socket.SOCK_STREAM) as connection:
			connection.settimeout(timeout)
			connection.connect(target)
		return "open"
	except ConnectionRefusedError:
		return "closed"
	except (TimeoutError, socket.timeout):
		return "no response"
	except OSError as exc:
		return {"error": str(exc)}


def _http_head(address, port, scheme, timeout=REQUEST_TIMEOUT):
	connection_type = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
	host = f"[{address}]" if address.version == 6 else str(address)
	connection = connection_type(host, port, timeout=timeout)
	try:
		connection.request("HEAD", "/", headers={"User-Agent": USER_AGENT, "Connection": "close"})
		response = connection.getresponse()
		allowed_headers = (
			"server",
			"content-type",
			"content-length",
			"location",
			"strict-transport-security",
			"content-security-policy",
			"x-content-type-options",
			"x-frame-options",
			"referrer-policy",
			"www-authenticate",
			"x-router-model",
			"x-firmware-version",
			"x-powered-by",
		)
		result = {
			"status_code": response.status,
			"headers": {
				name: response.getheader(name)
				for name in allowed_headers
				if response.getheader(name)
			},
		}
		if scheme == "https":
			result["tls"] = _tls_inspect(address, port, timeout)
		return result
	except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
		result = {"error": str(exc)}
		if scheme == "https":
			result["tls"] = _tls_inspect(address, port, timeout)
		return result
	finally:
		connection.close()


def _certificate_names(certificate):
	names = []
	for entry in certificate.get("subjectAltName", ()):
		if entry[0] in {"DNS", "IP Address"}:
			names.append(entry[1])
	return sorted(set(names))


def _certificate_subject_name(certificate, name):
	for rdn in certificate.get(name, ()):
		for key, value in rdn:
			if key == "commonName":
				return value
	return None


def _tls_inspect(address, port, timeout):
	"""Collect TLS metadata without weakening the reported verification status."""
	host = str(address)
	context = ssl.create_default_context()
	verified = True
	try:
		raw_socket = socket.create_connection((host, port), timeout=timeout)
		try:
			tls_socket = context.wrap_socket(raw_socket, server_hostname=host)
		except ssl.SSLCertVerificationError:
			raw_socket.close()
			raise
	except ssl.SSLCertVerificationError as verification_error:
		context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
		context.check_hostname = False
		context.verify_mode = ssl.CERT_NONE
		verified = False
		try:
			raw_socket = socket.create_connection((host, port), timeout=timeout)
			tls_socket = context.wrap_socket(raw_socket, server_hostname=host)
		except (OSError, ssl.SSLError) as exc:
			return {"error": str(exc), "certificate_verification": "failed"}
		verification_message = str(verification_error)
	except (OSError, ssl.SSLError) as exc:
		return {"error": str(exc), "certificate_verification": "failed"}
	else:
		verification_message = None

	try:
		peer_certificate = tls_socket.getpeercert()
		certificate_der = tls_socket.getpeercert(binary_form=True)
		result = {
			"tls_version": tls_socket.version(),
			"cipher": tls_socket.cipher()[0] if tls_socket.cipher() else None,
			"certificate_verification": "valid" if verified else "not trusted",
			"certificate_sha256": hashlib.sha256(certificate_der).hexdigest() if certificate_der else None,
			"subject": peer_certificate.get("subject", ()),
			"issuer": peer_certificate.get("issuer", ()),
			"valid_from": peer_certificate.get("notBefore"),
			"valid_until": peer_certificate.get("notAfter"),
			"hostnames": _certificate_names(peer_certificate),
		}
		if verification_message:
			result["verification_note"] = verification_message
			if "hostname" in verification_message.lower() or "ip address mismatch" in verification_message.lower():
				result["hostname_verification"] = "mismatch"
			else:
				result["hostname_verification"] = "not_verified"
		else:
			result["hostname_verification"] = "valid"
		result["certificate_subject"] = _certificate_subject_name(peer_certificate, "subject")
		result["certificate_issuer"] = _certificate_subject_name(peer_certificate, "issuer")
		if not verified:
			result["metadata_note"] = (
				"Certificate-chain and hostname verification failed; TLS metadata is observational only."
			)
		return result
	except (OSError, ssl.SSLError) as exc:
		return {"error": str(exc)}
	finally:
		tls_socket.close()


def _nvd_advisories(model, firmware):
	search_text = " ".join(value.strip() for value in (model, firmware) if value and value.strip())
	if not search_text:
		return {"status": "not_requested", "reason": "Supply --model and/or --firmware to search public NVD records."}
	result = lookup_nvd(search_text, timeout=NVD_TIMEOUT, opener=urlopen)
	for vulnerability in result.get("results", []):
		vulnerability["cvss"] = {
			key: vulnerability.get("cvss", {}).get(key)
			for key in ("score", "severity", "version")
		}
		vulnerability["product_match_status"] = (
			"potentially_affected" if vulnerability.get("affected_products") else "not_identified"
		)
	return result


def _tls_findings(target, port, service_name, tls):
	findings = []
	if not isinstance(tls, dict):
		return findings
	if tls.get("hostname_verification") == "mismatch":
		findings.append(make_finding(
			f"ROUTER-TLS-HOSTNAME-{port}",
			"TLS Certificate Hostname Mismatch",
			"LOW",
			target,
			"The certificate identity did not match the IP address used for this assessment.",
			[{"method": "TLS certificate verification", "value": tls.get("verification_note", "Hostname mismatch")}],
			"Users accessing the interface by this address may receive a certificate identity warning.",
			"Verify the intended management hostname and use the manufacturer-recommended certificate configuration.",
			port,
			service_name,
			category="certificate_observation",
			confidence="HIGH",
			status="OBSERVED",
		))
	if tls.get("certificate_verification") == "not trusted":
		expiry = tls.get("valid_until")
		expired_note = "expired" in str(tls.get("verification_note", "")).lower()
		expired = False
		if expiry:
			try:
				expires_at = datetime.strptime(expiry, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
				expired = expires_at < datetime.now(timezone.utc)
			except ValueError:
				pass
		if expired or expired_note:
			findings.append(make_finding(
				f"ROUTER-TLS-EXPIRED-{port}",
				"TLS Certificate Expired",
				"LOW",
				target,
				"The observed TLS certificate expiration date has passed.",
				[{"method": "TLS certificate", "value": f"Valid until {expiry}" if expiry else tls.get("verification_note")}],
				"Clients may be unable to verify the management interface certificate normally.",
				"Renew or replace the certificate through the router's supported administration process.",
				port,
				service_name,
				category="certificate_observation",
				confidence="HIGH",
				status="OBSERVED",
			))
	if tls.get("tls_version") in {"TLSv1", "TLSv1.1"}:
		findings.append(make_finding(
			f"ROUTER-TLS-LEGACY-{port}",
			"Obsolete TLS Version Observed",
			"MEDIUM",
			target,
			"The management endpoint negotiated an obsolete TLS protocol version.",
			[{"method": "TLS handshake", "value": tls["tls_version"]}],
			"Older TLS protocol versions lack modern security protections and may not meet current security policy.",
			"Where supported, configure the router to use current TLS versions and consult its vendor documentation.",
			port,
			service_name,
			category="tls_configuration_observation",
			confidence="HIGH",
			status="OBSERVED",
		))
	return findings


def _router_identity(model, firmware, services):
	headers = {}
	for service in services.values():
		http_result = service.get("http_head")
		if isinstance(http_result, dict):
			headers.update(http_result.get("headers", {}))
	header_model = headers.get("x-router-model")
	header_firmware = headers.get("x-firmware-version")
	observed_model = header_model or model
	model_text = (header_model or headers.get("server") or model or "").lower()
	manufacturer = next(
		(name for token, name in (
			("tp-link", "TP-Link"),
			("netgear", "NETGEAR"),
			("linksys", "Linksys"),
			("asus", "ASUS"),
			("d-link", "D-Link"),
			("cisco", "Cisco"),
			("ubiquiti", "Ubiquiti"),
			("huawei", "Huawei"),
			("zyxel", "Zyxel"),
		) if token in model_text),
		None,
	)
	return {
		"model": observed_model,
		"manufacturer": manufacturer,
		"manufacturer_confidence": "POTENTIAL MATCH" if manufacturer else "UNKNOWN",
		"model_confidence": "POTENTIAL MATCH" if observed_model else "UNKNOWN",
		"model_evidence": (
			[{"source": "HTTP X-Router-Model header", "value": header_model}]
			if header_model else
			([{"source": "administrator-provided input", "value": model}] if model else [])
		),
		"firmware": header_firmware or firmware or "Unknown",
		"firmware_source": (
			"HTTP X-Firmware-Version header" if header_firmware
			else "administrator-provided input" if firmware else "unknown"
		),
		"model_supplied_by_user": model,
		"firmware_supplied_by_user": firmware,
		"identification_note": (
			"HTTP identity headers and administrator-provided values are unverified hints, not independent "
			"confirmation of router model or firmware."
		),
	}


def audit_router(target, model=None, firmware=None, network_value=None, timeout=REQUEST_TIMEOUT):
	"""Inventory a private-network router without authentication or configuration changes."""
	timeout = validate_timeout(timeout)
	address, network = _validate_router_target(target, network_value)
	services = {}
	for port, name in ROUTER_TCP_PORTS.items():
		status = (
			_probe_tcp(address, port)
			if timeout == REQUEST_TIMEOUT
			else _probe_tcp(address, port, timeout)
		)
		service = {"name": name, "tcp_status": status}
		if status == "open" and port in HTTP_PORTS:
			service["http_head"] = (
				_http_head(address, port, HTTP_PORTS[port])
				if timeout == REQUEST_TIMEOUT
				else _http_head(address, port, HTTP_PORTS[port], timeout)
			)
		services[str(port)] = service

	findings = []
	service_assessments = []
	for port, name in ROUTER_TCP_PORTS.items():
		service = services[str(port)]
		status = service["tcp_status"]
		state = "OPEN" if status == "open" else "CLOSED" if status == "closed" else (
			"ERROR" if isinstance(status, dict) else "NO RESPONSE"
		)
		http_result = service.get("http_head")
		evidence = [{"method": "TCP connect", "value": "Connection accepted" if status == "open" else str(status)}]
		if isinstance(http_result, dict):
			if http_result.get("status_code") is not None:
				evidence.append({"method": "HTTP HEAD /", "value": f"HTTP {http_result['status_code']}"})
			if http_result.get("error"):
				evidence.append({"method": "HTTP HEAD /", "value": http_result["error"]})
		service_assessments.append({
			"port": port,
			"protocol": "tcp",
			"state": state,
			"service": name,
			"evidence": evidence,
			"confidence": "HIGH" if isinstance(status, str) and status in {"open", "closed"} else "UNKNOWN",
		})
		if port == 23 and status == "open":
			findings.append(make_finding(
				"ROUTER-TELNET-001",
				"Telnet Service Exposed",
				"HIGH",
				str(address),
				"Telnet is an insecure remote-administration protocol and should generally be replaced by secure administration mechanisms.",
				[{"method": "TCP connect", "value": "TCP/23 is reachable."}],
				"Remote administration over Telnet may expose management traffic to interception on the network.",
				"Disable Telnet if unnecessary and use secure administration such as SSH where supported.",
				23,
				"Telnet",
				category="service_exposure",
				confidence="HIGH",
				status="OBSERVED",
			))
		if port in {80, 8080} and status == "open" and isinstance(http_result, dict) and http_result.get("status_code") is not None:
			findings.append(make_finding(
				"ROUTER-HTTP-MGMT-001" if port == 80 else f"ROUTER-HTTP-MGMT-{port}",
				"Router Administration Interface Available Over HTTP",
				"MEDIUM",
				str(address),
				"An HTTP response was detected on a configured router management port. This does not establish that a login page is present or that credentials are transmitted.",
				[{"method": "HTTP HEAD /", "value": f"HTTP {http_result['status_code']} on TCP/{port}"}],
				"Management functions, if available through this interface, may not receive transport encryption.",
				"Prefer HTTPS-only administration if supported and disable unnecessary HTTP management.",
				port,
				"HTTP",
				category="management_interface_observation",
				confidence="MEDIUM",
				status="POTENTIAL",
			))
		if port == 7547 and status == "open":
			findings.append(make_finding(
				"ROUTER-TR069-001",
				"TR-069 / CWMP-Related Service Detected",
				"INFO",
				str(address),
				"A TCP service commonly associated with TR-069/CWMP was reachable; port reachability alone does not establish a vulnerability.",
				[{"method": "TCP connect", "value": "TCP/7547 is reachable."}],
				"An unnecessary remote-management service may increase the router's exposed service surface.",
				"Review whether remote management is required and ensure router firmware is current.",
				7547,
				"TR-069/CWMP",
				category="service_exposure",
				confidence="LOW",
				status="POTENTIAL",
			))
		if isinstance(http_result, dict):
			findings.extend(_tls_findings(str(address), port, name, http_result.get("tls")))

	http_secure = any(
		port in {443, 8443} and isinstance(services[str(port)].get("http_head"), dict)
		and services[str(port)]["http_head"].get("status_code") is not None
		for port in HTTP_PORTS
	)
	http_plain = any(
		port in {80, 8080} and isinstance(services[str(port)].get("http_head"), dict)
		and services[str(port)]["http_head"].get("status_code") is not None
		for port in HTTP_PORTS
	)
	management_transport = (
		"HTTP + HTTPS" if http_plain and http_secure else
		"HTTP only" if http_plain else
		"HTTPS only" if http_secure else
		"Unknown"
	)
	router_identity = _router_identity(model, firmware, services)
	advisories = _nvd_advisories(model, firmware)
	cve_findings = findings_for_cves(str(address), advisories.get("results", []))
	findings.extend(cve_findings)
	report = {
		"target": str(address),
		"network": str(network) if network else None,
		"router_identity": router_identity,
		"scope": (
			"Authorized private-network inventory only. Checks a fixed list of TCP ports and sends "
			"HTTP HEAD requests to detected administration ports. No login attempts, password testing, "
			"packet capture, configuration changes, UDP probing, or exploitation."
		),
		"services": services,
		"service_assessments": service_assessments,
		"findings": findings,
		"management_transport": management_transport,
		"upnp": "Not assessed by current TCP scanner",
		"udp_services": {
			"status": "not_checked",
			"note": "UDP services such as UPnP/SSDP are not probed by this TCP-only audit.",
		},
		"vulnerability_advisories": advisories,
		"summary": {
			"open_services": [item for item in service_assessments if item["state"] == "OPEN"],
			"finding_count": len(findings),
			"assessment": "Preliminary evidence-based observations; this is not a comprehensive router vulnerability determination.",
		},
	}
	from ..intel.pipeline import enrich_intelligence

	return enrich_intelligence(report)
