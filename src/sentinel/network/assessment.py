"""Application-level orchestration for authorized TCP service assessments."""

from typing import Any, Dict, List

from .scanner import scan_ports
from .services import identify_service


def assess_tcp_services(
	address: str,
	ports: List[int],
	timeout: float,
	concurrency: int,
) -> Dict[str, Any]:
	"""Scan selected TCP ports and return service labels and aggregate counts."""
	scan_results = scan_ports(address, ports, timeout=timeout, max_workers=concurrency)
	services = []
	for port, status in scan_results:
		services.append({
			"port": port,
			"service": identify_service(address, port, status, timeout=timeout),
			"status": status,
		})
	statuses = ("OPEN", "CLOSED", "FILTERED", "TIMEOUT", "ERROR")
	return {
		"target": address,
		"ports": services,
		"summary": {
			status: sum(item_status == status for _, item_status in scan_results)
			for status in statuses
		},
		"state_limitations": (
			"TIMEOUT means the connection attempt exceeded its timeout. FILTERED is reported only "
			"when the operating system returns an access-denied result. Network/path failures are "
			"reported as ERROR because a client cannot reliably distinguish filtering from routing or "
			"other failures."
		),
		"scope": "Authorized TCP connectivity checks only; no stealth or firewall-evasion techniques.",
	}
