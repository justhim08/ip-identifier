"""Argument-driven and interactive command-line interfaces for SENTINEL."""

import argparse
import json
import logging
import socket
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from .config import (
	DEFAULT_PORTS,
	ConfigurationError,
	SentinelConfig,
	load_config,
)
from .files.analysis import analyze_file
from .intel.pipeline import enrich_intelligence
from .intel.vulnerability import correlate_product_version, findings_for_cves, lookup_nvd
from .logging_config import configure_logging
from .network.assessment import assess_tcp_services
from .network.inventory import collect_local_inventory
from .network.wifi import discover_wifi_access_points, require_authorization_confirmation
from .osint.intelligence import lookup_osint
from .reports.renderer import export_report, resolve_format
from .risk.engine import assess_report
from .router.audit import audit_router
from .validation import (
	parse_port_ranges,
	validate_concurrency,
	validate_file_path,
	validate_ip_address,
	validate_log_level,
	validate_target,
	validate_timeout,
)


LOGGER = logging.getLogger("sentinel")


def _output_format(value: str) -> str:
	"""Normalize the user-facing text alias to the renderer's ``txt`` name."""
	output_format = value.lower()
	if output_format == "text":
		output_format = "txt"
	if output_format not in {"json", "csv", "txt"}:
		raise argparse.ArgumentTypeError("Choose json, csv, or text.")
	return output_format


def _log_level(value: str) -> str:
	try:
		return validate_log_level(value)
	except ValueError as exc:
		raise argparse.ArgumentTypeError(str(exc)) from exc


def _add_common_options(parser: argparse.ArgumentParser, root: bool = False) -> None:
	default = None if root else argparse.SUPPRESS
	parser.add_argument("--config", metavar="FILE", default=default, help="load optional settings from a TOML file")
	parser.add_argument("--log-level", type=_log_level, default=default, help="DEBUG, INFO, WARNING, or ERROR")
	parser.add_argument("--timeout", type=validate_timeout, default=default, help="TCP connection timeout in seconds (0.1-5)")
	parser.add_argument("--concurrency", type=validate_concurrency, default=default, help="maximum concurrent TCP checks (1-100)")
	parser.add_argument("--ports", type=parse_port_ranges, default=default, help="TCP ports/ranges for scan, e.g. 22,80,8000-8010")
	parser.add_argument("--report-directory", metavar="DIR", default=default, help="directory for relative report output paths")
	parser.add_argument(
		"--output-format",
		"--format",
		type=_output_format,
		default=default,
		metavar="FORMAT",
		help="report format: json, csv, or text",
	)
	parser.add_argument("--output", metavar="FILE", default=default, help="write the generated report to this file")


def build_parser() -> argparse.ArgumentParser:
	"""Create the top-level parser and supported command parsers."""
	parser = argparse.ArgumentParser(
		prog="sentinel",
		description=(
			"SENTINEL\n"
			"Network Security Assessment & Threat Intelligence Toolkit\n\n"
			"Use only on systems and networks you own or have explicit permission to assess."
		),
		epilog=(
			"Commands:\n"
			"  recon         Passive domain/IP reconnaissance\n"
			"  intel         Passive reconnaissance with provenance and relationships\n"
			"  cve           Search and correlate public NVD vulnerability intelligence\n"
			"  scan          Authorized TCP service assessment\n"
			"  router-audit  Audit an authorized private router\n"
			"  inventory     View local network information without probing\n"
			"  file          Perform static local file/IOC analysis\n"
			"  assess        Score findings in a saved report without new scans\n"
			"  report        Render an existing JSON report as JSON, CSV, or text\n"
			"  settings      Show the effective configuration\n\n"
			"Examples (use scan only for authorized targets):\n"
			"  sentinel recon example.com\n"
			"  sentinel intel example.com\n"
			"  sentinel cve \"Example Router\" --vendor example --product router --version 1.2.3\n"
			"  sentinel scan 192.168.1.1 --ports 22,80,443\n"
			"  sentinel router-audit 192.168.1.1 --authorized\n"
			"  sentinel file suspicious.pdf"
			"\n"
			"  sentinel assess assessment.json --exposure private --output-format text"
		),
		formatter_class=argparse.RawDescriptionHelpFormatter,
	)
	_add_common_options(parser, root=True)

	legacy = parser.add_mutually_exclusive_group()
	legacy.add_argument("--osint", dest="legacy_osint", metavar="TARGET", help=argparse.SUPPRESS)
	legacy.add_argument("--extract", dest="legacy_extract", metavar="FILE", help=argparse.SUPPRESS)
	legacy.add_argument("--router-audit", dest="legacy_router_audit", metavar="IP", help=argparse.SUPPRESS)
	legacy.add_argument(
		"--local-inventory",
		dest="legacy_inventory",
		action="store_true",
		help=argparse.SUPPRESS,
	)
	parser.add_argument("--model", dest="legacy_model", help=argparse.SUPPRESS)
	parser.add_argument("--firmware", dest="legacy_firmware", help=argparse.SUPPRESS)
	parser.add_argument("--network", dest="legacy_network", help=argparse.SUPPRESS)
	parser.add_argument(
		"--authorized",
		action="store_true",
		default=argparse.SUPPRESS,
		help="confirm that you own or have explicit permission to assess the router",
	)

	commands = parser.add_subparsers(dest="command")
	recon_parser = commands.add_parser("recon", help="passive domain/IP reconnaissance")
	_add_common_options(recon_parser)
	recon_parser.add_argument("target", help="public hostname, URL, or globally routable IP")

	intel_parser = commands.add_parser("intel", help="passive intelligence with source provenance and relationships")
	_add_common_options(intel_parser)
	intel_parser.add_argument("target", help="public hostname, URL, or globally routable IP")

	cve_parser = commands.add_parser("cve", help="search public NVD CVE intelligence")
	_add_common_options(cve_parser)
	cve_parser.add_argument("query", help="product, vendor, model, or CVE search text")
	cve_parser.add_argument("--vendor", help="observed product vendor for conservative correlation")
	cve_parser.add_argument("--product", help="observed product name for conservative correlation")
	cve_parser.add_argument("--version", help="observed product version for conservative correlation")

	scan_parser = commands.add_parser("scan", help="authorized TCP service assessment")
	_add_common_options(scan_parser)
	scan_parser.add_argument("target", help="literal IP address of an authorized assessment target")

	router_parser = commands.add_parser("router-audit", help="audit an authorized private-network router")
	_add_common_options(router_parser)
	router_parser.add_argument("target", help="private, link-local, or loopback router IP")
	router_parser.add_argument("--model", help="router model to search in public vulnerability advisories")
	router_parser.add_argument("--firmware", help="router firmware version to include in advisory lookup")
	router_parser.add_argument("--network", help="optional authorized subnet in CIDR notation")
	router_parser.add_argument(
		"--authorized",
		action="store_true",
		default=argparse.SUPPRESS,
		help="confirm that you own or have explicit permission to assess the router",
	)

	file_parser = commands.add_parser(
		"file",
		help="safely analyze a local file for metadata, indicators, and evidence",
		description=(
			"Identify and hash a local file, then extract supported content without "
			"executing files, scripts, macros, or attachment payloads."
		),
	)
	_add_common_options(file_parser)
	file_parser.add_argument("path", help="path to a supported local file")

	assess_parser = commands.add_parser(
		"assess",
		help="rank findings in a saved report using deterministic, explainable risk rules",
		description=(
			"Assess findings already present in a SENTINEL JSON report. This command "
			"does not scan targets, inspect files, or contact external services."
		),
	)
	_add_common_options(assess_parser)
	assess_parser.add_argument("path", help="path to an existing SENTINEL JSON report")
	assess_parser.add_argument(
		"--exposure",
		choices=("unknown", "private", "public"),
		default="unknown",
		help="explicitly supplied target exposure context (default: unknown)",
	)

	inventory_parser = commands.add_parser("inventory", help="read local gateway and cached neighbor information")
	_add_common_options(inventory_parser)

	report_parser = commands.add_parser("report", help="render an existing JSON report in another format")
	_add_common_options(report_parser)
	report_parser.add_argument("path", help="path to a SENTINEL JSON report")

	settings_parser = commands.add_parser("settings", help="show effective SENTINEL settings")
	_add_common_options(settings_parser)
	return parser


def run_recon(target: str) -> Dict[str, Any]:
	"""Perform the existing passive OSINT workflow for a validated target."""
	validate_target(target)
	LOGGER.info("Starting passive reconnaissance.")
	report = lookup_osint(target)
	LOGGER.info("Passive reconnaissance completed.")
	return report


def run_cve_lookup(
	query: str,
	vendor: Optional[str] = None,
	product: Optional[str] = None,
	version: Optional[str] = None,
) -> Dict[str, Any]:
	"""Search NVD and optionally compare reported product/version evidence."""
	LOGGER.info("Starting passive NVD vulnerability-intelligence lookup.")
	report = lookup_nvd(query)
	if report.get("status") in {"unavailable", "rate_limited"}:
		LOGGER.warning("NVD lookup %s: %s", report["status"], report.get("error", "no details"))
	results = report.get("results", [])
	correlations = []
	product_evidence = None
	if vendor or product or version:
		product_evidence = {
			"vendor": vendor or "",
			"product": product or "",
			"version": version or "",
			"confidence": "MEDIUM" if vendor and product and version else "LOW",
			"evidence_source": "administrator-provided input",
		}
		correlations = correlate_product_version(product_evidence, results)
	report["target"] = query
	report["product_evidence"] = product_evidence
	report["correlations"] = correlations
	report["findings"] = findings_for_cves(query, results, correlations)
	enriched = enrich_intelligence({
		"target": query,
		"type": "vulnerability_query",
		"vulnerability_advisories": report,
	})
	report["intelligence"] = enriched["intelligence"]
	report["relationships"] = enriched["relationships"]
	report["intelligence_generated_at"] = enriched["intelligence_generated_at"]
	LOGGER.info("Passive NVD vulnerability-intelligence lookup completed.")
	return report


def run_scan(
	target: str,
	config: SentinelConfig,
	ports: Optional[Sequence[int]] = None,
	timeout: Optional[float] = None,
	concurrency: Optional[int] = None,
) -> Dict[str, Any]:
	"""Run the existing bounded TCP assessment through the network layer."""
	address = validate_ip_address(target)
	selected_ports = list(ports) if ports is not None else list(config.default_ports)
	selected_timeout = timeout if timeout is not None else config.connection_timeout
	selected_concurrency = concurrency if concurrency is not None else config.scanner_concurrency
	LOGGER.info("Starting authorized TCP service assessment.")
	report = assess_tcp_services(address, selected_ports, selected_timeout, selected_concurrency)
	LOGGER.info("TCP service assessment completed.")
	return enrich_intelligence(report)


def run_router_audit(
	target: str,
	config: SentinelConfig,
	model: Optional[str] = None,
	firmware: Optional[str] = None,
	network: Optional[str] = None,
) -> Dict[str, Any]:
	"""Run the existing bounded private-router audit."""
	LOGGER.info("Starting authorized private-router audit.")
	report = audit_router(
		target,
		model=model,
		firmware=firmware,
		network_value=network,
		timeout=config.connection_timeout,
	)
	advisories = report.get("vulnerability_advisories", {})
	if advisories.get("status") in {"unavailable", "rate_limited"}:
		LOGGER.warning("NVD lookup %s; continuing with local router service assessment.", advisories["status"])
	LOGGER.info("Private-router audit completed.")
	return report


def _confirm_router_authorization(authorized_flag: bool = False) -> None:
	"""Require explicit operator authorization at the CLI boundary."""
	print("This module is intended only for routers you own or have explicit permission to assess.")
	if authorized_flag:
		require_authorization_confirmation("I AM AUTHORIZED")
		return
	require_authorization_confirmation(input('Type "I AM AUTHORIZED" to continue: '))


def run_file_analysis(path: str) -> Dict[str, Any]:
	"""Analyze a local file without executing or uploading its contents."""
	valid_path = validate_file_path(path)
	LOGGER.info("Analyzing a local artifact locally.")
	return analyze_file(str(valid_path))


def run_inventory() -> Dict[str, Any]:
	"""Return the existing read-only local network inventory."""
	LOGGER.info("Reading the local gateway and cached neighbor information.")
	return collect_local_inventory()


def load_report(path: str) -> Dict[str, Any]:
	"""Load an existing JSON object report for rendering in another format."""
	report_path = validate_file_path(path)
	try:
		with report_path.open("r", encoding="utf-8") as report_file:
			report = json.load(report_file)
	except (OSError, json.JSONDecodeError) as exc:
		raise ValueError(f"Could not read JSON report '{report_path}': {exc}") from exc
	if not isinstance(report, dict):
		raise ValueError("A SENTINEL report must be a JSON object.")
	return report


def run_assessment(path: str, exposure: str = "unknown") -> Dict[str, Any]:
	"""Assess a saved report's findings without collecting additional information."""
	exposure_values = {
		"unknown": "EXPOSURE_UNKNOWN",
		"private": "PRIVATE_TARGET",
		"public": "PUBLIC_TARGET",
	}
	if exposure not in exposure_values:
		raise ValueError("Exposure must be unknown, private, or public.")
	report = load_report(path)
	return assess_report(
		report,
		exposure=exposure_values[exposure],
		exposure_source="operator-provided context" if exposure != "unknown" else "not supplied",
	)


def _effective_output_path(
	path: Optional[str],
	config: SentinelConfig,
	output_format: str,
) -> Optional[Path]:
	if path is None:
		return None
	output_path = Path(path).expanduser()
	if not output_path.is_absolute():
		output_path = config.report_directory / output_path
	if path.endswith(("/", "\\")) or output_path.is_dir():
		extension = "txt" if output_format == "txt" else output_format
		filename = f"sentinel_report_{datetime.now():%Y%m%d_%H%M%S_%f}.{extension}"
		output_path = output_path / filename
	return output_path


def display_report(
	report: Dict[str, Any],
	output_path: Optional[str],
	output_format: Optional[str],
	config: SentinelConfig,
) -> None:
	"""Render results with the shared report module and optionally save them."""
	selected_format = output_format or config.output_format
	resolved_path = _effective_output_path(output_path, config, selected_format)
	serialized = export_report(report, resolved_path, selected_format)
	if resolved_path:
		print(f"Saved {resolve_format(resolved_path, selected_format).upper()} report to {resolved_path.resolve()}")
	else:
		print(serialized, end="")


def _configuration_overrides(args: argparse.Namespace) -> Dict[str, Any]:
	return {
		"timeout": getattr(args, "timeout", None),
		"concurrency": getattr(args, "concurrency", None),
		"ports": getattr(args, "ports", None),
		"report_directory": getattr(args, "report_directory", None),
		"log_level": getattr(args, "log_level", None),
		"output_format": getattr(args, "output_format", None),
	}


def _print_settings(config: SentinelConfig) -> None:
	if config.default_ports == DEFAULT_PORTS:
		ports = "common"
	else:
		ports = ",".join(str(port) for port in config.default_ports)
	print("CURRENT CONFIGURATION")
	print(f"Timeout:       {config.connection_timeout:.1f}s")
	print(f"Concurrency:   {config.scanner_concurrency}")
	print(f"Ports:         {ports}")
	print(f"Reports:       {config.report_directory}")
	print(f"Output format: {config.output_format}")
	print(f"Log level:     {config.log_level}")


def _prompt_report_export(report: Dict[str, Any], config: SentinelConfig) -> None:
	default_choice = {"json": "1", "csv": "2", "txt": "3"}[config.output_format]
	choice = (
		input(f"Report format: 1. JSON  2. CSV  3. Readable text [{default_choice}]: ").strip()
		or default_choice
	)
	formats = {"1": "json", "2": "csv", "3": "txt"}
	output_format = formats.get(choice)
	if output_format is None:
		raise ValueError("Choose JSON, CSV, or readable text (1, 2, or 3).")
	filename = input("Save to file? Enter a path, or leave blank to print: ").strip() or None
	display_report(report, filename, output_format, config)


def _interactive_scan(config: SentinelConfig) -> None:
	target = validate_ip_address(input("Enter the authorized target IP address: ").strip())
	print("\nPort selection:")
	print("1. Configured default ports")
	print("2. Ports 1-1024")
	print("3. Enter ports or ranges")
	choice = input("Choose an option: ").strip()
	if choice == "1":
		ports = config.default_ports
	elif choice == "2":
		ports = list(range(1, 1025))
	elif choice == "3":
		ports = parse_port_ranges(input("Ports (example: 22,80,8000-8010): "))
	else:
		raise ValueError("Choose 1, 2, or 3.")
	timeout_text = input(f"Connection timeout in seconds [{config.connection_timeout}]: ").strip()
	timeout = validate_timeout(timeout_text) if timeout_text else config.connection_timeout
	report = run_scan(target, config, ports=ports, timeout=timeout)
	_prompt_report_export(report, config)


def _safe_terminal_text(value: str) -> str:
	return "".join(
		character if character.isprintable() else f"\\u{ord(character):04x}"
		for character in value
	)


def _present_error(error: Exception) -> None:
	"""Log only the error category, then show the useful detail to the operator."""
	LOGGER.error("Operation failed (%s).", type(error).__name__)
	print(f"Error: {error}", file=sys.stderr)


def _interactive_wifi_router_audit(config: SentinelConfig) -> Optional[Dict[str, Any]]:
	access_points = discover_wifi_access_points()
	print("\nNearby Wi-Fi access points (discovery only; no network has been joined):")
	for index, access_point in enumerate(access_points, start=1):
		ssid = _safe_terminal_text(access_point.get("ssid") or "(hidden SSID)")
		bssid = _safe_terminal_text(access_point.get("bssid") or "(BSSID unavailable)")
		signal = _safe_terminal_text(access_point.get("signal", "unknown"))
		security = _safe_terminal_text(access_point.get("authentication", "unknown"))
		print(f"{index}. {ssid} | {bssid} | signal {signal} | {security}")
	selection = input("Choose an access point number, or press Enter to cancel: ").strip()
	if not selection:
		print("Wi-Fi selection cancelled.")
		return None
	if not selection.isdigit() or not 1 <= int(selection) <= len(access_points):
		raise ValueError("Choose one of the listed access point numbers.")
	selected = access_points[int(selection) - 1]
	print(
		"\nOnly continue if this is your router or you have explicit permission to assess it. "
		"Selecting a Wi-Fi name does not prove ownership or connect to that network."
	)
	require_authorization_confirmation(input('Type "I AM AUTHORIZED" to continue: '))
	target = input("Enter the authorized router's private IP address: ").strip()
	model = input("Router model (optional): ").strip() or None
	firmware = input("Firmware version (optional): ").strip() or None
	network = input("Authorized subnet in CIDR notation (optional): ").strip() or None
	report = run_router_audit(target, config, model, firmware, network)
	report["selected_wifi_access_point"] = {
		"ssid": selected.get("ssid") or None,
		"bssid": selected.get("bssid"),
		"signal": selected.get("signal"),
		"authentication": selected.get("authentication"),
	}
	return report


def interactive_menu(config: SentinelConfig) -> int:
	"""Run the interactive menu, returning to it after recoverable input errors."""
	print("+------------------------------------------+")
	print("|                 SENTINEL                 |")
	print("| Network Security Assessment Toolkit      |")
	print("+------------------------------------------+")
	print("Only assess systems and networks you own or have permission to test.")
	while True:
		print("\n1. Reconnaissance")
		print("2. Network Scan")
		print("3. Router Security Audit")
		print("4. Local Network Inventory")
		print("5. File Investigation")
		print("6. Generate Report")
		print("7. Settings")
		print("8. Exit")
		choice = input("Choose an option: ").strip()
		try:
			if choice == "1":
				target = input("Enter a URL, hostname, or public IP address: ").strip()
				_prompt_report_export(run_recon(target), config)
			elif choice == "2":
				_interactive_scan(config)
			elif choice == "3":
				mode = input("1. Enter router IP  2. Discover nearby Wi-Fi first [1]: ").strip() or "1"
				if mode == "1":
					_confirm_router_authorization()
					target = input("Enter the authorized router's private IP address: ").strip()
					model = input("Router model (optional): ").strip() or None
					firmware = input("Firmware version (optional): ").strip() or None
					network = input("Authorized subnet in CIDR notation (optional): ").strip() or None
					report = run_router_audit(target, config, model, firmware, network)
				elif mode == "2":
					report = _interactive_wifi_router_audit(config)
				else:
					raise ValueError("Choose 1 or 2.")
				if report is not None:
					_prompt_report_export(report, config)
			elif choice == "4":
				_prompt_report_export(run_inventory(), config)
			elif choice == "5":
				path = input("Enter the path to a local file: ").strip()
				_prompt_report_export(run_file_analysis(path), config)
			elif choice == "6":
				path = input("Enter the path to an existing SENTINEL JSON report: ").strip()
				_prompt_report_export(load_report(path), config)
			elif choice == "7":
				_print_settings(config)
			elif choice == "8":
				print("Goodbye.")
				return 0
			else:
				print("Choose a number from 1 to 8.")
		except (ValueError, RuntimeError, socket.gaierror, OSError) as exc:
			_present_error(exc)


def _legacy_action(args: argparse.Namespace, config: SentinelConfig) -> Optional[Dict[str, Any]]:
	if args.legacy_osint:
		return run_recon(args.legacy_osint)
	if args.legacy_extract:
		return run_file_analysis(args.legacy_extract)
	if args.legacy_router_audit:
		_confirm_router_authorization(getattr(args, "authorized", False))
		return run_router_audit(
			args.legacy_router_audit,
			config,
			args.legacy_model,
			args.legacy_firmware,
			args.legacy_network,
		)
	if args.legacy_inventory:
		return run_inventory()
	return None


def _dispatch(args: argparse.Namespace, config: SentinelConfig, parser: argparse.ArgumentParser) -> int:
	if args.command is None:
		legacy_selected = any((
			args.legacy_osint,
			args.legacy_extract,
			args.legacy_router_audit,
			args.legacy_inventory,
		))
		if legacy_selected:
			if (args.legacy_model or args.legacy_firmware or args.legacy_network) and not args.legacy_router_audit:
				parser.error("--model, --firmware, and --network require --router-audit.")
			report = _legacy_action(args, config)
			display_report(report, args.output, args.output_format, config)
			return 0
		if args.legacy_model or args.legacy_firmware or args.legacy_network:
			parser.error("--model, --firmware, and --network require --router-audit.")
		if args.output:
			parser.error("--output requires a report command.")
		return interactive_menu(config)

	if args.command in {"recon", "intel"}:
		report = run_recon(args.target)
	elif args.command == "cve":
		report = run_cve_lookup(
			args.query,
			vendor=args.vendor,
			product=args.product,
			version=args.version,
		)
	elif args.command == "scan":
		report = run_scan(
			args.target,
			config,
			ports=args.ports,
			timeout=args.timeout,
			concurrency=args.concurrency,
		)
	elif args.command == "router-audit":
		_confirm_router_authorization(getattr(args, "authorized", False))
		report = run_router_audit(args.target, config, args.model, args.firmware, args.network)
	elif args.command == "file":
		report = run_file_analysis(args.path)
	elif args.command == "assess":
		report = run_assessment(args.path, args.exposure)
	elif args.command == "inventory":
		report = run_inventory()
	elif args.command == "report":
		report = load_report(args.path)
	elif args.command == "settings":
		_print_settings(config)
		return 0
	else:
		parser.error(f"Unsupported command: {args.command}")
	display_report(report, args.output, args.output_format, config)
	return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
	"""Run the CLI and return a stable process exit code."""
	parser = build_parser()
	try:
		args = parser.parse_args(argv)
	except SystemExit as exc:
		return int(exc.code or 0)

	try:
		config = load_config(args.config, _configuration_overrides(args))
	except ConfigurationError as exc:
		print(f"Configuration error: {exc}", file=sys.stderr)
		return 3
	configure_logging(config.log_level)

	try:
		try:
			return _dispatch(args, config, parser)
		except SystemExit as exc:
			return int(exc.code or 0)
	except EOFError:
		_present_error(ValueError("Authorization confirmation is required; use --authorized only when permitted."))
		return 3
	except (ValueError, FileNotFoundError, PermissionError, socket.gaierror) as exc:
		_present_error(exc)
		return 3
	except (RuntimeError, OSError) as exc:
		_present_error(exc)
		return 1
	except KeyboardInterrupt:
		LOGGER.warning("Interrupted.")
		return 130


if __name__ == "__main__":
	raise SystemExit(main())
