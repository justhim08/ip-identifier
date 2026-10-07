import contextlib
import io
import logging
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel.cli import main
from sentinel.config import (
	DEFAULT_CONFIG,
	DEFAULT_CONCURRENCY,
	DEFAULT_PORTS,
	DEFAULT_TIMEOUT,
	ConfigurationError,
	LOG_LEVEL,
	REPORT_DIRECTORY,
	load_config,
)
from sentinel.logging_config import configure_logging
from sentinel.network.assessment import assess_tcp_services
from sentinel.validation import (
	parse_port_ranges,
	validate_concurrency,
	validate_file_path,
	validate_hostname,
	validate_ip_address,
	validate_port,
	validate_target,
	validate_timeout,
)


class ValidationTests(unittest.TestCase):
	def test_validates_ipv4_and_ipv6(self):
		self.assertEqual(validate_ip_address("192.168.1.1"), "192.168.1.1")
		self.assertEqual(validate_ip_address("2001:4860:4860::8888"), "2001:4860:4860::8888")

	def test_rejects_invalid_ip_with_clear_message(self):
		with self.assertRaisesRegex(ValueError, "Invalid IP address: not-an-ip"):
			validate_ip_address("not-an-ip")

	def test_validates_hostnames_and_url_targets(self):
		self.assertEqual(validate_hostname("Example.COM."), "example.com")
		self.assertEqual(validate_target("https://Example.COM/path"), "example.com")
		self.assertEqual(validate_target("https://[2001:4860:4860::8888]/"), "2001:4860:4860::8888")
		self.assertEqual(validate_target("2001:4860:4860::8888"), "2001:4860:4860::8888")

	def test_rejects_malformed_hostnames_and_numeric_ip_like_targets(self):
		with self.assertRaisesRegex(ValueError, "Invalid hostname"):
			validate_hostname("bad..example.com")
		with self.assertRaisesRegex(ValueError, "Invalid IP address"):
			validate_target("999.1.1.1")
		with self.assertRaisesRegex(ValueError, "Do not include credentials"):
			validate_target("https://analyst:secret@example.com")

	def test_validates_port_values_and_ranges(self):
		self.assertEqual(validate_port("443"), 443)
		self.assertEqual(parse_port_ranges("22,80,8000-8002"), [22, 80, 8000, 8001, 8002])
		with self.assertRaisesRegex(ValueError, "Port must be between 1 and 65535"):
			validate_port(65536)
		with self.assertRaisesRegex(ValueError, "start must not exceed"):
			parse_port_ranges("80-22")
		with self.assertRaises(ValueError):
			parse_port_ranges("22,,80")

	def test_validates_scan_limits(self):
		self.assertEqual(validate_timeout("3"), 3.0)
		self.assertEqual(validate_concurrency("25"), 25)
		with self.assertRaisesRegex(ValueError, "between 0.1 and 5"):
			validate_timeout(6)
		with self.assertRaisesRegex(ValueError, "between 1 and 100"):
			validate_concurrency(101)

	def test_validates_existing_regular_file(self):
		with tempfile.TemporaryDirectory() as directory:
			path = Path(directory) / "sample.txt"
			path.write_text("local test", encoding="utf-8")
			self.assertEqual(validate_file_path(path), path)
			with self.assertRaisesRegex(ValueError, "File does not exist"):
				validate_file_path(Path(directory) / "missing.txt")
			with self.assertRaisesRegex(ValueError, "Path is not a file"):
				validate_file_path(directory)


class ConfigurationTests(unittest.TestCase):
	def test_defaults_are_validated_and_preserve_phase_one_values(self):
		self.assertEqual(DEFAULT_CONFIG.connection_timeout, DEFAULT_TIMEOUT)
		self.assertEqual(DEFAULT_CONFIG.scanner_concurrency, DEFAULT_CONCURRENCY)
		self.assertEqual(DEFAULT_CONFIG.default_ports, DEFAULT_PORTS)
		self.assertEqual(DEFAULT_CONFIG.report_directory, REPORT_DIRECTORY)
		self.assertEqual(DEFAULT_CONFIG.log_level, LOG_LEVEL)

	def test_loads_toml_then_applies_cli_overrides(self):
		with tempfile.TemporaryDirectory() as directory:
			root = Path(directory)
			config_path = root / "sentinel.toml"
			config_path.write_text(
				"[scanner]\ntimeout = 2.0\nconcurrency = 25\nports = [22, 80, 443]\n"
				"[reports]\ndirectory = \"reports\"\nformat = \"csv\"\n"
				"[logging]\nlevel = \"DEBUG\"\n",
				encoding="utf-8",
			)
			config = load_config(
				str(config_path),
				{
					"timeout": 3.0,
					"concurrency": 10,
					"ports": "443,8443",
					"report_directory": root / "cli-reports",
					"log_level": "ERROR",
					"output_format": "text",
				},
			)

		self.assertEqual(config.connection_timeout, 3.0)
		self.assertEqual(config.scanner_concurrency, 10)
		self.assertEqual(config.default_ports, (443, 8443))
		self.assertEqual(config.report_directory, root / "cli-reports")
		self.assertEqual(config.log_level, "ERROR")
		self.assertEqual(config.output_format, "txt")

	def test_config_relative_report_directory_is_relative_to_config_file(self):
		with tempfile.TemporaryDirectory() as directory:
			config_path = Path(directory) / "sentinel.toml"
			config_path.write_text("[reports]\ndirectory = \"reports\"\n", encoding="utf-8")
			config = load_config(str(config_path))

		self.assertEqual(config.report_directory, Path(directory) / "reports")

	def test_load_config_without_file_and_validates_cli_only_overrides(self):
		config = load_config(cli_overrides={"timeout": "1.25", "ports": [80, 443]})
		self.assertEqual(config.connection_timeout, 1.25)
		self.assertEqual(config.default_ports, (80, 443))
		with self.assertRaisesRegex(ConfigurationError, "Concurrency must be between 1 and 100"):
			load_config(cli_overrides={"concurrency": 101})

	def test_rejects_missing_or_invalid_config_files(self):
		with tempfile.TemporaryDirectory() as directory:
			missing = Path(directory) / "missing.toml"
			with self.assertRaisesRegex(ConfigurationError, "does not exist"):
				load_config(str(missing))
			invalid = Path(directory) / "invalid.toml"
			invalid.write_text("[scanner]\nconcurrency = 101\n", encoding="utf-8")
			with self.assertRaisesRegex(ConfigurationError, "Concurrency must be between 1 and 100"):
				load_config(str(invalid))

	def test_cli_reports_missing_configuration_as_exit_code_three(self):
		with tempfile.TemporaryDirectory() as directory:
			missing = Path(directory) / "missing.toml"
			with contextlib.redirect_stderr(io.StringIO()) as stderr:
				status = main(["settings", "--config", str(missing)])
		self.assertEqual(status, 3)
		self.assertIn("Configuration error", stderr.getvalue())

	def test_rejects_unknown_configuration_keys(self):
		with tempfile.TemporaryDirectory() as directory:
			config_path = Path(directory) / "sentinel.toml"
			config_path.write_text("[scanner]\nworkers = 3\n", encoding="utf-8")
			with self.assertRaisesRegex(ConfigurationError, "Unknown key"):
				load_config(str(config_path))


class LoggingTests(unittest.TestCase):
	def test_configures_supported_log_level_and_format(self):
		with patch("sentinel.logging_config.logging.basicConfig") as basic_config:
			configure_logging("debug")
		self.assertEqual(basic_config.call_args.kwargs["level"], 10)
		self.assertEqual(basic_config.call_args.kwargs["format"], "[%(levelname)s] %(message)s")

	def test_configures_all_supported_levels(self):
		with patch("sentinel.logging_config.logging.basicConfig") as basic_config:
			for name in ("DEBUG", "INFO", "WARNING", "ERROR"):
				configure_logging(name)
				self.assertEqual(basic_config.call_args.kwargs["level"], getattr(logging, name))

	def test_rejects_unsupported_log_level(self):
		with self.assertRaisesRegex(ValueError, "Log level must be"):
			configure_logging("TRACE")


class AssessmentTests(unittest.TestCase):
	def test_assessment_delegates_scanning_and_service_identification(self):
		with patch("sentinel.network.assessment.scan_ports", return_value=[(80, "OPEN"), (443, "CLOSED")]) as scan:
			with patch(
				"sentinel.network.assessment.identify_service",
				side_effect=[
					{"name": "HTTP"},
					{"name": "HTTPS"},
				],
			) as identify:
				report = assess_tcp_services("192.168.1.1", [80, 443], 1.5, 10)
		scan.assert_called_once_with("192.168.1.1", [80, 443], timeout=1.5, max_workers=10)
		self.assertEqual(identify.call_count, 2)
		self.assertEqual(
			report["summary"],
			{"OPEN": 1, "CLOSED": 1, "FILTERED": 0, "TIMEOUT": 0, "ERROR": 0},
		)
		self.assertEqual(report["ports"][0]["service"]["name"], "HTTP")


class CliTests(unittest.TestCase):
	def test_help_lists_supported_commands(self):
		output = io.StringIO()
		with contextlib.redirect_stdout(output):
			status = main(["--help"])
		self.assertEqual(status, 0)
		self.assertIn("SENTINEL", output.getvalue())
		self.assertIn("router-audit", output.getvalue())
		self.assertIn("Examples (use scan only for authorized targets)", output.getvalue())

	def test_invalid_arguments_return_exit_code_two(self):
		with contextlib.redirect_stderr(io.StringIO()):
			self.assertEqual(main(["scan"]), 2)
			self.assertEqual(main(["scan", "192.168.1.1", "--ports", "0"]), 2)
			self.assertEqual(main(["unknown-command"]), 2)

	def test_invalid_target_returns_exit_code_three_without_traceback(self):
		stderr = io.StringIO()
		with contextlib.redirect_stderr(stderr):
			status = main(["scan", "not-an-ip"])
		self.assertEqual(status, 3)
		self.assertIn("Invalid IP address", stderr.getvalue())
		self.assertNotIn("Traceback", stderr.getvalue())

	def test_credentials_in_target_url_are_neither_accepted_nor_logged(self):
		stderr = io.StringIO()
		with patch("sentinel.cli.LOGGER.error") as log_error:
			with contextlib.redirect_stderr(stderr):
				status = main(["recon", "https://analyst:secret@example.com"])
		self.assertEqual(status, 3)
		self.assertNotIn("secret", stderr.getvalue())
		self.assertNotIn("secret", str(log_error.call_args))

	def test_invalid_file_path_returns_exit_code_three(self):
		with tempfile.TemporaryDirectory() as directory:
			missing_path = Path(directory) / "missing.pdf"
			with contextlib.redirect_stderr(io.StringIO()) as stderr:
				status = main(["file", str(missing_path)])
		self.assertEqual(status, 3)
		self.assertIn("File does not exist", stderr.getvalue())

	def test_scan_command_uses_configuration_and_cli_overrides(self):
		with tempfile.TemporaryDirectory() as directory:
			config_path = Path(directory) / "sentinel.toml"
			config_path.write_text(
				"[scanner]\ntimeout = 1.5\nconcurrency = 20\nports = [22, 80]\n",
				encoding="utf-8",
			)
			with patch("sentinel.cli.run_scan", return_value={"target": "192.168.1.1"}) as run_scan:
				with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
					status = main([
						"scan",
						"192.168.1.1",
						"--config",
						str(config_path),
						"--timeout",
						"3",
						"--concurrency",
						"12",
						"--ports",
						"443,8443",
						"--output-format",
						"text",
					])

		self.assertEqual(status, 0)
		configuration = run_scan.call_args.args[1]
		self.assertEqual(configuration.connection_timeout, 3.0)
		self.assertEqual(configuration.scanner_concurrency, 12)
		self.assertEqual(configuration.default_ports, (443, 8443))
		self.assertEqual(configuration.output_format, "txt")

	def test_configuration_override_before_command_is_preserved(self):
		with patch("sentinel.cli.run_scan", return_value={"target": "192.168.1.1"}) as run_scan:
			with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
				status = main(["--timeout", "2", "scan", "192.168.1.1", "--ports", "22"])
		self.assertEqual(status, 0)
		self.assertEqual(run_scan.call_args.args[1].connection_timeout, 2.0)

	def test_router_command_passes_configured_timeout_to_audit(self):
		from sentinel.cli import run_router_audit

		config = load_config(cli_overrides={"timeout": 2.5})
		with patch("sentinel.cli.audit_router", return_value={"target": "192.168.1.1"}) as audit:
			run_router_audit("192.168.1.1", config)
		self.assertEqual(audit.call_args.kwargs["timeout"], 2.5)

	def test_output_directory_override_saves_a_rendered_report(self):
		with tempfile.TemporaryDirectory() as directory:
			output_directory = Path(directory) / "reports"
			with patch("sentinel.cli.run_recon", return_value={"target": "example.com"}):
				with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
					status = main([
						"recon",
						"example.com",
						"--report-directory",
						directory,
						"--output",
						"reports/",
					])
			files = list(output_directory.glob("sentinel_report_*.json"))
			self.assertEqual(status, 0)
			self.assertEqual(len(files), 1)
			self.assertIn('"target": "example.com"', files[0].read_text(encoding="utf-8"))

	def test_settings_command_reports_effective_values(self):
		output = io.StringIO()
		with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
			status = main(["settings", "--timeout", "2", "--concurrency", "25"])
		self.assertEqual(status, 0)
		self.assertIn("Timeout:       2.0s", output.getvalue())
		self.assertIn("Concurrency:   25", output.getvalue())
		self.assertIn("Log level:     INFO", output.getvalue())

	def test_recon_command_uses_shared_workflow_without_network_in_test(self):
		with patch("sentinel.cli.run_recon", return_value={"target": "example.com"}) as run_recon:
			with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
				status = main(["recon", "example.com"])
		self.assertEqual(status, 0)
		run_recon.assert_called_once_with("example.com")

	def test_router_file_inventory_and_report_commands_dispatch(self):
		with tempfile.TemporaryDirectory() as directory:
			input_file = Path(directory) / "sample.pdf"
			input_file.write_bytes(b"local fixture")
			report_file = Path(directory) / "input.json"
			report_file.write_text('{"status": "complete"}', encoding="utf-8")
			tests = (
				(
					["router-audit", "192.168.1.1", "--authorized"],
					"sentinel.cli.run_router_audit",
					{"target": "192.168.1.1"},
				),
				(["file", str(input_file)], "sentinel.cli.run_file_analysis", {"file": "sample.pdf"}),
				(["inventory"], "sentinel.cli.run_inventory", {"gateway": None}),
			)
			for arguments, patched_function, result in tests:
				with self.subTest(command=arguments[0]):
					with patch(patched_function, return_value=result) as handler:
						with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
							self.assertEqual(main(arguments), 0)
					handler.assert_called_once()

			with contextlib.redirect_stdout(io.StringIO()) as output:
				self.assertEqual(main(["report", str(report_file), "--output-format", "text"]), 0)
		self.assertIn("Status", output.getvalue())

	def test_legacy_option_mode_remains_available(self):
		with patch("sentinel.cli.run_recon", return_value={"target": "example.com"}) as run_recon:
			with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
				status = main(["--osint", "example.com"])
		self.assertEqual(status, 0)
		run_recon.assert_called_once_with("example.com")

	def test_runtime_failure_returns_exit_code_one(self):
		with patch("sentinel.cli.run_recon", side_effect=RuntimeError("source unavailable")):
			with contextlib.redirect_stderr(io.StringIO()):
				self.assertEqual(main(["recon", "example.com"]), 1)

	def test_command_line_log_level_is_applied(self):
		with patch("sentinel.cli.configure_logging") as configure:
			with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
				self.assertEqual(main(["settings", "--log-level", "ERROR"]), 0)
		configure.assert_called_once_with("ERROR")

	def test_no_command_starts_interactive_mode(self):
		with patch("sentinel.cli.interactive_menu", return_value=0) as menu:
			with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
				self.assertEqual(main([]), 0)
		menu.assert_called_once()

	def test_interactive_menu_exits_cleanly_after_a_valid_choice(self):
		from sentinel.cli import interactive_menu

		with patch("builtins.input", return_value="8"):
			with contextlib.redirect_stdout(io.StringIO()) as output:
				self.assertEqual(interactive_menu(DEFAULT_CONFIG), 0)
		self.assertIn("SENTINEL", output.getvalue())
		self.assertIn("Goodbye.", output.getvalue())


if __name__ == "__main__":
	unittest.main()
