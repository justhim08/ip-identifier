"""Read nearby Wi-Fi access-point advertisements on Windows."""

import platform
import re
import subprocess


def parse_windows_networks(output):
	"""Parse access-point details from `netsh wlan show networks mode=bssid`."""
	networks = []
	current_network = None
	current_access_point = None
	detail_labels = {
		"signal": "signal",
		"radio type": "radio_type",
		"channel": "channel",
		"authentication": "authentication",
		"encryption": "encryption",
	}

	def finish_access_point():
		if current_network is None:
			return
		if current_access_point is None and current_network.get("has_access_points"):
			return
		entry = {"ssid": current_network["ssid"], **current_network["details"]}
		if current_access_point is not None:
			entry.update(current_access_point)
		networks.append(entry)

	for line in output.splitlines():
		match = re.match(r"^\s*SSID\s+\d+\s*:\s*(.*)$", line, re.IGNORECASE)
		if match:
			finish_access_point()
			current_network = {"ssid": match.group(1).strip(), "details": {}, "has_access_points": False}
			current_access_point = None
			continue

		match = re.match(r"^\s*BSSID\s+\d+\s*:\s*(.*)$", line, re.IGNORECASE)
		if match:
			if current_network is not None:
				current_network["has_access_points"] = True
			finish_access_point()
			if current_network is not None:
				current_access_point = {"bssid": match.group(1).strip()}
			continue

		if current_network is None:
			continue
		match = re.match(r"^\s*([^:]+?)\s*:\s*(.*?)\s*$", line)
		if not match:
			continue
		label, value = match.group(1).strip().lower(), match.group(2).strip()
		key = detail_labels.get(label)
		if key and value:
			details = current_access_point if current_access_point is not None else current_network["details"]
			details[key] = value

	finish_access_point()
	return networks


def discover_wifi_access_points():
	"""List visible Wi-Fi access points using Windows' built-in WLAN command."""
	if platform.system() != "Windows":
		raise RuntimeError("Nearby Wi-Fi discovery currently requires Windows and its built-in netsh command.")

	try:
		result = subprocess.run(
			["netsh", "wlan", "show", "networks", "mode=bssid"],
			capture_output=True,
			text=True,
			errors="replace",
			timeout=20,
			check=False,
		)
	except (OSError, subprocess.TimeoutExpired) as exc:
		raise RuntimeError(f"Could not query nearby Wi-Fi networks: {exc}") from exc
	if result.returncode != 0:
		message = result.stderr.strip() or result.stdout.strip() or "netsh returned an error."
		raise RuntimeError(f"Wi-Fi discovery failed: {message}")

	access_points = parse_windows_networks(result.stdout)
	if not access_points:
		raise RuntimeError(
			"No nearby Wi-Fi access points were reported. Check that a wireless adapter is enabled "
			"and that Windows WLAN AutoConfig is running."
		)
	return access_points


def require_authorization_confirmation(value):
	"""Reject a Wi-Fi audit unless the operator explicitly confirms authorization."""
	if value.strip() != "I AM AUTHORIZED":
		raise ValueError("Wi-Fi router audit cancelled; authorization confirmation was not provided.")
