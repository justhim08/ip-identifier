"""Read local routing and neighbor caches without sending network probes."""

import ipaddress
import platform
import re
import subprocess


MAC_PATTERN = re.compile(r"(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}")


def _interface_entry(name):
	return {"name": name, "addresses": [], "mac": None, "vendor": None}


def _add_interface_address(interface, value, netmask=None):
	try:
		ip_interface = ipaddress.ip_interface(value.split("%", maxsplit=1)[0])
	except ValueError:
		return
	if ip_interface.network.prefixlen == ip_interface.max_prefixlen and netmask:
		try:
			ip_interface = ipaddress.ip_interface(f"{ip_interface.ip}/{netmask}")
		except ValueError:
			pass
	address = str(ip_interface.ip)
	entry = {
		"address": address,
		"ip_version": ip_interface.version,
		"network": str(ip_interface.network),
	}
	if entry not in interface["addresses"]:
		interface["addresses"].append(entry)


def _parse_linux_interfaces(output):
	interfaces = {}
	for line in output.splitlines():
		match = re.match(r"^\d+:\s+(\S+)\s+(.*)$", line)
		if not match:
			continue
		name, details = match.groups()
		interface = interfaces.setdefault(name, _interface_entry(name))
		link_match = re.search(r"\blink/ether\s+([0-9a-f:]{17})", details, re.I)
		if link_match:
			interface["mac"] = link_match.group(1).lower()
		address_match = re.search(r"\b(inet6?)\s+([0-9a-f:.%/]+)", details, re.I)
		if address_match:
			kind, address = address_match.groups()
			if "/" in address:
				_add_interface_address(interface, address)
			elif kind.lower() == "inet":
				_add_interface_address(interface, address, "32")
			else:
				_add_interface_address(interface, address, "128")
	return list(interfaces.values())


def _parse_windows_interfaces(output):
	interfaces = []
	for block in re.split(r"\r?\n\s*\r?\n", output):
		header = re.search(r"(?m)^(.+ adapter .+):\s*$", block)
		if not header:
			continue
		name = header.group(1).strip()
		interface = _interface_entry(name)
		mac_match = re.search(r"(?im)^\s*Physical Address[^:]*:\s*([0-9a-f:-]{12,17})", block)
		if mac_match:
			interface["mac"] = mac_match.group(1).replace("-", ":").lower()
		mask_match = re.search(r"(?im)^\s*Subnet Mask[^:]*:\s*([\d.]+)", block)
		subnet_mask = mask_match.group(1) if mask_match else None
		for address_match in re.finditer(
			r"(?im)^\s*(?:IPv4 Address|IPv6 Address|Temporary IPv6 Address|Link-local IPv6 Address)[^:]*:\s*([0-9a-f:.%]+)",
			block,
		):
			_add_interface_address(interface, address_match.group(1), subnet_mask)
		if interface["addresses"] or interface["mac"]:
			interfaces.append(interface)
	return interfaces


def _parse_macos_interfaces(output):
	interfaces = []
	current = None
	for line in output.splitlines():
		header = re.match(r"^([A-Za-z0-9_.-]+):\s+flags=", line)
		if header:
			if current is not None:
				interfaces.append(current)
			current = _interface_entry(header.group(1))
			continue
		if current is None:
			continue
		mac_match = re.search(r"\bether\s+([0-9a-f:]{17})", line, re.I)
		if mac_match:
			current["mac"] = mac_match.group(1).lower()
		ipv4_match = re.search(r"\binet\s+([\d.]+).*\bnetmask\s+(0x[0-9a-f]+|[\d.]+)", line, re.I)
		if ipv4_match:
			address, mask = ipv4_match.groups()
			if mask.startswith("0x"):
				try:
					prefix = bin(int(mask, 16)).count("1")
					mask = str(ipaddress.ip_network(f"0.0.0.0/{prefix}").netmask)
				except ValueError:
					mask = None
			_add_interface_address(current, address, mask)
		ipv6_match = re.search(r"\binet6\s+([0-9a-f:]+)(?:%[^\s]+)?.*?\bprefixlen\s+(\d+)", line, re.I)
		if ipv6_match:
			_add_interface_address(current, f"{ipv6_match.group(1)}/{ipv6_match.group(2)}")
	if current is not None:
		interfaces.append(current)
	return [interface for interface in interfaces if interface["addresses"] or interface["mac"]]


def _run(command):
	try:
		result = subprocess.run(
			command,
			capture_output=True,
			text=True,
			errors="replace",
			timeout=10,
			check=False,
		)
	except (OSError, subprocess.TimeoutExpired) as exc:
		raise RuntimeError(f"Could not read local network information using {command[0]}: {exc}") from exc
	if result.returncode != 0:
		detail = result.stderr.strip() or result.stdout.strip() or "command failed"
		raise RuntimeError(f"Could not read local network information using {command[0]}: {detail}")
	return result.stdout


def _parse_neighbors(output):
	neighbors = {}
	for line in output.splitlines():
		candidates = re.findall(
			r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])"
			r"|(?<![\w:])(?:[0-9a-f]{0,4}:){2,}[0-9a-f:.]+",
			line,
			re.IGNORECASE,
		)
		address_info = None
		for candidate in candidates:
			try:
				address_info = (candidate, ipaddress.ip_address(candidate))
				break
			except ValueError:
				continue
		if address_info is None:
			continue
		address, ip = address_info
		mac_match = MAC_PATTERN.search(line)
		mac = mac_match.group().replace("-", ":").lower() if mac_match else None
		state_match = re.search(r"\b(dynamic|static|reachable|stale|delay|probe|permanent|incomplete|failed)\b", line, re.I)
		neighbors[address] = {
			"ip": address,
			"ip_version": ip.version,
			"mac": mac,
			"state": state_match.group().lower() if state_match else "unknown",
		}
	return [
		neighbors[address]
		for address in sorted(neighbors, key=lambda item: (ipaddress.ip_address(item).version, int(ipaddress.ip_address(item))))
	]


def _windows_inventory():
	routes = _run(["route", "print", "-4"])
	ipv4_neighbors = _run(["arp", "-a"])
	ipv6_neighbors = _run(["netsh", "interface", "ipv6", "show", "neighbors"])
	gateway_match = re.search(
		r"(?m)^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})\s+",
		routes,
	)
	neighbors = _parse_neighbors(ipv4_neighbors + "\n" + ipv6_neighbors)
	return (
		gateway_match.group(1) if gateway_match else None,
		neighbors,
		gateway_match.group(2) if gateway_match else None,
	)


def _linux_inventory():
	routes = _run(["ip", "route", "show", "default"])
	neighbors = _run(["ip", "neigh", "show"])
	gateway_match = re.search(r"(?m)^default\s+via\s+(\S+)", routes)
	interface_match = re.search(r"(?m)^default\b.*?\bdev\s+(\S+)", routes)
	return (
		gateway_match.group(1) if gateway_match else None,
		_parse_neighbors(neighbors),
		interface_match.group(1) if interface_match else None,
	)


def _macos_inventory():
	routes = _run(["route", "-n", "get", "default"])
	ipv4_neighbors = _run(["arp", "-an"])
	ipv6_neighbors = _run(["ndp", "-an"])
	gateway_match = re.search(r"(?m)^\s*gateway:\s*(\S+)", routes)
	interface_match = re.search(r"(?m)^\s*interface:\s*(\S+)", routes)
	return (
		gateway_match.group(1) if gateway_match else None,
		_parse_neighbors(ipv4_neighbors + "\n" + ipv6_neighbors),
		interface_match.group(1) if interface_match else None,
	)


def _get_local_interfaces(system):
	"""Read interface details with platform-native commands; never probe the network."""
	if system == "Windows":
		return _parse_windows_interfaces(_run(["ipconfig", "/all"]))
	if system == "Linux":
		interfaces = _parse_linux_interfaces(_run(["ip", "-o", "addr", "show"]))
		link_output = _run(["ip", "-o", "link", "show"])
		mac_by_name = {}
		for line in link_output.splitlines():
			match = re.match(r"^\d+:\s+([^:]+):.*?\blink/ether\s+([0-9a-f:]{17})", line, re.I)
			if match:
				mac_by_name[match.group(1)] = match.group(2).lower()
		for interface in interfaces:
			interface["mac"] = mac_by_name.get(interface["name"])
		return interfaces
	if system == "Darwin":
		return _parse_macos_interfaces(_run(["ifconfig"]))
	return []


def collect_local_inventory():
	"""Report cached local neighbors and default gateway; never performs discovery probes."""
	system = platform.system()
	collectors = {
		"Windows": _windows_inventory,
		"Linux": _linux_inventory,
		"Darwin": _macos_inventory,
	}
	collector = collectors.get(system)
	if collector is None:
		raise RuntimeError(f"Local network inventory is not supported on {system}.")
	inventory = collector()
	gateway, neighbors = inventory[:2]
	gateway_interface = inventory[2] if len(inventory) > 2 else None
	interface_error = None
	try:
		interfaces = _get_local_interfaces(system)
	except RuntimeError as exc:
		interfaces = []
		interface_error = str(exc)
	for interface in interfaces:
		interface["addresses"].sort(key=lambda item: (item["ip_version"], item["address"]))
	if system == "Windows" and gateway_interface:
		gateway_address = gateway_interface
		gateway_interface = next(
			(
				interface["name"]
				for interface in interfaces
				if any(address["address"] == gateway_address for address in interface["addresses"])
			),
			gateway_address,
		)
	for neighbor in neighbors:
		neighbor["vendor"] = None
		neighbor["vendor_status"] = "not_available_without_local_OUI_database"
	gateway_network = None
	if gateway:
		try:
			gateway_address = ipaddress.ip_address(gateway)
			for interface in interfaces:
				if gateway_interface and interface["name"] != gateway_interface:
					continue
				gateway_network = next(
					(
						address["network"]
						for address in interface["addresses"]
						if gateway_address in ipaddress.ip_network(address["network"])
					),
					None,
				)
				if gateway_network:
					break
		except ValueError:
			gateway_network = None
	return {
		"platform": system,
		"default_gateway": gateway,
		"default_gateway_interface": gateway_interface,
		"default_gateway_network": gateway_network,
		"interfaces": interfaces,
		"interfaces_status": "available" if interfaces else "unavailable_or_no_configured_addresses",
		"interfaces_error": interface_error,
		"neighbors": neighbors,
		"neighbor_snapshot_type": "CACHED LOCAL NEIGHBOR SNAPSHOT",
		"vendor_information": "Unavailable without a local OUI database; no external vendor lookup was performed.",
		"scope": (
			"CACHED LOCAL NEIGHBOR SNAPSHOT: entries already present in the operating system cache, "
			"not a complete list of network devices. Interface addresses are read from local system "
			"configuration. No subnet sweep, active discovery probe, or port scan was performed."
		),
	}
