"""Resolve a URL to IP addresses and scan TCP ports on one host."""

import csv
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit


COMMON_PORTS = {
	20: "FTP-data",
	21: "FTP",
	22: "SSH",
	23: "Telnet",
	25: "SMTP",
	53: "DNS",
	80: "HTTP",
	110: "POP3",
	143: "IMAP",
	443: "HTTPS",
	445: "SMB",
	587: "SMTP-submission",
	993: "IMAPS",
	995: "POP3S",
	1433: "MS-SQL",
	3306: "MySQL",
	3389: "RDP",
	5432: "PostgreSQL",
	8080: "HTTP-alt",
	8443: "HTTPS-alt",
}
MAX_WORKERS = 100


def normalize_host(value):
	"""Accept a URL, hostname, or IP address and return its host component."""
	value = value.strip()
	if not value:
		raise ValueError("Please enter a URL, hostname, or IP address.")

	try:
		return str(ipaddress.ip_address(value))
	except ValueError:
		pass

	parsed = urlsplit(value if "://" in value else f"//{value}")
	host = parsed.hostname
	if not host:
		raise ValueError("That input does not contain a valid hostname or IP address.")
	return host


def resolve_host(host):
	"""Return unique IP addresses resolved for a hostname or IP literal."""
	try:
		literal = ipaddress.ip_address(host)
		return [str(literal)]
	except ValueError:
		results = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
		addresses = list(dict.fromkeys(result[4][0] for result in results))
		if not addresses:
			raise socket.gaierror(f"No IP addresses found for {host}")
		return addresses


def parse_ports(value):
	"""Parse comma-separated ports and ranges, such as 22,80,8000-8010."""
	ports = set()
	try:
		for item in value.split(","):
			item = item.strip()
			if not item:
				raise ValueError
			if "-" in item:
				start_text, end_text = item.split("-", maxsplit=1)
				start, end = int(start_text), int(end_text)
				if start > end:
					raise ValueError
				ports.update(range(start, end + 1))
			else:
				ports.add(int(item))
	except ValueError as exc:
		raise ValueError("Use port numbers and ranges like 22,80,8000-8010.") from exc

	if not ports or min(ports) < 1 or max(ports) > 65535:
		raise ValueError("Ports must be between 1 and 65535.")
	return sorted(ports)


def scan_port(address, port, timeout):
	"""Try one TCP connection and classify the result."""
	family = socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET
	target = (address, port, 0, 0) if family == socket.AF_INET6 else (address, port)
	try:
		with socket.socket(family, socket.SOCK_STREAM) as connection:
			connection.settimeout(timeout)
			connection.connect(target)
		status = "open"
	except ConnectionRefusedError:
		status = "closed"
	except (TimeoutError, socket.timeout):
		status = "filtered/no response"
	except OSError:
		status = "filtered/no response"
	return port, status


def ask_timeout():
	value = input("Connection timeout in seconds [0.5]: ").strip()
	if not value:
		return 0.5
	try:
		timeout = float(value)
	except ValueError as exc:
		raise ValueError("Timeout must be a number between 0.1 and 5 seconds.") from exc
	if not 0.1 <= timeout <= 5:
		raise ValueError("Timeout must be between 0.1 and 5 seconds.")
	return timeout


def choose_ports():
	print("\nPort selection:")
	print("1. Common ports")
	print("2. Ports 1-1024")
	print("3. Enter ports or ranges")
	choice = input("Choose an option: ").strip()
	if choice == "1":
		return sorted(COMMON_PORTS)
	if choice == "2":
		return list(range(1, 1025))
	if choice == "3":
		return parse_ports(input("Ports (example: 22,80,8000-8010): "))
	raise ValueError("Choose 1, 2, or 3.")


def save_results(address, results):
	choice = input("Save results as CSV? [y/N]: ").strip().lower()
	if choice not in {"y", "yes"}:
		return

	default_name = f"port_scan_{datetime.now():%Y%m%d_%H%M%S}.csv"
	filename = input(f"File name [{default_name}]: ").strip() or default_name
	path = Path(filename)
	with path.open("w", newline="", encoding="utf-8") as csv_file:
		writer = csv.writer(csv_file)
		writer.writerow(["IP address", "Port", "Service", "Status"])
		for port, status in results:
			writer.writerow([address, port, COMMON_PORTS.get(port, ""), status])
	print(f"Saved results to {path.resolve()}")


def scan_address(address):
	ports = choose_ports()
	timeout = ask_timeout()
	print(f"\nScanning {address} ({len(ports)} TCP ports)...")

	results = []
	with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
		futures = [executor.submit(scan_port, address, port, timeout) for port in ports]
		for future in as_completed(futures):
			results.append(future.result())
	results.sort()

	for port, status in results:
		service = COMMON_PORTS.get(port, "")
		label = f" ({service})" if service else ""
		print(f"{port:5}{label:20} {status}")

	counts = {status: sum(result == status for _, result in results)
			  for status in ("open", "closed", "filtered/no response")}
	print("\nSummary: " + ", ".join(f"{status}: {count}" for status, count in counts.items()))
	save_results(address, results)


def get_host_from_prompt():
	return normalize_host(input("Enter a URL, hostname, or IP address: "))


def main():
	print("IP Finder and TCP Port Scanner")
	print("Only scan systems you own or have permission to test.\n")

	while True:
		print("\nMenu:")
		print("1. Resolve a URL/hostname to IP addresses")
		print("2. Scan TCP ports on an IP address")
		print("3. Resolve a URL, then scan a selected IP")
		print("4. Exit")
		choice = input("Choose an option: ").strip()

		try:
			if choice == "1":
				host = get_host_from_prompt()
				for address in resolve_host(host):
					print(f"{host} -> {address}")
			elif choice == "2":
				host = get_host_from_prompt()
				try:
					address = str(ipaddress.ip_address(host))
				except ValueError as exc:
					raise ValueError("Option 2 requires an IP address. Use option 3 for a URL or hostname.") from exc
				scan_address(address)
			elif choice == "3":
				host = get_host_from_prompt()
				addresses = resolve_host(host)
				print("\nResolved addresses:")
				for index, address in enumerate(addresses, start=1):
					print(f"{index}. {address}")
				selection = input("Scan which address? [1]: ").strip() or "1"
				if not selection.isdigit() or not 1 <= int(selection) <= len(addresses):
					raise ValueError("Choose one of the listed address numbers.")
				scan_address(addresses[int(selection) - 1])
			elif choice == "4":
				print("Goodbye.")
				return
			else:
				print("Choose 1, 2, 3, or 4.")
		except (ValueError, socket.gaierror, OSError) as error:
			print(f"Error: {error}")


if __name__ == "__main__":
	main()
