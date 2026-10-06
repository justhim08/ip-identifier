# IP Finder, Passive OSINT, and File Extractor

A Python command-line utility for resolving hosts, collecting passive public-source information about domains and IP addresses, extracting text and indicators from local documents, and checking TCP ports on authorized hosts.

## Features

- Resolve a hostname or URL to its IPv4 and IPv6 addresses.
- Create passive reports from public RDAP, DNS, reverse-DNS, and Certificate Transparency sources.
- Audit an authorized private-network router's selected TCP services and query public NVD advisories for a user-supplied model/firmware.
- Extract text, basic metadata, URLs, domains, IP addresses, and email addresses from local files.
- Scan a selected IP address using a built-in common-port list, ports 1-1024, or custom ports and ranges.
- Adjust the connection timeout for each port check.
- Save port scans as CSV and OSINT, extraction, or router-audit reports as JSON.

## Requirements

- Python 3.9 or newer
- A terminal: PowerShell or Command Prompt on Windows, Terminal on macOS, or a shell on Linux
- Git to clone the repository, or a browser to download it as a ZIP file
- The `pypdf` and `python-docx` packages for PDF and DOCX extraction

Install the project dependencies after cloning or updating the repository:

```sh
python -m pip install -r requirements.txt
```

On Windows, `py -3 -m pip install -r requirements.txt` can be used instead. The GitHub Actions workflow runs the unit tests on supported Python versions when changes are pushed or a pull request is opened.

## Installation

### Windows

1. Install Python 3.9 or newer from [python.org](https://www.python.org/downloads/). Select **Add python.exe to PATH** in the installer. The Python Launcher (`py`) is also useful and is included with the official installer.
2. Open PowerShell and clone the project:

	```powershell
	git clone https://github.com/justhim08/ip-identifier.git
	cd ip-identifier
	```

	If Git is not installed, use the repository's **Code > Download ZIP** button, extract the archive, and open a terminal in the extracted folder.
3. Confirm Python is available and run the program:

	```powershell
	py -3 --version
	py -3 -m pip install -r requirements.txt
	py -3 "ip finder.py"
	```

	If `py` is unavailable but `python` works, use `python --version` and `python "ip finder.py"` instead.

### macOS

1. Install Python 3.9 or newer from [python.org](https://www.python.org/downloads/macos/) or with [Homebrew](https://brew.sh/):

	```sh
	brew install python
	```

2. In Terminal, clone the project and enter its folder:

	```sh
	git clone https://github.com/justhim08/ip-identifier.git
	cd ip-identifier
	```

	Alternatively, download and extract the repository ZIP from GitHub.
3. Confirm Python is available and start the program:

	```sh
	python3 --version
	python3 -m pip install -r requirements.txt
	python3 "ip finder.py"
	```

### Linux

1. Install Python 3.9 or newer using your distribution's package manager if it is not already installed. For example, on Debian or Ubuntu:

	```sh
	sudo apt update
	sudo apt install python3
	```

	On Fedora, use `sudo dnf install python3`.
2. Clone the project and enter its folder:

	```sh
	git clone https://github.com/justhim08/ip-identifier.git
	cd ip-identifier
	```

	Alternatively, download and extract the repository ZIP from GitHub.
3. Install dependencies, confirm Python is available, and start the program:

	```sh
	python3 --version
	python3 -m pip install -r requirements.txt
	python3 "ip finder.py"
	```

## Use

Run `python "ip finder.py"` (or `python3` on macOS/Linux) to open the interactive menu:

1. Resolve a URL or hostname and display its IP addresses.
2. Scan ports on an IP address you provide.
3. Resolve a URL or hostname, select one of its returned addresses, and scan it.
4. Create a passive OSINT report for a URL, hostname, or IP address.
5. Extract text and indicators from a local file.
6. Audit an authorized router on a private network.
7. Discover nearby Wi-Fi access points and audit an authorized router.
8. Exit.

For a URL or hostname, enter values such as `example.com` or `https://example.com/path`. Option 2 expects an IP address; use option 3 when starting with a URL or hostname.

For a scan, select the common-port list, ports 1-1024, or enter comma-separated ports and ranges, for example `22,80,8000-8010`. The connection timeout defaults to 0.5 seconds and can be set between 0.1 and 5 seconds. Results are sorted by port. You can optionally save them to CSV; the default filename includes the scan date and time, and the file is written to the current directory unless you enter another path.

The two report actions are also available without the interactive menu:

```sh
python "ip finder.py" --osint https://example.com/path
python "ip finder.py" --osint 8.8.8.8 --output ip-report.json
python "ip finder.py" --extract report.pdf
python "ip finder.py" --extract investigation.docx --output extracted.json
python "ip finder.py" --router-audit 192.168.1.1 --network 192.168.1.0/24
python "ip finder.py" --router-audit 192.168.1.1 --model "Example Router X1" --firmware "1.2.3" --output router-report.json
```

OSINT lookups query public DNS-over-HTTPS, RDAP, reverse-DNS, and Certificate Transparency services as applicable. They do not fetch the target website, scan ports, or enumerate private/local IP addresses. Reports include source errors if a public service is unavailable; network access is required. These services can log lookup requests, so avoid submitting confidential targets.

File extraction runs locally and does not upload documents. Supported formats are PDF, DOCX, EML, HTML, HTM, TXT, Markdown, CSV, JSON, XML, RTF, and LOG. PDF and DOCX support uses the installed dependencies. Legacy binary `.doc` files are not supported; save them as `.docx` first. The extractor reads document text and metadata and identifies URLs, domains, IP addresses, and email addresses; it does not extract embedded attachments or run macros.

## Nearby Wi-Fi Discovery

The interactive menu's option 7 uses Windows' built-in `netsh wlan show networks mode=bssid` command to list currently visible Wi-Fi access points with the SSID (network name), BSSID (radio MAC address), signal percentage, and advertised authentication type. It is a discovery/listing feature only: it does not connect to, deauthenticate, or collect traffic from any network. It currently requires Windows, a working wireless adapter, and the Windows WLAN AutoConfig service; no extra Python package or administrator privilege is intended to be required.

You can select an access point from the list, but the selection does **not** mean the computer is connected to it or that you have permission to assess it. To proceed, the operator must type exactly `I AM AUTHORIZED`, then enter the router's private IP address. The audit still refuses public IPs and only checks the fixed TCP ports and optional HTTP `HEAD` responses described above. It does not sweep the selected Wi-Fi network, discover hosts, or infer the router IP from an SSID/BSSID. Provide the target router IP and, optionally, the authorized subnet yourself. Press Enter at the selection prompt to cancel.

The system can display SSID/BSSID values controlled by nearby access points. Treat them as untrusted names; do not interpret them as proof of identity or authorization. The selected SSID, BSSID, signal, and advertised authentication label are included in the saved JSON report as context only.

## Authorized Router Audit

Use router audit only on a router you own or have explicit permission to assess. The audit accepts a **literal private, link-local, or loopback IP address**; it rejects public targets and does not discover or sweep an entire network. It makes TCP connection checks to a fixed list of common router ports: 22 (SSH), 23 (Telnet), 53 (DNS over TCP), 80 (HTTP administration), 443 (HTTPS administration), 7547 (TR-069/CWMP), 8080 (alternate HTTP), and 8443 (alternate HTTPS). It sends an HTTP `HEAD /` request only to detected HTTP/HTTPS management ports and reports selected response headers. It does not request page bodies or submit credentials.

To locate your own router's address, check the default gateway shown by `ipconfig` on Windows, `ip route` on Linux, or `route -n get default` on macOS. Confirm the address belongs to your authorized router before running the audit. To include the subnet in the report, pass its CIDR network, such as `--network 192.168.1.0/24`; the tool checks that the target is inside that subnet and does not infer a network mask. Router model and firmware are optional inputs; read them from the router label or its administration/status page and pass them using `--model` and `--firmware`.

When model or firmware is provided, the tool makes one public NVD CVE API keyword search and includes up to 20 returned advisory candidates. NVD keyword results are not an exact affected-version determination: verify the hardware revision, firmware range, CVE affected-product records, and vendor advisory before deciding that a router is vulnerable. The report can record identity hints from selected HTTP response headers, but those headers and user-supplied model/firmware are not independently verified.

This is an inventory and research aid, not a vulnerability scanner or exploit framework. It does not test passwords, capture password hashes, brute-force accounts, intercept browser activity, capture packets, probe UDP/UPnP, change router settings, or exploit vulnerabilities. UDP/UPnP status is explicitly reported as not checked. Review authentication settings, remote administration, firmware support, WPS, guest-network isolation, and vendor guidance manually through the router's documented administration interface.

## Interpreting Results

- `open`: the TCP connection succeeded.
- `closed`: the target actively refused the connection.
- `filtered/no response`: the connection timed out or another socket error prevented a connection.

A TCP connection scan cannot reliably distinguish firewall filtering from packet loss, routing problems, or other network errors. Results reflect the host and network at the time of the scan; firewalls and other policies can affect them.

Passive OSINT results are limited to information available from the queried public sources; they are not a complete inventory of a host or its owners. Missing records do not prove that a domain, address, or service does not exist.

For a router audit, `open` means a TCP connection was accepted at the time of the check; it does not prove a weakness. A service marked `closed` refused the connection, while `no response` is inconclusive. HTTP response headers are hints and can be hidden, customized, or misleading. CVE results are search candidates and require manual product/version verification.

## Troubleshooting

- **Python is not recognized:** reopen the terminal after installing Python, confirm the installer added Python to `PATH`, or try `py -3` on Windows and `python3` on macOS/Linux.
- **A hostname cannot be resolved:** check the spelling and network/DNS connection, and try again.
- **A scan returns no open ports:** this does not prove a host is offline; its ports may be closed, filtered, or unreachable from your network.
- **PDF or DOCX extraction is unavailable:** install the project dependencies with `python -m pip install -r requirements.txt`.
- **An OSINT source reports an error:** retry later or verify that your network permits access to the public lookup service named in the report.
- **Router audit rejects an address:** confirm it is the router's private/link-local IP, not a public address, hostname, or subnet broadcast address.
- **No router CVEs are returned:** search results are keyword-based and absence of results is not proof of security; check the vendor's support and security-advisory pages directly.
- **Wi-Fi discovery is unavailable:** confirm that you are running Windows, Wi-Fi is enabled, an adapter is present, and the WLAN AutoConfig service is running.

## Responsible Use

Only scan systems you own or have explicit permission to test. Scanning can trigger security alerts and may be restricted by network policies. Keep scans limited to authorized targets and ports.