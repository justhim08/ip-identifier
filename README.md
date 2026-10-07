# SENTINEL — Network & Threat Intelligence Toolkit

A Python command-line toolkit for authorized router auditing, nearby Wi-Fi discovery, passive OSINT, TCP port checks, and extracting indicators from local documents.

## Features

- Resolve a hostname or URL to its IPv4 and IPv6 addresses.
- Collect passive DNS, RDAP, reverse-DNS, Certificate Transparency, and approximate IP/ASN/geolocation intelligence.
- Read the default gateway and cached neighbor table without sending network probes.
- Identify common TCP services by port and make bounded HTTP `HEAD` checks for open web ports.
- Audit an authorized private-network router's selected TCP services and query public NVD advisories for a user-supplied model/firmware.
- Extract text, basic metadata, URLs, domains, IP addresses, and email addresses from local files.
- Perform structured, read-only artifact analysis with file-type evidence, streamed hashes, normalized indicators, conservative findings, and provenance-preserving relationships.
- Scan a selected IP address using a built-in common-port list, ports 1-1024, or custom ports and ranges.
- Adjust the connection timeout for each port check.
- Export supported results as JSON, CSV, or readable text.

## Requirements

- Python 3.9 or newer
- A terminal: PowerShell or Command Prompt on Windows, Terminal on macOS, or a shell on Linux
- Git to clone the repository, or a browser to download it as a ZIP file
- The `pypdf` and `python-docx` packages for PDF and DOCX extraction

Install the package in editable mode after cloning. This installs the `sentinel` command and `python -m sentinel` entry point:

```sh
python -m pip install -e .
```

On Windows, use `py -3 -m pip install -e .`. To install only the runtime dependencies without installing the command, use `python -m pip install -r requirements.txt`. The GitHub Actions workflow installs the package and runs the unit tests on supported Python versions when changes are pushed or a pull request is opened.

If your shell cannot find the `sentinel` command after installation, the Python `Scripts` directory may not be on `PATH`; use `python -m sentinel` (or `py -3 -m sentinel` on Windows) instead.

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
	py -3 -m pip install -e .
	py -3 -m sentinel
	```

	If `py` is unavailable but `python` works, use `python --version`, install with `python -m pip install -e .`, then run `python -m sentinel`.

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
	python3 -m pip install -e .
	python3 -m sentinel
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
	python3 -m pip install -e .
	python3 -m sentinel
	```

## Use

Run `sentinel` or `python -m sentinel` with no command to open the interactive menu. On Windows, `py -3 -m sentinel` is also supported. The menu offers reconnaissance, authorized scans and router audits, local inventory, document analysis, report rendering, and a settings view. Actions return to the menu after completion or a recoverable input error.

For non-interactive command mode:

```sh
sentinel --help
sentinel recon example.com
sentinel intel example.com
sentinel cve "Example Router"
sentinel scan 192.168.1.1 --ports 22,80,443
sentinel router-audit 192.168.1.1 --authorized --authorized
sentinel file sample.pdf
sentinel assess scan-report.json --exposure private --output-format text
sentinel inventory
sentinel report results.json --output-format csv --output reports/
sentinel settings
```

Network scanning is intended only for targets you own or have explicit permission to assess. `scan` accepts a literal IPv4 or IPv6 address and performs bounded TCP connection checks; it does not use stealth or firewall-evasion techniques. `router-audit` remains limited to private, link-local, or loopback router IP addresses.

The `report` command reads a previously saved SENTINEL JSON report and renders it as JSON, CSV, or readable text. A trailing slash on `--output` means “save into this directory” and generates a dated filename. Otherwise `--output` is a file path. Relative file outputs are placed under the configured report directory.

The original script launchers and option-style commands remain available for compatibility:

```sh
python "SENTINEL — Network & Threat Intelligence Toolkit.py"
python "ip finder.py"
python -m sentinel --osint 8.8.8.8 --output ip-report.json
python -m sentinel --extract report.pdf --output extracted.json
python -m sentinel --router-audit 192.168.1.1 --network 192.168.1.0/24
python -m sentinel --local-inventory --output local-network.txt
```

Use `--output-format json`, `--output-format csv`, or `--output-format text` to select a report representation. `--format` is retained as an alias.

Report actions are also available without the interactive menu:

```sh
sentinel --osint https://example.com/path
python -m sentinel --osint 8.8.8.8 --output ip-report.json
python -m sentinel --osint 8.8.8.8 --output ip-report.csv
python -m sentinel --extract report.pdf
python -m sentinel --extract investigation.docx --output extracted.json
python -m sentinel --router-audit 192.168.1.1 --network 192.168.1.0/24
python -m sentinel --router-audit 192.168.1.1 --model "Example Router X1" --firmware "1.2.3" --output router-report.json
python -m sentinel --local-inventory --output local-network.txt
python -m sentinel --local-inventory --format csv --output local-network.csv
```

Reports use JSON by default. `--format json`, `--format csv`, or `--format txt` selects an explicit format; absent that flag, `.json`, `.csv`, `.txt`, and `.md` output extensions are recognized. In the interactive menu's report actions, choose JSON, CSV, or readable text. CSV reports use `Field,Value` rows with nested object paths and indexed list entries so structured information is preserved.

### Local file and artifact analysis

`sentinel file <path>` analyzes one local file without uploading it or contacting external services. It reports the filename and extension separately from the detected type, MIME type, size, local SHA-256/SHA-1/MD5 identification hashes, extracted metadata, deduplicated indicators, source evidence, relationships, and cautious observations. SHA-1 and MD5 are included only for identification and are not security guarantees. JSON is the default output; `--output-format csv|text` and `--output` use the same report options as the other commands.

Supported content extraction covers PDF, DOCX, EML, HTML, CSV, JSON, Markdown, RTF, XML, and plain text. The analyzer reads document properties and email attachment metadata but does not open attachment payloads. It never executes analyzed files, scripts, macros, embedded content, or JavaScript, and does not follow extracted URLs. Extension/signature disagreement is recorded as an observation, not a malware verdict. A per-file extraction limit and bounded PDF/DOCX processing can produce a `PARTIAL` result; hashes are still computed locally by streaming. Metadata is unverified file-supplied content, and an IP, URL, command reference, or other indicator alone does not establish maliciousness.

## Configuration and Logging

SENTINEL works with built-in defaults; a configuration file is optional. To load one, use `--config sentinel.toml`. CLI overrides take precedence over that file, which takes precedence over built-in defaults:

```text
CLI options
    ↓
TOML configuration file
    ↓
built-in defaults
```

Example `sentinel.toml`:

```toml
[scanner]
timeout = 2.0
concurrency = 25
ports = [22, 80, 443]

[reports]
directory = "reports"
format = "json"

[logging]
level = "INFO"
```

The report directory in a TOML file is relative to that configuration file. For Python 3.9 and 3.10, TOML support is provided by the installed `tomli` dependency.

Scanner options are bounded and validated: `--timeout` accepts 0.1–5 seconds, `--concurrency` accepts 1–100 workers, and `--ports` accepts comma-separated ports/ranges such as `22,80,8000-8010`. For example:

```sh
sentinel scan 192.168.1.1 --ports 22,80,443 --timeout 2 --concurrency 25
sentinel recon example.com --config sentinel.toml --log-level DEBUG
sentinel inventory --report-directory reports --output local-network.json
```

Logging uses the standard Python logging system and supports `DEBUG`, `INFO`, `WARNING`, and `ERROR`; set it through `[logging].level` or `--log-level`. Logs contain operation-level messages and avoid printing target arguments or credentials. SENTINEL does not store credentials in its configuration. Errors are presented without tracebacks: command-line syntax/argument errors exit with status 2, target or configuration errors with status 3, general runtime errors with status 1, and success with status 0.

OSINT lookups query public DNS-over-HTTPS, RDAP, reverse-DNS, Certificate Transparency, and (for IP targets) an IP intelligence/geolocation API. They do not fetch the target website, scan ports, or enumerate private/local IP addresses. Reports include source errors if a public service is unavailable; network access is required. External lookup services can log queries; IP geolocation is approximate and may be inaccurate, so avoid submitting confidential targets.

File extraction runs locally and does not upload documents. Supported formats are PDF, DOCX, EML, HTML, HTM, TXT, Markdown, CSV, JSON, XML, RTF, and LOG. PDF and DOCX support uses the installed dependencies. Legacy binary `.doc` files are not supported; save them as `.docx` first. The extractor reads document text and metadata and identifies URLs, domains, IP addresses, and email addresses; it does not extract embedded attachments or run macros.

## Nearby Wi-Fi Discovery

In the interactive menu, choose **Router Security Audit**, then choose nearby Wi-Fi discovery. SENTINEL uses Windows' built-in `netsh wlan show networks mode=bssid` command to list currently visible Wi-Fi access points with the SSID (network name), BSSID (radio MAC address), signal percentage, and advertised authentication type. It is a discovery/listing feature only: it does not connect to, deauthenticate, or collect traffic from any network. It currently requires Windows, a working wireless adapter, and the Windows WLAN AutoConfig service; no extra Python package or administrator privilege is intended to be required.

You can select an access point from the list, but the selection does **not** mean the computer is connected to it or that you have permission to assess it. To proceed, the operator must type exactly `I AM AUTHORIZED`, then enter the router's private IP address. The audit still refuses public IPs and only checks the fixed TCP ports and optional HTTP `HEAD` responses described above. It does not sweep the selected Wi-Fi network, discover hosts, or infer the router IP from an SSID/BSSID. Provide the target router IP and, optionally, the authorized subnet yourself. Press Enter at the selection prompt to cancel.

The system can display SSID/BSSID values controlled by nearby access points. Treat them as untrusted names; do not interpret them as proof of identity or authorization. The selected SSID, BSSID, signal, and advertised authentication label are included in the saved JSON report as context only.

## Router Security Assessment

Use router audit only on a router you own or have explicit permission to assess. The CLI displays an authorization notice and requires you to type `I AM AUTHORIZED`; for non-interactive use, supply `--authorized` explicitly. This module accepts a **literal private or local IP address** and rejects public targets. Supported IPv4 ranges include RFC 1918 private networks; local loopback/link-local and IPv6 ULA/link-local addresses are also accepted. It does not discover or sweep an entire network.

The audit makes TCP connection checks to a fixed list of common router ports: 22 (SSH), 23 (Telnet), 53 (DNS over TCP), 80 (HTTP administration), 443 (HTTPS administration), 7547 (TR-069/CWMP), 8080 (alternate HTTP), and 8443 (alternate HTTPS). It sends an HTTP `HEAD /` request only to detected HTTP/HTTPS management ports and reports selected response headers, status, and safe TLS certificate metadata. It does not request page bodies, attempt login, submit credentials, or change router settings. UDP 1900/UPnP/SSDP is not assessed by the TCP-only scanner; SENTINEL does not claim that UPnP is absent.

To locate your own router's address, check the default gateway shown by `ipconfig` on Windows, `ip route` on Linux, or `route -n get default` on macOS. Confirm the address belongs to your authorized router before running the audit. To include the subnet in the report, pass its CIDR network, such as `--network 192.168.1.0/24`; the tool checks that the target is inside that subnet and does not infer a network mask. Router model and firmware are optional inputs; read them from the router label or its administration/status page and pass them using `--model` and `--firmware`.

Router identity from administrator-supplied values and HTTP headers is shown as a potential match, not independent confirmation. Unknown firmware remains `Unknown`; SENTINEL does not guess a version. Findings include stable IDs, severity, target and service context, evidence, impact, and recommendation. A detected Telnet listener receives a HIGH finding; HTTP response evidence is described as an administration-interface observation, not proof of a login form or unencrypted credential submission. TR-069 port reachability is informational unless there is additional evidence.

When model or firmware is provided, the tool makes one public NVD CVE API keyword search and includes up to 20 normalized candidates (CVSS, dates, references, and available CPE product strings). A result is only **potentially relevant** and its applicability **requires verification** against the exact model, hardware revision, firmware range, and manufacturer advisory. A keyword match is not a confirmed vulnerability. NVD/network errors are reported while the local service assessment continues.

Example text report:

```text
SENTINEL ROUTER SECURITY ASSESSMENT
Target: 192.168.1.1
Router: Unknown
Identification confidence: UNKNOWN
Firmware: Unknown
Management transport: HTTP + HTTPS

ROUTER SERVICE EXPOSURE
23    OPEN        Telnet
80    OPEN        HTTP administration
443   OPEN        HTTPS administration
7547  CLOSED      TR-069/CWMP

FINDINGS
[HIGH] Telnet Service Exposed
Evidence: TCP/23 is reachable.
Recommendation: Disable Telnet if unnecessary and use secure administration such as SSH where supported.
[MEDIUM] Router Administration Interface Available Over HTTP
Evidence: HTTP 200 on TCP/80.
Recommendation: Prefer HTTPS-only administration if supported.

VULNERABILITY INTELLIGENCE
No NVD query requested.
```

This is an inventory and research aid, not a comprehensive vulnerability scanner or exploit framework. It does not test passwords, capture password hashes, brute-force accounts, intercept browser activity, capture packets, probe UDP/UPnP, change router settings, or exploit vulnerabilities. Review authentication settings, remote administration, firmware support, WPS, guest-network isolation, and vendor guidance manually through the router's documented administration interface.

## Local Network Inventory and Service Identification

The read-only local inventory action reports available interface addresses, subnets, interface names, MAC addresses, the default gateway, and entries already present in the operating system's neighbor cache. The neighbor list is explicitly a **CACHED LOCAL NEIGHBOR SNAPSHOT**, not a complete device inventory. No subnet sweep or discovery probes are performed. Interface or vendor details can be unavailable; vendor identification is omitted unless a local OUI database is available.

During an explicitly requested TCP port scan, SENTINEL labels known service ports and consults the local TCP service-name database for other ports. For open web ports, it sends a bounded HTTP `HEAD /` request and captures status, selected content/security headers, and TLS metadata for HTTPS; it does not crawl, download page bodies, or submit credentials. An SSH identification banner may be collected from open TCP/22. A port mapping is only a service inference; direct protocol responses are stronger evidence and no software version is asserted beyond an observed banner. Scans should be limited to systems you own or have explicit permission to test.

Reconnaissance is passive: DNS, RDAP, reverse-DNS, IP intelligence, and Certificate Transparency results come from public sources. DNS `NXDOMAIN`/empty answers are represented as no-record results, distinct from resolver failures. PTR absence is not inherently suspicious. IP geolocation is third-party and approximate. Certificate names are discovery data, not authorization: SENTINEL never automatically scans hostnames found in certificates.

## Passive Intelligence and CVE Correlation

`recon` and its `intel` alias query public DNS-over-HTTPS, RDAP, reverse DNS, Certificate Transparency, and (for public IP targets) ipwho.is. The `intel` command uses the same passive collection path and adds normalized intelligence records and evidence-backed relationships; it does not crawl certificate-derived hostnames or probe discovered hosts. Certificate Transparency data is externally reported. Router/service HTTP headers and TLS certificates are directly observed only where the existing authorized audit already makes its bounded request.

Each structured intelligence record carries its source, category, target, value, evidence, confidence, timestamp, classification, and status. Confidence uses `CONFIRMED`, `HIGH`, `MEDIUM`, `LOW`, or `UNKNOWN`; weak/incomplete evidence is not upgraded. Relationships retain their source and evidence, and duplicate facts are merged without discarding provenance. Reports expose records and links in JSON and CSV and summarize provenance/status in text.

Supported intelligence inputs include DNS A/AAAA/CNAME/MX/NS/TXT/CAA/PTR responses, RDAP allocation/registration fields, approximate IP ASN/organization/geolocation information, Certificate Transparency names/certificate metadata, and already observed HTTP/TLS/service-banner evidence. DNS/CT/RDAP/IP intelligence is externally reported; local HTTP and TLS metadata is marked directly observed, while hostnames derived from certificates are marked certificate-derived. A DNS record, certificate hostname, ASN, organization field, or geolocation is not proof of ownership or a vulnerability.

Use `sentinel cve "Example Router"` for public NVD keyword intelligence. Optional product details can be supplied for conservative CPE correlation:

```sh
sentinel cve "Example Router" --vendor example --product router --version 1.2.3
```

CVE reports normalize CVE IDs, descriptions, CVSS score/severity, dates, references, and available CPE affected-product/version ranges while preserving source data from NVD. CVSS severity is normalized to `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `UNKNOWN`. A product/version match is reported as correlated or potentially affected only when the supplied evidence is sufficiently reliable; administrator-provided values remain medium/low confidence and require verification. A CVE search hit is **not** a confirmed vulnerability: verify exact model, hardware revision, firmware range, and vendor advisory. NVD rate limits, timeouts, malformed responses, and source outages are shown as source status rather than successful applicability claims.

## Risk Assessment

`sentinel assess <saved-report.json>` consumes only findings already present in a SENTINEL JSON report. It performs no scanning, DNS or NVD lookup, file inspection, or other external access. It preserves all original report data and adds `risk_assessments`, an `assessment` summary, and the explicit `risk_context`. Use `--exposure public|private` only when the operator can supply that context; the default is `unknown`, and exposure is never inferred from an IP address or target type.

Severity is normalized through the shared finding layer and ordered `CRITICAL > HIGH > MEDIUM > LOW > INFO`; missing severity is `UNKNOWN`. Confidence and status reuse the Phase 5 levels (`CONFIRMED`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`) and states (`OBSERVED`, `CORRELATED`, `POTENTIAL`, `REQUIRES_VERIFICATION`, `CONFIRMED`, `UNKNOWN`). Unknown severity, confidence, or status produces an unscored `UNKNOWN`/`UNRANKED` result rather than a manufactured low score.

The fixed, deterministic per-finding score is clamped to **0–100** and rounded half-up:

`severity points × confidence weight × status weight × exposure multiplier`

| Input | Value | Points / weight |
|---|---|---:|
| Severity | CRITICAL / HIGH / MEDIUM / LOW / INFO | 100 / 75 / 50 / 25 / 5 |
| Confidence | CONFIRMED / HIGH / MEDIUM / LOW | 1.00 / 0.85 / 0.65 / 0.35 |
| Status | CONFIRMED / OBSERVED / CORRELATED / POTENTIAL / REQUIRES_VERIFICATION | 1.00 / 0.90 / 0.75 / 0.60 / 0.40 |
| Exposure | PUBLIC_TARGET / EXPOSURE_UNKNOWN / PRIVATE_TARGET | 1.05 / 1.00 / 0.95 |

Exposure multipliers are intentionally small: command-line exposure is operator-provided context, not independently verified. Risk levels use score thresholds: 85+ `CRITICAL`, 65+ `HIGH`, 40+ `MEDIUM`, 15+ `LOW`, lower scores `INFO`. Priorities are separate: `P0` requires a confirmed critical finding, high/confirmed confidence, and explicitly public exposure; `P1` requires score ≥60 and a high/critical severity with strong confidence and confirmed/observed/correlated status; `P2` requires score ≥40, medium-or-higher severity/confidence, and confirmed/observed/correlated status; `P3` is a known score ≥15; `P4` is a lower known score. Incomplete core inputs remain `UNRANKED`, not `P4`.

Duplicate findings are grouped only by an explicit `risk_key` within the same target, or by target, category, port, and issue title (CVE ID for CVE findings). The assessment keeps every source finding, evidence item, provenance, and recommendation; it selects the strongest individual score for that issue and counts the issue once. Shared target alone is not a deduplication rule. The overall score is `70% × highest deduplicated issue score + 30% × mean of deduplicated issue scores`, not a sum; empty or wholly unranked input yields `UNKNOWN`. Severity/confidence counts are over deduplicated issues, and the summary also reports raw and deduplicated counts.

**Worked example:** a `HIGH` severity finding with `HIGH` confidence, `OBSERVED` status, and unknown exposure scores `round_half_up(75 × 0.85 × 0.90 × 1.00) = 57`. Its risk level is `MEDIUM`, its remediation priority is `P2`, and its rationale records each input and notes that exposure was not supplied. A CVE requiring verification receives the 0.40 status weight and remains labelled `REQUIRES_VERIFICATION`; the risk engine does not claim exploitability or vulnerability confirmation.

## Project Modules

```text
src/sentinel/
├── __main__.py             # python -m sentinel
├── cli.py                  # shared interactive and command-driven CLI
├── config.py               # validated defaults and optional TOML settings
├── validation.py           # reusable target, path, and scan-option checks
├── logging_config.py       # consistent CLI logging
├── recon/dns.py            # host normalization and DNS resolution
├── osint/intelligence.py   # DNS, RDAP, reverse DNS, certificates, IP intel
├── intel/
│   ├── models.py           # intelligence records and sourced relationships
│   ├── pipeline.py         # provenance-aware normalization and deduplication
│   └── vulnerability.py    # NVD normalization and product/version correlation
├── network/
│   ├── assessment.py       # scan/service orchestration
│   ├── scanner.py          # bounded TCP connection checks
│   ├── services.py
│   ├── inventory.py
│   └── wifi.py
├── router/
│   ├── audit.py
│   └── findings.py
├── files/
│   ├── models.py           # structured artifact identity and evidence model
│   ├── extractor.py        # bounded, non-executing content extraction
│   └── analysis.py         # artifact indicators, relationships, and findings
├── risk/
│   ├── models.py           # per-issue risk and overall assessment structures
│   └── engine.py           # deterministic normalization, scoring, and aggregation
└── reports/renderer.py
```

The top-level `SENTINEL — Network & Threat Intelligence Toolkit.py` and legacy `ip finder.py` scripts are compatibility launchers. Both delegate to the same package CLI. The console command is installed by `pip install -e .`.

## Interpreting Results

- `OPEN`: the TCP connection succeeded.
- `CLOSED`: the target actively refused the connection.
- `TIMEOUT`: the connection attempt exceeded the configured timeout.
- `FILTERED`: the operating system returned an access-denied result; it is not inferred merely from silence.
- `ERROR`: another socket or network-path failure occurred.

A TCP connection scan cannot reliably distinguish firewall filtering from packet loss, routing problems, or other network errors. SENTINEL therefore uses `ERROR` for ambiguous path failures rather than claiming they were filtered. Results reflect the host and network at the time of the scan; firewalls and other policies can affect them.

Passive OSINT results are limited to information available from the queried public sources; they are not a complete inventory of a host or its owners. Missing records do not prove that a domain, address, or service does not exist.

For a router audit, `open` means a TCP connection was accepted at the time of the check; it does not prove a weakness. HTTP response headers and TLS certificate fields are observations, not proof that a service or certificate is trustworthy. TLS inspection may report an untrusted certificate without treating it as a verified identity. CVE results are search candidates and require manual product/version verification.

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