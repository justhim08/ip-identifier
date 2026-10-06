# IP Finder and TCP Port Scanner

A Python command-line utility for resolving URLs and hostnames to IP addresses and checking TCP ports on a selected host. It uses only the Python standard library, so there are no third-party packages to install.

## Features

- Resolve a hostname or URL to its IPv4 and IPv6 addresses.
- Scan a selected IP address using a built-in common-port list, ports 1-1024, or custom ports and ranges.
- Adjust the connection timeout for each port check.
- Save scan results as a CSV file.

## Requirements

- Python 3.9 or newer
- A terminal: PowerShell or Command Prompt on Windows, Terminal on macOS, or a shell on Linux
- Git to clone the repository, or a browser to download it as a ZIP file

No administrator privileges or Python packages are required to run the program. Package-manager commands below may require administrator privileges when installing Python.

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
3. Confirm Python is available and start the program:

	```sh
	python3 --version
	python3 "ip finder.py"
	```

## Use

The interactive menu offers four choices:

1. Resolve a URL or hostname and display its IP addresses.
2. Scan ports on an IP address you provide.
3. Resolve a URL or hostname, select one of its returned addresses, and scan it.
4. Exit.

For a URL or hostname, enter values such as `example.com` or `https://example.com/path`. Option 2 expects an IP address; use option 3 when starting with a URL or hostname.

For a scan, select the common-port list, ports 1-1024, or enter comma-separated ports and ranges, for example `22,80,8000-8010`. The connection timeout defaults to 0.5 seconds and can be set between 0.1 and 5 seconds. Results are sorted by port. You can optionally save them to CSV; the default filename includes the scan date and time, and the file is written to the current directory unless you enter another path.

## Interpreting Results

- `open`: the TCP connection succeeded.
- `closed`: the target actively refused the connection.
- `filtered/no response`: the connection timed out or another socket error prevented a connection.

A TCP connection scan cannot reliably distinguish firewall filtering from packet loss, routing problems, or other network errors. Results reflect the host and network at the time of the scan; firewalls and other policies can affect them.

## Troubleshooting

- **Python is not recognized:** reopen the terminal after installing Python, confirm the installer added Python to `PATH`, or try `py -3` on Windows and `python3` on macOS/Linux.
- **A hostname cannot be resolved:** check the spelling and network/DNS connection, and try again.
- **A scan returns no open ports:** this does not prove a host is offline; its ports may be closed, filtered, or unreachable from your network.

## Responsible Use

Only scan systems you own or have explicit permission to test. Scanning can trigger security alerts and may be restricted by network policies. Keep scans limited to authorized targets and ports.