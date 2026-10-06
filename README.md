# IP Finder and TCP Port Scanner

A small, standard-library-only Python command-line tool that resolves URLs or hostnames to IP addresses and checks TCP ports on one selected host.

## Requirements

- Python 3.9 or newer
- No third-party packages

## Run

```powershell
python "ip finder.py"
```

## Options

1. Resolve a URL or hostname to its IP addresses.
2. Scan TCP ports on an IP address you already know.
3. Resolve a URL or hostname, choose one returned IP address, and scan it.
4. Exit.

For a port scan, choose the common-port list, ports 1-1024, or enter individual ports and ranges such as `22,80,8000-8010`. The connection timeout can be adjusted from 0.1 to 5 seconds. Results can optionally be saved to CSV.

The scan reports a successful connection as `open`, a refused connection as `closed`, and a timeout or other socket error as `filtered/no response`. A TCP connection scan cannot always tell filtering from packet loss or other network failures.

Only scan systems you own or have explicit permission to test. Port availability can change, and firewall rules may affect results.