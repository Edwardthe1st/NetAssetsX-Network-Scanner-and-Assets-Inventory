# NetAssetsX

A local network scanner and asset inventory tool, written in Python. It discovers live hosts on a subnet, scans their TCP ports, identifies services, and produces an inventory with JSON, HTML and Nmap-style output.

Built to understand how a scanner like nmap works from the inside: host discovery, port states, service and version detection, OS fingerprinting and risk scoring, each implemented from scratch rather than shelled out to an external tool.

> **Authorised use only.** Run this against your own network or a network you have permission to scan. Port scanning networks you don't control is illegal in most countries.

---

## What it does

- **Host discovery** — finds live hosts on the local subnet with TCP probes
- **Port scanning** — multi-threaded TCP connect scan
- **Service identification** — service and version from banners, HTTP HEAD, and TLS
- **Host detail** — reverse DNS, MAC address via the local ARP cache, heuristic OS fingerprint
- **Risk scoring** — a simple score per host based on what's exposed
- **Exports** — JSON, HTML, and an Nmap-like text format, plus a diff between two scans

The pipeline is split into a `Scanner/` package (discovery, port scan, service, OS fingerprint, enrichment, risk) and a `Reporting/` package (JSON, HTML, Nmap-style, diff), tied together by `Main.py`.

---

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r Requirement.txt
```

The only dependency is Jinja2, used for the HTML report.

---

## Usage

Scan the local subnet automatically:

```bash
python3 Main.py --target auto
```

A single host, skipping discovery:

```bash
python3 Main.py --target 192.168.1.10 -Pn
```

Custom ports with Nmap-style output:

```bash
python3 Main.py --target 192.168.1.0/24 -p 22,80,443 -oN scan.nmap
```

Show reasons and closed ports in the console:

```bash
python3 Main.py --target auto --show-closed --reason --print-nmap
```

### Main options

| Option | Purpose |
| --- | --- |
| `--target` | IP, CIDR, or `auto` |
| `--around` | scan the /24 around a single target IP |
| `-p`, `--ports` | ports to scan (`22,80,443,8000-8100`) |
| `-Pn`, `--no-discovery` | skip host discovery |
| `--no-rdns` / `--no-mac` / `--no-http` / `--no-tls` | turn off individual enrichment steps |
| `--json` / `--html` / `-oN` | output paths for each format |
| `--show-closed` / `--reason` / `--print-nmap` | Nmap-style output detail |

Threads and timeouts for each stage are tunable too — see `python3 Main.py --help`.

---

## Output

- JSON: `Data/Scans/scan_YYYY_MM_DD_HHMMSS.json`
- HTML: `report.html`
- Nmap-like: `Data/Scans/scan_YYYY_MM_DD_HHMMSS.nmap`

---

## Known limits

This is a learning project, and it makes deliberate trade-offs against a tool like nmap:

- It's a TCP connect scan, not a raw SYN scan, so it's noisier and slower.
- Version detection is heuristic, so less precise than `nmap -sV`.
- MAC addresses only resolve on the same L2 segment (via the ARP cache); otherwise `N/A`.
