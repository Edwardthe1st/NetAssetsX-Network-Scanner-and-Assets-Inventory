# NetAssetX

Scanner réseau local pour inventaire d’assets avec enrichissement léger et rapports JSON/HTML.

## Overview
- Découvre les hôtes actifs sur un réseau local.
- Scanne les ports TCP et identifie les services.
- Enrichit avec reverse DNS, MAC (ARP), headers HTTP et infos TLS.
- Génère un rapport JSON et un HTML lisible.

## Features
- Host discovery (TCP probes)
- TCP port scan
- Service identification (banner + heuristics)
- Reverse DNS (hostname)
- MAC via ARP (local L2)
- HTTP headers (HEAD)
- TLS cert info (CN, issuer, version)
- OS fingerprint heuristique
- Risk scoring
- JSON + HTML export

## Requirements
- Python 3
- Dependencies: `jinja2`

## Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r Requirement.txt
```

## Usage
```bash
python3 Main.py --target auto
```

### Scan a Single IP
```bash
python3 Main.py --target 192.168.1.10
```

### Scan Around an IP (/24)
```bash
python3 Main.py --target 192.168.1.10 --around
```

### Scan a CIDR + Custom Ports
```bash
python3 Main.py --target 192.168.1.0/24 --ports 22,80,443
```

## Key Options
- `--target` : IP, CIDR, ou `auto`
- `--around` : si `--target` est une IP, scanne le `/24`
- `--mask` : masque pour `--around` ou `auto`
- `--ports` : liste de ports (`22,80,443,8000-8100`)
- `--discovery-ports` : ports utilisés pour la découverte d’hôtes
- `--no-discovery` : désactive la découverte
- `--no-rdns` : désactive reverse DNS
- `--no-mac` : désactive récupération MAC
- `--no-http` : désactive HEAD HTTP
- `--no-tls` : désactive infos TLS
- `--json` : chemin de sortie JSON
- `--html` : chemin de sortie HTML

## Output
- JSON: `Data/Scans/scan_YYYY_MM_DD_HHMMSS.json`
- HTML: `report.html`

## Notes
- MAC = uniquement sur le même réseau L2 (ARP cache), sinon `N/A`.
- TLS CN récupéré via handshake (SNI basé sur reverse DNS si dispo).

## Safety
Utiliser uniquement dans des environnements autorisés.
