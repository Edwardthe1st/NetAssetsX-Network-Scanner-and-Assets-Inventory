# NetAssetX

Scanner reseau local oriente inventaire d'assets, avec rendu et options proches de `nmap`.

## Overview
- Decouverte des hotes actifs sur le reseau local.
- Scan TCP multi-threads.
- Enrichissement service/version (banner, HTTP, TLS).
- Reverse DNS, MAC (ARP local), estimation OS, scoring risque.
- Exports `JSON`, `HTML` et sortie texte `Nmap-like`.

## Features
- Host discovery (TCP probes)
- TCP connect scan
- Service identification (`service` + `version`)
- Reverse DNS (hostname)
- MAC via ARP (local L2)
- HTTP headers (HEAD)
- TLS cert info (CN, issuer, TLS version)
- Heuristic OS fingerprint
- Risk scoring
- JSON + HTML + Nmap-like exports

## Requirements
- Python 3
- Dependency: `jinja2`

## Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r Requirement.txt
```

## Quick Start
```bash
python3 Main.py --target auto
```

## Nmap-like Commands
### Scan default local subnet
```bash
python3 Main.py --target auto
```

### Scan one host (no discovery)
```bash
python3 Main.py --target 192.168.1.10 -Pn
```

### Scan around one host (/24)
```bash
python3 Main.py --target 192.168.1.10 --around
```

### Custom ports (`-p`) + normal output (`-oN`)
```bash
python3 Main.py --target 192.168.1.0/24 -p 22,80,443 -oN scan.nmap
```

### Show reason and non-open ports in Nmap output
```bash
python3 Main.py --target auto --show-closed --reason --print-nmap
```

## Key Options
- `--target` : IP, CIDR ou `auto`
- `--around` : si `--target` est une IP, scanne le `/24` autour
- `-p`, `--ports` : ports a scanner (`22,80,443,8000-8100`)
- `-Pn`, `--no-discovery` : desactive host discovery
- `--discovery-ports` : ports utilises pour detecter les hotes vivants
- `--no-rdns` : desactive reverse DNS
- `--no-mac` : desactive recuperation MAC
- `--no-http` : desactive collecte HTTP
- `--no-tls` : desactive collecte TLS
- `--json` : chemin de sortie JSON
- `--html` : chemin de sortie HTML
- `-oN`, `--nmap` : chemin de sortie texte style nmap
- `--show-closed` : inclut closed/filtered dans le rapport nmap
- `--reason` : ajoute la colonne reason dans le rapport nmap
- `--print-nmap` : affiche le rendu nmap dans la console

## Outputs
- JSON: `Data/Scans/scan_YYYY_MM_DD_HHMMSS.json`
- HTML: `report.html`
- Nmap-like: `Data/Scans/scan_YYYY_MM_DD_HHMMSS.nmap`

## Notes
- La MAC est visible uniquement sur le meme segment L2 (ARP cache), sinon `N/A`.
- Le scan est un `TCP connect scan`, pas un SYN raw scan comme `nmap -sS`.
- La detection de version reste heuristique, donc moins precise que `nmap -sV`.

## Safety
Utiliser uniquement dans des environnements autorises.
