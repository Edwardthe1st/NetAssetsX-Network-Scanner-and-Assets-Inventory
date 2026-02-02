# main.py
import os
import ipaddress
from datetime import datetime

from Scanner.Discovery import discover_hosts
from Scanner.PortScan import scan_ports
from Scanner.Service import identify_services
from Scanner.Os_Fingerprint import guess_os
from Scanner.Risk import score_risk
from Reporting.Json_Export import export_json
from Reporting.Html_Export import export_html

TARGET_CIDR = "192.168.1.0/24"

def cidr_to_ips(cidr: str, max_hosts: int = 4096) -> list[str]:
    """
    Convertit un CIDR en liste d'IP (ex: 192.168.1.0/24 -> 254 IP).
    max_hosts évite de lancer un /16 énorme par accident.
    """
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = list(net.hosts())
    if len(hosts) > max_hosts:
        raise ValueError(f"Réseau trop grand: {len(hosts)} hôtes. Réduis le CIDR ou augmente max_hosts.")
    return [str(ip) for ip in hosts]


def main():
    # ===== CONFIG =====
    TARGET_CIDR = "192.168.1.0/24"   # <-- change ici ton réseau
    PORTS_TO_SCAN = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080]
    DISCOVERY_TIMEOUT = 0.4
    PORTSCAN_TIMEOUT = 0.8

    DISCOVERY_THREADS = 250
    PORTSCAN_THREADS = 200  # utilisé dans portscan.py (max_workers)

    os.makedirs("data/scans", exist_ok=True)
    timestamp = datetime.now().strftime("%Y_%m_%d_%H%M%S")
    json_path = f"data/scans/scan_{timestamp}.json"
    html_path = "report.html"

    print(f"[+] NetAssetX - Scan réseau démarré ({timestamp})")
    print(f"[+] Target: {TARGET_CIDR}")
    print(f"[+] Ports: {PORTS_TO_SCAN}")

    # ===== IP LIST =====
    ip_list = cidr_to_ips(TARGET_CIDR)
    print(f"[+] IPs à tester: {len(ip_list)}")

    # ===== DISCOVERY =====
    alive_ips = discover_hosts(ip_list, timeout=DISCOVERY_TIMEOUT, max_threads=DISCOVERY_THREADS)
    print(f"[+] Hôtes vivants détectés: {len(alive_ips)}")
    if alive_ips:
        print("    Exemples:", alive_ips[:10])

    # ===== SCAN + ENRICH =====
    hosts_data = []
    for ip in alive_ips:
        port_states = scan_ports(ip, PORTS_TO_SCAN, timeout=PORTSCAN_TIMEOUT)

        open_ports = sorted([p for p, s in port_states.items() if s == "open"])
        services = identify_services(ip, port_states)
        os_guess = guess_os(services)
        risk = score_risk(open_ports)

        hosts_data.append({
            "ip": ip,
            "open_ports": open_ports,
            "services": services,
            "os": os_guess,
            "risk": risk
        })

        print(f"    - {ip}: open={open_ports} risk={risk['level']}")

    result = {
        "metadata": {
            "tool": "NetAssetX",
            "timestamp": timestamp,
            "target": TARGET_CIDR,
            "ports_scanned": PORTS_TO_SCAN,
            "discovery_timeout": DISCOVERY_TIMEOUT,
            "portscan_timeout": PORTSCAN_TIMEOUT
        },
        "hosts": hosts_data
    }

    export_json(result, json_path)
    export_html(result, html_path)

    print("[+] Scan terminé")
    print(f"[+] JSON: {json_path}")
    print(f"[+] HTML: {html_path}")


if __name__ == "__main__":
    main()