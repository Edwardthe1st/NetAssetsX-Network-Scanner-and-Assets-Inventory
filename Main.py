import argparse
import ipaddress
import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from time import perf_counter

from Scanner.Discovery import discover_hosts
from Scanner.PortScan import scan_ports
from Scanner.Service import identify_services
from Scanner.Os_Fingerprint import guess_os
from Scanner.Risk import score_risk
from Scanner.Enrich import reverse_dns, get_mac_from_arp
from Reporting.Json_Export import export_json
from Reporting.Html_Export import export_html
from Reporting.Nmap_Export import export_nmap, render_nmap_output


DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080
]
DEFAULT_DISCOVERY_PORTS = [80, 443, 22, 445, 3389]
DEFAULT_MASK = 24


def parse_ports(value: str) -> list[int]:
    ports: list[int] = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start = int(start_s)
            end = int(end_s)
            if start > end:
                start, end = end, start
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))

    cleaned = []
    for p in ports:
        if 1 <= p <= 65535 and p not in cleaned:
            cleaned.append(p)
    return cleaned


def get_local_ip() -> str | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except Exception:
        return None
    finally:
        sock.close()


def resolve_target(target: str, around: bool, mask_bits: int) -> tuple[str, str | None]:
    if not target or target.lower() in ("auto", "local"):
        local_ip = get_local_ip()
        if not local_ip:
            raise ValueError("Impossible de déterminer l'IP locale. Spécifie --target.")
        return f"{local_ip}/{mask_bits}", local_ip

    if "/" in target:
        return target, None

    ipaddress.ip_address(target)
    if around:
        return f"{target}/{mask_bits}", target
    return target, target


def target_to_ips(target: str, max_hosts: int = 4096) -> list[str]:
    if "/" in target:
        net = ipaddress.ip_network(target, strict=False)
        host_count = net.num_addresses
        if net.version == 4 and net.num_addresses >= 4:
            host_count = net.num_addresses - 2
        if host_count > max_hosts:
            raise ValueError(
                f"Réseau trop grand: {host_count} hôtes. Réduis le CIDR ou augmente max_hosts."
            )
        hosts = list(net.hosts())
        return [str(ip) for ip in hosts]

    ipaddress.ip_address(target)
    return [target]


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="NetAssetX - Scanner réseau & inventaire d'assets"
    )

    parser.add_argument(
        "-t",
        "--target",
        default="auto",
        help="CIDR, IP unique, ou 'auto' pour le réseau local",
    )
    parser.add_argument(
        "--around",
        action="store_true",
        help="Si target est une IP, scanne le /24 autour",
    )
    parser.add_argument(
        "--mask",
        type=int,
        default=DEFAULT_MASK,
        help="Masque utilisé avec --around ou target=auto (ex: 24)",
    )
    parser.add_argument(
        "-p",
        "--ports",
        default=",".join(str(p) for p in DEFAULT_PORTS),
        help="Ports à scanner, ex: 22,80,443,8000-8100",
    )
    parser.add_argument(
        "--discovery-ports",
        default=",".join(str(p) for p in DEFAULT_DISCOVERY_PORTS),
        help="Ports utilisés pour la découverte d'hôtes",
    )
    parser.add_argument(
        "--max-hosts",
        type=int,
        default=4096,
        help="Limite anti-scan massif",
    )
    parser.add_argument("-Pn", "--no-discovery", action="store_true", help="Skip discovery")
    parser.add_argument("--no-rdns", action="store_true", help="Désactive reverse DNS")
    parser.add_argument("--no-mac", action="store_true", help="Désactive récupération MAC")
    parser.add_argument("--no-http", action="store_true", help="Désactive HEAD HTTP")
    parser.add_argument("--no-tls", action="store_true", help="Désactive info TLS")

    parser.add_argument("--discovery-timeout", type=float, default=0.4)
    parser.add_argument("--portscan-timeout", type=float, default=0.8)
    parser.add_argument("--banner-timeout", type=float, default=1.0)
    parser.add_argument("--http-timeout", type=float, default=2.0)
    parser.add_argument("--tls-timeout", type=float, default=2.0)
    parser.add_argument("--rdns-timeout", type=float, default=1.0)
    parser.add_argument("--arp-timeout", type=float, default=1.0)

    parser.add_argument("--discovery-threads", type=int, default=250)
    parser.add_argument("--portscan-threads", type=int, default=200)
    parser.add_argument("--host-threads", type=int, default=20)

    parser.add_argument("--json", default=None, help="Chemin de sortie JSON")
    parser.add_argument("--html", default="report.html", help="Chemin de sortie HTML")
    parser.add_argument("-oN", "--nmap", default=None, help="Chemin de sortie texte style nmap")
    parser.add_argument("--show-closed", action="store_true", help="Inclure ports non-open dans sortie nmap")
    parser.add_argument("--reason", action="store_true", help="Inclure reason dans sortie nmap")
    parser.add_argument("--print-nmap", action="store_true", help="Afficher sortie nmap en console")

    return parser


def main() -> None:
    args = build_arg_parser().parse_args()

    try:
        if not (1 <= args.mask <= 32):
            raise ValueError("Masque invalide (1-32)")

        resolved_target, base_ip = resolve_target(args.target, args.around, args.mask)
        ports_to_scan = parse_ports(args.ports)
        discovery_ports = parse_ports(args.discovery_ports)
        ip_list = target_to_ips(resolved_target, max_hosts=args.max_hosts)
    except ValueError as exc:
        print(f"[!] {exc}")
        return

    os.makedirs("Data/Scans", exist_ok=True)
    timestamp = datetime.now().strftime("%Y_%m_%d_%H%M%S")
    started_human = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    scan_started = perf_counter()
    json_path = args.json or f"Data/Scans/scan_{timestamp}.json"
    html_path = args.html
    nmap_path = args.nmap or f"Data/Scans/scan_{timestamp}.nmap"

    print(f"[+] NetAssetX - Scan réseau démarré ({timestamp})")
    print(f"[+] Target: {resolved_target}")
    print(f"[+] Ports: {ports_to_scan}")

    print(f"[+] IPs à tester: {len(ip_list)}")

    if args.no_discovery or len(ip_list) == 1:
        alive_ips = ip_list
    else:
        alive_ips = discover_hosts(
            ip_list,
            timeout=args.discovery_timeout,
            max_threads=args.discovery_threads,
            probe_ports=discovery_ports,
        )

    print(f"[+] Hôtes vivants détectés: {len(alive_ips)}")
    if alive_ips:
        print("    Exemples:", alive_ips[:10])

    def scan_host(ip: str) -> dict:
        rdns = None
        if not args.no_rdns:
            rdns = reverse_dns(ip, timeout=args.rdns_timeout)

        port_states = scan_ports(
            ip,
            ports_to_scan,
            timeout=args.portscan_timeout,
            max_threads=args.portscan_threads,
        )

        services = identify_services(
            ip,
            port_states,
            banner_timeout=args.banner_timeout,
            http_timeout=args.http_timeout,
            tls_timeout=args.tls_timeout,
            server_name=rdns or ip,
            enable_http=not args.no_http,
            enable_tls=not args.no_tls,
        )

        mac = None
        if not args.no_mac:
            mac = get_mac_from_arp(ip, timeout=args.arp_timeout)

        open_ports = sorted([p for p, info in port_states.items() if info.get("state") == "open"])
        latencies = [info.get("latency_ms") for info in port_states.values() if info.get("latency_ms") is not None]
        latency_ms = min(latencies) if latencies else None
        os_guess = guess_os(services)
        risk = score_risk(open_ports)

        return {
            "ip": ip,
            "reverse_dns": rdns,
            "mac": mac,
            "latency_ms": latency_ms,
            "port_states": port_states,
            "open_ports": open_ports,
            "services": services,
            "os": os_guess,
            "risk": risk,
        }

    hosts_data: list[dict] = []

    with ThreadPoolExecutor(max_workers=args.host_threads) as executor:
        futures = {executor.submit(scan_host, ip): ip for ip in alive_ips}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                host_data = future.result()
                hosts_data.append(host_data)
                print(f"    - {ip}: open={host_data['open_ports']} risk={host_data['risk']['level']}")
            except Exception as exc:
                print(f"    - {ip}: erreur: {exc}")

    scan_duration = perf_counter() - scan_started
    result = {
        "metadata": {
            "tool": "NetAssetX",
            "timestamp": timestamp,
            "scan_started_human": started_human,
            "target_input": args.target,
            "target_resolved": resolved_target,
            "around": args.around,
            "mask": args.mask,
            "base_ip": base_ip,
            "total_ips": len(ip_list),
            "hosts_up": len(hosts_data),
            "duration_seconds": round(scan_duration, 3),
            "ports_scanned": ports_to_scan,
            "discovery_ports": discovery_ports,
            "discovery_timeout": args.discovery_timeout,
            "portscan_timeout": args.portscan_timeout,
            "banner_timeout": args.banner_timeout,
            "http_timeout": args.http_timeout,
            "tls_timeout": args.tls_timeout,
            "rdns_timeout": args.rdns_timeout,
            "arp_timeout": args.arp_timeout,
            "discovery_threads": args.discovery_threads,
            "portscan_threads": args.portscan_threads,
            "host_threads": args.host_threads,
            "flags": {
                "no_discovery": args.no_discovery,
                "no_rdns": args.no_rdns,
                "no_mac": args.no_mac,
                "no_http": args.no_http,
                "no_tls": args.no_tls,
                "show_closed": args.show_closed,
                "reason": args.reason,
            },
        },
        "hosts": sorted(hosts_data, key=lambda h: h["ip"]),
    }

    export_json(result, json_path)
    export_html(result, html_path)
    export_nmap(result, nmap_path, show_closed=args.show_closed, show_reasons=args.reason)

    if args.print_nmap:
        print("")
        print(render_nmap_output(result, show_closed=args.show_closed, show_reasons=args.reason))

    print("[+] Scan terminé")
    print(f"[+] JSON: {json_path}")
    print(f"[+] HTML: {html_path}")
    print(f"[+] NMAP: {nmap_path}")


if __name__ == "__main__":
    main()
