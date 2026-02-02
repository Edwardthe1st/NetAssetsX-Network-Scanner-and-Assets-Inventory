# scanner/discovery.py
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


DEFAULT_PROBE_PORTS = [80, 443, 22, 445, 3389]


def _tcp_probe(ip: str, port: int, timeout: float) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        res = sock.connect_ex((ip, port))
        sock.close()
        return res == 0
    except Exception:
        return False


def is_host_alive(ip: str, timeout: float = 0.5, probe_ports=None) -> bool:
    if probe_ports is None:
        probe_ports = DEFAULT_PROBE_PORTS

    # Si un seul port répond, on considère l’hôte “alive”
    for port in probe_ports:
        if _tcp_probe(ip, port, timeout):
            return True
    return False


def discover_hosts(ip_list: list[str], timeout: float = 0.5, max_threads: int = 200) -> list[str]:
    alive = []

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(is_host_alive, ip, timeout): ip for ip in ip_list}
        for f in as_completed(futures):
            ip = futures[f]
            try:
                if f.result():
                    alive.append(ip)
            except Exception:
                pass

    return sorted(alive)
