import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


def scan_port(ip: str, port: int, timeout: float) -> tuple[int, str]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()

        if result == 0:
            return port, "open"
        else:
            return port, "closed"

    except Exception:
        return port, "filtered"


def scan_ports(ip: str, ports: list[int], timeout: float = 1.0, max_threads: int = 200) -> dict[int, str]:
    results = {}

    if not ports:
        return results

    max_workers = min(max_threads, len(ports))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(scan_port, ip, port, timeout)
            for port in ports
        ]

        for future in as_completed(futures):
            port, state = future.result()
            results[port] = state

    return results
