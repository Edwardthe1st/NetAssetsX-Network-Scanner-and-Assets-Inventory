import errno
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


def _state_from_errno(code: int) -> tuple[str, str]:
    if code == 0:
        return "open", "connect-success"

    closed_codes = {errno.ECONNREFUSED}
    timeout_codes = {errno.ETIMEDOUT, errno.EHOSTUNREACH, errno.ENETUNREACH}

    if code in closed_codes:
        return "closed", "conn-refused"
    if code in timeout_codes:
        return "filtered", "no-response"

    return "filtered", f"errno-{code}"


def scan_port(ip: str, port: int, timeout: float) -> tuple[int, dict]:
    start = time.perf_counter()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        code = sock.connect_ex((ip, port))
        sock.close()
        state, reason = _state_from_errno(code)

        return port, {
            "state": state,
            "reason": reason,
            "error_code": code,
            "latency_ms": round((time.perf_counter() - start) * 1000, 2),
        }

    except Exception as exc:
        return port, {
            "state": "filtered",
            "reason": type(exc).__name__,
            "error_code": None,
            "latency_ms": round((time.perf_counter() - start) * 1000, 2),
        }


def scan_ports(ip: str, ports: list[int], timeout: float = 1.0, max_threads: int = 200) -> dict[int, dict]:
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
