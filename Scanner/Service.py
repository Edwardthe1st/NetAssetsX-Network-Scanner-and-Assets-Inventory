import socket


def grab_banner(ip: str, port: int, timeout: float = 1.0) -> str | None:
    try:
        sock = socket.socket()
        sock.settimeout(timeout)
        sock.connect((ip, port))
        banner = sock.recv(1024)
        sock.close()
        return banner.decode(errors="ignore").strip()
    except Exception:
        return None


def identify_services(ip: str, scan_results: dict[int, str]) -> dict[int, dict]:
    services = {}

    for port, state in scan_results.items():
        if state != "open":
            continue

        banner = grab_banner(ip, port)

        if port == 22:
            name = "ssh"
        elif port in (80, 8080):
            name = "http"
        elif port == 443:
            name = "https"
        elif port == 21:
            name = "ftp"
        else:
            name = "unknown"

        services[port] = {
            "service": name,
            "banner": banner
        }

    return services
