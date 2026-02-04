import socket

from Scanner.Enrich import fetch_http_headers, get_tls_cert_info


HTTP_PORTS = {80, 8080, 8000, 8008, 8081, 8888}
TLS_PORTS = {443, 8443, 9443, 10443}


def grab_banner(ip: str, port: int, timeout: float = 1.0) -> str | None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        banner = sock.recv(1024)
        sock.close()
        return banner.decode(errors="ignore").strip()
    except Exception:
        return None


def _guess_service_name(port: int) -> str:
    if port in HTTP_PORTS:
        return "http"
    if port in TLS_PORTS:
        return "https"
    try:
        return socket.getservbyport(port)
    except Exception:
        return "unknown"


def identify_services(
    ip: str,
    scan_results: dict[int, str],
    banner_timeout: float = 1.0,
    http_timeout: float = 2.0,
    tls_timeout: float = 2.0,
    server_name: str | None = None,
    enable_http: bool = True,
    enable_tls: bool = True,
) -> dict[int, dict]:
    services: dict[int, dict] = {}

    for port, state in scan_results.items():
        if state != "open":
            continue

        name = _guess_service_name(port)
        banner = None
        http_info = None
        tls_info = None

        is_http = name in ("http", "https") or port in HTTP_PORTS or port in TLS_PORTS
        is_tls = name == "https" or port in TLS_PORTS

        if is_http and enable_http:
            http_info = fetch_http_headers(
                ip,
                port,
                use_tls=is_tls,
                timeout=http_timeout,
                server_name=server_name,
            )
        if is_tls and enable_tls:
            tls_info = get_tls_cert_info(
                ip,
                port,
                timeout=tls_timeout,
                server_name=server_name,
            )
        if not is_http:
            banner = grab_banner(ip, port, timeout=banner_timeout)

        services[port] = {
            "service": name,
            "banner": banner,
            "http": http_info,
            "tls": tls_info,
        }

    return services
