import socket
import re

from Scanner.Enrich import fetch_http_headers, get_tls_cert_info


HTTP_PORTS = {80, 8080, 8000, 8008, 8081, 8888}
TLS_PORTS = {443, 8443, 9443, 10443}
_OPENSSH_RE = re.compile(r"OpenSSH[_-]([0-9A-Za-z._-]+)")


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


def _is_open(state) -> bool:
    if isinstance(state, dict):
        return state.get("state") == "open"
    return state == "open"


def _first_header(headers: dict, key: str) -> str | None:
    value = headers.get(key)
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _version_from_banner(service_name: str, banner: str | None) -> str | None:
    if not banner:
        return None

    line = " ".join(banner.split())
    if not line:
        return None

    if service_name == "ssh":
        match = _OPENSSH_RE.search(line)
        if match:
            return f"OpenSSH {match.group(1)}"

    return line[:120]


def _version_from_http(http_info: dict | None) -> str | None:
    if not http_info:
        return None
    headers = http_info.get("headers") or {}
    server = _first_header(headers, "server")
    if server:
        return str(server)[:120]
    status = http_info.get("status_line")
    if status:
        return str(status)[:120]
    return None


def _version_from_tls(tls_info: dict | None) -> str | None:
    if not tls_info:
        return None
    parts = []
    if tls_info.get("cn"):
        parts.append(f"TLS cert: {tls_info['cn']}")
    if tls_info.get("version"):
        parts.append(f"({tls_info['version']})")
    if not parts:
        return None
    return " ".join(parts)[:120]


def identify_services(
    ip: str,
    scan_results: dict[int, dict],
    banner_timeout: float = 1.0,
    http_timeout: float = 2.0,
    tls_timeout: float = 2.0,
    server_name: str | None = None,
    enable_http: bool = True,
    enable_tls: bool = True,
) -> dict[int, dict]:
    services: dict[int, dict] = {}

    for port, state in scan_results.items():
        if not _is_open(state):
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

        version = (
            _version_from_http(http_info)
            or _version_from_banner(name, banner)
            or _version_from_tls(tls_info)
        )

        services[port] = {
            "service": name,
            "banner": banner,
            "http": http_info,
            "tls": tls_info,
            "version": version,
        }

    return services
