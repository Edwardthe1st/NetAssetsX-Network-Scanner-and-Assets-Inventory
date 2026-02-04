import re
import socket
import ssl
import subprocess
import sys
import shutil
from concurrent.futures import ThreadPoolExecutor


_MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")


def reverse_dns(ip: str, timeout: float = 1.0) -> str | None:
    def _lookup() -> str | None:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None

    if timeout <= 0:
        return _lookup()

    with ThreadPoolExecutor(max_workers=1) as executor:
        fut = executor.submit(_lookup)
        try:
            return fut.result(timeout=timeout)
        except Exception:
            return None


def get_mac_from_arp(ip: str, timeout: float = 1.0) -> str | None:
    if not shutil.which("arp"):
        return None

    if sys.platform.startswith("win"):
        cmd = ["arp", "-a", ip]
    else:
        cmd = ["arp", "-a", ip]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except Exception:
        return None

    output = (result.stdout or "") + "\n" + (result.stderr or "")
    match = _MAC_RE.search(output)
    if not match:
        return None
    mac = match.group(0).lower().replace("-", ":")
    return mac


def fetch_http_headers(
    ip: str,
    port: int,
    use_tls: bool = False,
    timeout: float = 2.0,
    server_name: str | None = None,
) -> dict | None:
    request = (
        f"HEAD / HTTP/1.1\r\n"
        f"Host: {server_name or ip}\r\n"
        f"User-Agent: NetAssetX\r\n"
        f"Connection: close\r\n\r\n"
    )

    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        if use_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=server_name or ip)

        sock.settimeout(timeout)
        sock.sendall(request.encode("ascii", errors="ignore"))

        data = b""
        while b"\r\n\r\n" not in data and len(data) < 16384:
            chunk = sock.recv(1024)
            if not chunk:
                break
            data += chunk

        sock.close()
    except Exception:
        return None

    if not data:
        return None

    text = data.decode("iso-8859-1", errors="ignore")
    lines = text.split("\r\n")
    if not lines:
        return None

    status_line = lines[0].strip()
    headers: dict[str, str | list[str]] = {}
    for line in lines[1:]:
        if not line:
            break
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key in headers:
            existing = headers[key]
            if isinstance(existing, list):
                existing.append(value)
            else:
                headers[key] = [existing, value]
        else:
            headers[key] = value

    return {
        "status_line": status_line,
        "headers": headers,
    }


def _extract_cn(dn) -> str | None:
    for attrs in dn or []:
        for key, value in attrs:
            if key == "commonName":
                return value
    return None


def get_tls_cert_info(
    ip: str,
    port: int,
    timeout: float = 2.0,
    server_name: str | None = None,
) -> dict | None:
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=server_name or ip) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return None

                san = [
                    name for kind, name in cert.get("subjectAltName", [])
                    if kind in ("DNS", "IP Address")
                ]

                cipher = ssock.cipher()
                return {
                    "cn": _extract_cn(cert.get("subject")),
                    "issuer_cn": _extract_cn(cert.get("issuer")),
                    "san": san,
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "version": ssock.version(),
                    "cipher": cipher[0] if cipher else None,
                }
    except Exception:
        return None
