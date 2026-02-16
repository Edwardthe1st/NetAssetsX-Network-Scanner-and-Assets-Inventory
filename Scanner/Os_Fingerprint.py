def guess_os(services: dict[int, dict]) -> dict:
    """
    OS fingerprint heuristique simple.
    """
    for svc in services.values():
        banner = svc.get("banner", "")
        version = svc.get("version", "")
        tls = svc.get("tls") or {}
        cn = tls.get("cn", "")

        if banner:
            if "Windows" in banner or "IIS" in banner:
                return {"name": "Windows-like", "confidence": 0.7}
            if "Linux" in banner or "OpenSSH" in banner:
                return {"name": "Linux-like", "confidence": 0.7}
        if version:
            if any(token in version for token in ("Microsoft", "WinRM", "IIS")):
                return {"name": "Windows-like", "confidence": 0.65}
            if any(token in version for token in ("Ubuntu", "Debian", "CentOS", "OpenSSH")):
                return {"name": "Linux-like", "confidence": 0.65}
        if cn and ".local" in cn:
            return {"name": "Likely Unix-like", "confidence": 0.4}

    return {"name": "Unknown", "confidence": 0.3}
