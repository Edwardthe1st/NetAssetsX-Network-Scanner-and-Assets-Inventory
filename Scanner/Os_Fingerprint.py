def guess_os(services: dict[int, dict]) -> dict:
    """
    OS fingerprint heuristique simple.
    """
    for svc in services.values():
        banner = svc.get("banner", "")
        if banner:
            if "Windows" in banner or "IIS" in banner:
                return {"name": "Windows-like", "confidence": 0.7}
            if "Linux" in banner or "OpenSSH" in banner:
                return {"name": "Linux-like", "confidence": 0.7}

    return {"name": "Unknown", "confidence": 0.3}
