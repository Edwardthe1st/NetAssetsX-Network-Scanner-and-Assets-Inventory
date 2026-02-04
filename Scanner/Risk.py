def score_risk(open_ports: list[int]) -> dict:
    score = 0
    reasons = []

    if 21 in open_ports:
        score += 3
        reasons.append("FTP exposé")

    if 23 in open_ports:
        score += 5
        reasons.append("Telnet exposé")

    if 80 in open_ports and 443 not in open_ports:
        score += 2
        reasons.append("HTTP sans HTTPS")

    if 22 in open_ports:
        score += 1
        reasons.append("SSH exposé")

    if 445 in open_ports:
        score += 3
        reasons.append("SMB exposé")

    if 3389 in open_ports:
        score += 3
        reasons.append("RDP exposé")

    if score >= 6:
        level = "high"
    elif score >= 3:
        level = "medium"
    else:
        level = "low"

    return {
        "score": score,
        "level": level,
        "reasons": reasons
    }
