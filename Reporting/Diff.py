import json


def diff_scans(file_a: str, file_b: str) -> dict:
    with open(file_a) as f:
        a = json.load(f)

    with open(file_b) as f:
        b = json.load(f)

    ips_a = {h["ip"] for h in a["hosts"]}
    ips_b = {h["ip"] for h in b["hosts"]}

    return {
        "new_hosts": list(ips_b - ips_a),
        "removed_hosts": list(ips_a - ips_b)
    }
