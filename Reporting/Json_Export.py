import json


def export_json(scan_result: dict, filename: str):
    with open(filename, "w") as f:
        json.dump(scan_result, f, indent=4)
