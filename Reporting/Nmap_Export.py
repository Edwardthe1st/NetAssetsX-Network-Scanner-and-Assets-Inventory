from datetime import datetime


def _host_label(host: dict) -> str:
    ip = host.get("ip", "unknown")
    rdns = host.get("reverse_dns")
    if rdns:
        return f"{rdns} ({ip})"
    return ip


def _state_counts(port_states: dict[int, dict]) -> dict[str, int]:
    counts = {"open": 0, "closed": 0, "filtered": 0, "unknown": 0}
    for info in port_states.values():
        state = info.get("state", "unknown")
        if state not in counts:
            state = "unknown"
        counts[state] += 1
    return counts


def _format_port_line(
    port: int,
    port_info: dict,
    service_info: dict | None,
    show_reasons: bool,
) -> str:
    state = (port_info or {}).get("state", "unknown")
    reason = (port_info or {}).get("reason", "")
    service = (service_info or {}).get("service", "unknown")
    version = (service_info or {}).get("version", "") or ""

    if show_reasons:
        return f"{f'{port}/tcp':<10}{state:<10}{reason:<18}{service:<12}{version}"
    return f"{f'{port}/tcp':<10}{state:<10}{service:<12}{version}"


def render_nmap_output(
    scan_result: dict,
    show_closed: bool = False,
    show_reasons: bool = False,
) -> str:
    metadata = scan_result.get("metadata", {})
    hosts = scan_result.get("hosts", [])

    started = metadata.get("scan_started_human")
    if not started:
        started = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = [f"Starting NetAssetX (Nmap-like) at {started}", ""]

    for host in hosts:
        lines.append(f"Nmap scan report for {_host_label(host)}")
        latency_ms = host.get("latency_ms")
        if latency_ms is not None:
            lines.append(f"Host is up ({latency_ms / 1000:.4f}s latency).")
        else:
            lines.append("Host is up.")

        port_states = host.get("port_states", {})
        services = host.get("services", {})
        counts = _state_counts(port_states)

        if not show_closed:
            hidden_chunks = []
            if counts["closed"] > 0:
                hidden_chunks.append(f"{counts['closed']} closed tcp ports")
            if counts["filtered"] > 0:
                hidden_chunks.append(f"{counts['filtered']} filtered tcp ports")
            if counts["unknown"] > 0:
                hidden_chunks.append(f"{counts['unknown']} unknown tcp ports")
            if hidden_chunks:
                lines.append("Not shown: " + ", ".join(hidden_chunks))

        if show_reasons:
            lines.append(f"{'PORT':<10}{'STATE':<10}{'REASON':<18}{'SERVICE':<12}VERSION")
        else:
            lines.append(f"{'PORT':<10}{'STATE':<10}{'SERVICE':<12}VERSION")

        visible_rows = 0
        for port in sorted(port_states.keys()):
            pinfo = port_states.get(port, {})
            state = pinfo.get("state")
            if not show_closed and state != "open":
                continue
            lines.append(_format_port_line(port, pinfo, services.get(port), show_reasons))
            visible_rows += 1

        if visible_rows == 0:
            lines.append("No open ports found.")

        if host.get("mac"):
            lines.append(f"MAC Address: {host['mac']}")

        os_info = host.get("os") or {}
        lines.append(
            f"OS details: {os_info.get('name', 'Unknown')} "
            f"(confidence {os_info.get('confidence', 0):.2f})"
        )

        risk = host.get("risk") or {}
        reasons = ", ".join(risk.get("reasons", []))
        if reasons:
            lines.append(
                f"Risk: {risk.get('level', 'unknown')} (score {risk.get('score', 0)}) [{reasons}]"
            )
        else:
            lines.append(
                f"Risk: {risk.get('level', 'unknown')} (score {risk.get('score', 0)})"
            )

        lines.append("")

    duration = metadata.get("duration_seconds")
    if duration is None:
        lines.append(
            f"Nmap done: {metadata.get('total_ips', 0)} IP addresses "
            f"({metadata.get('hosts_up', len(hosts))} hosts up)"
        )
    else:
        lines.append(
            f"Nmap done: {metadata.get('total_ips', 0)} IP addresses "
            f"({metadata.get('hosts_up', len(hosts))} hosts up) scanned in {duration:.2f} seconds"
        )

    return "\n".join(lines).rstrip() + "\n"


def export_nmap(scan_result: dict, filename: str, show_closed: bool = False, show_reasons: bool = False):
    content = render_nmap_output(
        scan_result=scan_result,
        show_closed=show_closed,
        show_reasons=show_reasons,
    )
    with open(filename, "w") as f:
        f.write(content)
