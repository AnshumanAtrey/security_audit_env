"""
Network-layer tool handlers: network_scan, service_fingerprint, vulnerability_scan.

Reads from the scenario's ground-truth host/port/vuln data and generates
realistic nmap-style output.  Hidden-host logic and progressive discovery
are preserved from the original tools.py.
"""

from typing import Any, Dict, List, Optional, Set, Tuple

from .formatters import format_port_table, format_tool_output, _map_vuln_to_type, _get_sample_payload


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _filter_by_chain(vulns: List[Dict], discovered_vulns: Optional[Set[str]]) -> List[Dict]:
    """Filter vulnerabilities by chain prerequisites."""
    if discovered_vulns is None:
        discovered_vulns = set()
    return [
        v for v in vulns
        if not v.get("requires_found") or all(r in discovered_vulns for r in v["requires_found"])
    ]


def _normalize_difficulty(scenario: Dict[str, Any]) -> str:
    """Extract difficulty tier from scenario ID."""
    sid = scenario.get("id", "easy")
    if "easy" in sid:
        return "easy"
    elif "medium" in sid:
        return "medium"
    elif "hard" in sid:
        return "hard"
    return "easy"


# ---------------------------------------------------------------------------
# network_scan
# ---------------------------------------------------------------------------

def handle_network_scan(
    args: Dict[str, Any],
    scenario: Dict[str, Any],
    discovered_hosts: List[str],
    discovered_ports: Dict[str, List[int]],
    discovered_vulns: Optional[Set[str]] = None,
) -> Tuple[str, List[str], Dict[str, List[int]], float]:
    """Discover hosts and ports.  Generate nmap-style output from scenario data."""
    target = args.get("target", scenario.get("target_network", ""))
    all_hosts = scenario.get("hosts", {})
    ports = scenario.get("ports", {})
    dv = discovered_vulns or set()

    # Progressive discovery: filter out hidden hosts whose prereqs aren't met
    hosts: Dict[str, Any] = {}
    hidden_count = 0
    for ip, info in all_hosts.items():
        required = info.get("hidden_until", [])
        if not required or all(r in dv for r in required):
            hosts[ip] = info
        else:
            hidden_count += 1

    difficulty = _normalize_difficulty(scenario)
    total_ports = 0
    lines = [
        f"Starting Nmap 7.94 scan on {target}",
        f"Nmap scan report -- {len(hosts)} host(s) responding",
        "",
    ]
    new_hosts: List[str] = []
    new_ports: Dict[str, List[int]] = {}
    reward = 0.0

    for ip, host_info in hosts.items():
        host_ports = ports.get(ip, [])
        lines.extend(format_port_table(ip, host_info, host_ports, difficulty))
        total_ports += len(host_ports)

        port_nums = [p["port"] for p in host_ports]

        if ip not in discovered_hosts:
            new_hosts.append(ip)
            reward += 0.05

        current_known = set(discovered_ports.get(ip, []))
        new_port_nums = [p for p in port_nums if p not in current_known]
        if new_port_nums:
            new_ports[ip] = new_port_nums
            reward += len(new_port_nums) * 0.02

    lines.append(f"Nmap done: {len(hosts)} IP addresses ({len(hosts)} hosts up) scanned")
    lines.append(f"  {total_ports} open ports found across {len(hosts)} hosts")
    if hidden_count > 0:
        lines.append(
            f"  Note: {hidden_count} host(s) may exist on internal segments not directly "
            f"reachable. Pivot through compromised hosts to discover them."
        )
    return "\n".join(lines), new_hosts, new_ports, reward


# ---------------------------------------------------------------------------
# service_fingerprint
# ---------------------------------------------------------------------------

def handle_service_fingerprint(
    args: Dict[str, Any],
    scenario: Dict[str, Any],
    discovered_hosts: List[str],
    discovered_ports: Dict[str, List[int]],
    discovered_vulns: Optional[Set[str]] = None,
) -> Tuple[str, List[str], Dict[str, List[int]], float]:
    """Get detailed service version information for a specific host and port."""
    host = args.get("host", "")
    target_port = args.get("port")
    dv = discovered_vulns or set()

    host_info_raw = scenario.get("hosts", {}).get(host)
    if not host_info_raw:
        return (f"Error: Host {host} not reachable. Run network_scan first.", [], {}, -0.02)
    required = host_info_raw.get("hidden_until", [])
    if required and not all(r in dv for r in required):
        return (f"Error: Host {host} not reachable. It may be on an internal network segment.", [], {}, -0.02)

    ports = scenario.get("ports", {}).get(host, [])
    host_info = scenario["hosts"][host]
    lines = [f"Service fingerprint for {host} ({host_info['hostname']})", ""]

    for p in ports:
        if target_port and p["port"] != int(target_port):
            continue
        lines.append(f"Port {p['port']}/tcp:")
        lines.append(f"  Service: {p['service']}")
        lines.append(f"  Version: {p['version']}")
        lines.append(f"  State: {p['state']}")
        lines.append(f"  Protocol: TCP")
        lines.append("")

    return "\n".join(lines), [], {}, 0.01


# ---------------------------------------------------------------------------
# vulnerability_scan
# ---------------------------------------------------------------------------

def handle_vulnerability_scan(
    args: Dict[str, Any],
    scenario: Dict[str, Any],
    discovered_hosts: List[str],
    discovered_ports: Dict[str, List[int]],
    discovered_vulns: Optional[Set[str]] = None,
) -> Tuple[str, List[str], Dict[str, List[int]], float]:
    """Check a host's services against known CVE databases."""
    host = args.get("host", "")
    ports = scenario.get("ports", {}).get(host, [])

    if not ports:
        return (f"Error: No services known for {host}. Run network_scan first.", [], {}, -0.02)

    vulns = [
        v for v in scenario.get("vulnerabilities", [])
        if v["host"] == host and "vulnerability_scan" in v.get("discoverable_by", [])
    ]
    vulns = _filter_by_chain(vulns, discovered_vulns)
    difficulty = _normalize_difficulty(scenario)

    lines = [f"Vulnerability scan for {host}:", ""]
    reported: set = set()
    for p in ports:
        lines.append(f"  {p['service']} {p['version']} on port {p['port']}:")
        found_any = False
        for v in vulns:
            if v["id"] not in reported:
                if difficulty == "easy":
                    lines.append(f"    [!] VULNERABLE: {v['type']} (CVSS {v['cvss']}) -- {v['cwe']}")
                    lines.append(f"        Confidence: High | Source: NVD/OWASP")
                    lines.append(f"        Remediation: {v['remediation']}")
                else:
                    # Use KB templates for medium/hard
                    vuln_type_id = _map_vuln_to_type(v)
                    context = {
                        "host": host,
                        "endpoint": v.get("endpoint", ""),
                        "parameter": "multiple",
                        "payload": _get_sample_payload(vuln_type_id),
                        "cvss": str(v.get("cvss", 0)),
                        "cwe": v.get("cwe", ""),
                        "severity": v.get("severity", ""),
                        "owasp": v.get("owasp", ""),
                        "evidence_detail": v.get("evidence", ""),
                        "remediation": v.get("remediation", ""),
                        "service_version": p.get("version", ""),
                        "port": str(p.get("port", "")),
                    }
                    try:
                        rendered = format_tool_output(v, difficulty, context)
                        lines.append(rendered)
                    except Exception:
                        # Fallback: generic CVE-style output
                        lines.append(f"    NVD match for {p['version']}")
                        lines.append(f"    See output details for assessment.")
                reported.add(v["id"])
                found_any = True
        if not found_any:
            lines.append(f"    No known CVEs for {p['version']} (database current)")
        lines.append("")

    reward = 0.05 if vulns else 0.01
    return "\n".join(lines), [], {}, reward
