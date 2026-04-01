"""
Simulated Security Audit Tools.

Each tool reads from the scenario's ground truth data and returns
realistic-looking text output. No real network scanning occurs.
"""

from typing import Any, Dict, List, Optional, Tuple


TOOL_DEFINITIONS = [
    {
        "name": "network_scan",
        "description": "Discover hosts and open ports on a target network or host. Similar to nmap.",
        "parameters": {"target": "IP address or CIDR range (e.g., '10.0.1.0/24' or '10.0.1.10')"},
    },
    {
        "name": "service_fingerprint",
        "description": "Get detailed service version information for a specific host and port.",
        "parameters": {"host": "Target IP address", "port": "(optional) Specific port number"},
    },
    {
        "name": "web_crawl",
        "description": "Discover web endpoints and pages on a host's HTTP/HTTPS service.",
        "parameters": {"host": "Target IP address"},
    },
    {
        "name": "vulnerability_scan",
        "description": "Check a host's services against known CVE databases for vulnerable versions.",
        "parameters": {"host": "Target IP address"},
    },
    {
        "name": "test_injection",
        "description": "Test a web endpoint for injection vulnerabilities (SQL injection, command injection, SSRF, SSTI).",
        "parameters": {"host": "Target IP address", "endpoint": "URL path to test (e.g., '/api/login')"},
    },
    {
        "name": "test_xss",
        "description": "Test a web endpoint for Cross-Site Scripting (XSS) vulnerabilities.",
        "parameters": {"host": "Target IP address", "endpoint": "URL path to test"},
    },
    {
        "name": "test_auth",
        "description": "Test authentication and access controls — default credentials, IDOR, brute force, session management.",
        "parameters": {"host": "Target IP address", "endpoint": "(optional) Specific endpoint to test"},
    },
    {
        "name": "test_config",
        "description": "Check for security misconfigurations — exposed admin panels, directory listing, debug mode, open services.",
        "parameters": {"host": "Target IP address"},
    },
    {
        "name": "test_crypto",
        "description": "Analyze TLS/SSL configuration and cryptographic implementations.",
        "parameters": {"host": "Target IP address"},
    },
    {
        "name": "check_secrets",
        "description": "Scan for exposed secrets, API keys, credentials in accessible files and responses.",
        "parameters": {"host": "Target IP address", "endpoint": "(optional) Specific endpoint to check"},
    },
]


def execute_tool(
    tool_name: str,
    arguments: Dict[str, Any],
    scenario: Dict[str, Any],
    discovered_hosts: List[str],
    discovered_ports: Dict[str, List[int]],
) -> Tuple[str, List[str], Dict[str, List[int]], float]:
    """Execute a simulated tool and return (output, new_hosts, new_ports, reward)."""

    handler = TOOL_HANDLERS.get(tool_name)
    if not handler:
        return (f"Error: Unknown tool '{tool_name}'. Use list_tools to see available tools.", [], {}, -0.05)

    return handler(arguments, scenario, discovered_hosts, discovered_ports)


def _network_scan(
    args: Dict[str, Any],
    scenario: Dict[str, Any],
    discovered_hosts: List[str],
    discovered_ports: Dict[str, List[int]],
) -> Tuple[str, List[str], Dict[str, List[int]], float]:
    target = args.get("target", scenario.get("target_network", ""))
    hosts = scenario.get("hosts", {})
    ports = scenario.get("ports", {})

    lines = [f"Starting network scan on {target}...", ""]
    new_hosts = []
    new_ports: Dict[str, List[int]] = {}
    reward = 0.0

    for ip, host_info in hosts.items():
        host_ports = ports.get(ip, [])
        lines.append(f"Host: {ip} ({host_info['hostname']})")
        lines.append(f"  OS: {host_info['os']}")
        lines.append(f"  Role: {host_info['role']}")
        lines.append(f"  PORT     STATE  SERVICE        VERSION")

        port_nums = []
        for p in host_ports:
            lines.append(
                f"  {p['port']}/tcp  {p['state']}   {p['service']:14s} {p['version']}"
            )
            port_nums.append(p["port"])

        lines.append("")

        if ip not in discovered_hosts:
            new_hosts.append(ip)
            reward += 0.05

        current_known = set(discovered_ports.get(ip, []))
        new_port_nums = [p for p in port_nums if p not in current_known]
        if new_port_nums:
            new_ports[ip] = new_port_nums
            reward += len(new_port_nums) * 0.02

    lines.append(f"Scan complete. {len(hosts)} host(s) found.")
    return "\n".join(lines), new_hosts, new_ports, reward


def _service_fingerprint(
    args: Dict[str, Any],
    scenario: Dict[str, Any],
    discovered_hosts: List[str],
    discovered_ports: Dict[str, List[int]],
) -> Tuple[str, List[str], Dict[str, List[int]], float]:
    host = args.get("host", "")
    target_port = args.get("port")

    if host not in scenario.get("hosts", {}):
        return (f"Error: Host {host} not reachable. Run network_scan first to discover hosts.", [], {}, -0.02)

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
        lines.append("")

    return "\n".join(lines), [], {}, 0.01


def _web_crawl(
    args: Dict[str, Any],
    scenario: Dict[str, Any],
    discovered_hosts: List[str],
    discovered_ports: Dict[str, List[int]],
) -> Tuple[str, List[str], Dict[str, List[int]], float]:
    host = args.get("host", "")

    endpoints = scenario.get("web_endpoints", {}).get(host, [])
    if not endpoints:
        return (f"No web endpoints found on {host}. Host may not run a web server.", [], {}, 0.0)

    lines = [f"Web crawl results for {host}:", ""]
    for ep in endpoints:
        params = ""
        if ep.get("params"):
            params = f" (params: {', '.join(ep['params'])})"
        lines.append(f"  {ep['method']:6s} {ep['path']:30s} — {ep['description']}{params}")

    lines.append(f"\n{len(endpoints)} endpoint(s) discovered.")
    return "\n".join(lines), [], {}, 0.03


def _vulnerability_scan(
    args: Dict[str, Any],
    scenario: Dict[str, Any],
    discovered_hosts: List[str],
    discovered_ports: Dict[str, List[int]],
) -> Tuple[str, List[str], Dict[str, List[int]], float]:
    host = args.get("host", "")
    ports = scenario.get("ports", {}).get(host, [])

    if not ports:
        return (f"Error: No services known for {host}. Run network_scan first.", [], {}, -0.02)

    lines = [f"Vulnerability scan for {host}:", ""]
    vulns = [v for v in scenario.get("vulnerabilities", []) if v["host"] == host and "vulnerability_scan" in v.get("discoverable_by", [])]

    reported_vulns = set()
    for p in ports:
        lines.append(f"  {p['service']} {p['version']} on port {p['port']}:")
        found_any = False
        for v in vulns:
            if v["id"] not in reported_vulns:
                lines.append(f"    [!] VULNERABLE: {v['type']} (CVSS {v['cvss']}) — {v['cwe']}")
                reported_vulns.add(v["id"])
                found_any = True
        if not found_any:
            lines.append(f"    No known CVEs for this version.")
        lines.append("")

    reward = 0.05 if vulns else 0.01
    return "\n".join(lines), [], {}, reward


def _test_injection(
    args: Dict[str, Any],
    scenario: Dict[str, Any],
    discovered_hosts: List[str],
    discovered_ports: Dict[str, List[int]],
) -> Tuple[str, List[str], Dict[str, List[int]], float]:
    host = args.get("host", "")
    endpoint = args.get("endpoint", "")

    vulns = [
        v for v in scenario.get("vulnerabilities", [])
        if v["host"] == host
        and v.get("endpoint") == endpoint
        and "test_injection" in v.get("discoverable_by", [])
    ]

    if vulns:
        lines = [f"Injection testing on {host}{endpoint}:", ""]
        for v in vulns:
            lines.extend([
                f"  [CRITICAL] {v['type']} DETECTED",
                f"  CWE: {v['cwe']}",
                f"  OWASP: {v['owasp']}",
                f"  Evidence: {v['evidence']}",
                f"  Suggested CVSS: {v['cvss']}",
                f"  Suggested Severity: {v['severity']}",
                "",
            ])
        return "\n".join(lines), [], {}, 0.08
    else:
        return f"Injection testing on {host}{endpoint}: No injection vulnerabilities detected.", [], {}, 0.01


def _test_xss(
    args: Dict[str, Any],
    scenario: Dict[str, Any],
    discovered_hosts: List[str],
    discovered_ports: Dict[str, List[int]],
) -> Tuple[str, List[str], Dict[str, List[int]], float]:
    host = args.get("host", "")
    endpoint = args.get("endpoint", "")

    vulns = [
        v for v in scenario.get("vulnerabilities", [])
        if v["host"] == host
        and v.get("endpoint") == endpoint
        and "test_xss" in v.get("discoverable_by", [])
    ]

    if vulns:
        lines = [f"XSS testing on {host}{endpoint}:", ""]
        for v in vulns:
            lines.extend([
                f"  [WARNING] {v['type']} DETECTED",
                f"  CWE: {v['cwe']}",
                f"  OWASP: {v['owasp']}",
                f"  Evidence: {v['evidence']}",
                f"  Suggested CVSS: {v['cvss']}",
                f"  Suggested Severity: {v['severity']}",
                "",
            ])
        return "\n".join(lines), [], {}, 0.08
    else:
        return f"XSS testing on {host}{endpoint}: No XSS vulnerabilities detected.", [], {}, 0.01


def _test_auth(
    args: Dict[str, Any],
    scenario: Dict[str, Any],
    discovered_hosts: List[str],
    discovered_ports: Dict[str, List[int]],
) -> Tuple[str, List[str], Dict[str, List[int]], float]:
    host = args.get("host", "")
    endpoint = args.get("endpoint")

    vulns = [
        v for v in scenario.get("vulnerabilities", [])
        if v["host"] == host
        and "test_auth" in v.get("discoverable_by", [])
        and (endpoint is None or v.get("endpoint") is None or v.get("endpoint") == endpoint)
    ]

    if vulns:
        lines = [f"Authentication & access control testing on {host}" + (f"{endpoint}" if endpoint else "") + ":", ""]
        for v in vulns:
            lines.extend([
                f"  [ALERT] {v['type']} DETECTED",
                f"  CWE: {v['cwe']}",
                f"  OWASP: {v['owasp']}",
                f"  Evidence: {v['evidence']}",
                f"  Suggested CVSS: {v['cvss']}",
                f"  Suggested Severity: {v['severity']}",
                "",
            ])
        return "\n".join(lines), [], {}, 0.08
    else:
        target_desc = f"{host}{endpoint}" if endpoint else host
        return f"Auth testing on {target_desc}: Authentication and access controls appear properly configured.", [], {}, 0.01


def _test_config(
    args: Dict[str, Any],
    scenario: Dict[str, Any],
    discovered_hosts: List[str],
    discovered_ports: Dict[str, List[int]],
) -> Tuple[str, List[str], Dict[str, List[int]], float]:
    host = args.get("host", "")

    vulns = [
        v for v in scenario.get("vulnerabilities", [])
        if v["host"] == host
        and "test_config" in v.get("discoverable_by", [])
    ]

    if vulns:
        lines = [f"Configuration audit for {host}:", ""]
        for v in vulns:
            lines.extend([
                f"  [MISCONFIGURATION] {v['type']}",
                f"  CWE: {v['cwe']}",
                f"  OWASP: {v['owasp']}",
                f"  Evidence: {v['evidence']}",
                f"  Suggested CVSS: {v['cvss']}",
                f"  Suggested Severity: {v['severity']}",
                "",
            ])
        return "\n".join(lines), [], {}, 0.08
    else:
        return f"Configuration audit for {host}: No significant misconfigurations detected.", [], {}, 0.01


def _test_crypto(
    args: Dict[str, Any],
    scenario: Dict[str, Any],
    discovered_hosts: List[str],
    discovered_ports: Dict[str, List[int]],
) -> Tuple[str, List[str], Dict[str, List[int]], float]:
    host = args.get("host", "")

    vulns = [
        v for v in scenario.get("vulnerabilities", [])
        if v["host"] == host
        and "test_crypto" in v.get("discoverable_by", [])
    ]

    if vulns:
        lines = [f"Cryptographic analysis for {host}:", ""]
        for v in vulns:
            lines.extend([
                f"  [CRYPTO ISSUE] {v['type']}",
                f"  CWE: {v['cwe']}",
                f"  OWASP: {v['owasp']}",
                f"  Evidence: {v['evidence']}",
                f"  Suggested CVSS: {v['cvss']}",
                f"  Suggested Severity: {v['severity']}",
                "",
            ])
        return "\n".join(lines), [], {}, 0.06
    else:
        return f"Cryptographic analysis for {host}: TLS/SSL configuration appears secure.", [], {}, 0.01


def _check_secrets(
    args: Dict[str, Any],
    scenario: Dict[str, Any],
    discovered_hosts: List[str],
    discovered_ports: Dict[str, List[int]],
) -> Tuple[str, List[str], Dict[str, List[int]], float]:
    host = args.get("host", "")
    endpoint = args.get("endpoint")

    vulns = [
        v for v in scenario.get("vulnerabilities", [])
        if v["host"] == host
        and "check_secrets" in v.get("discoverable_by", [])
        and (endpoint is None or v.get("endpoint") is None or v.get("endpoint") == endpoint)
    ]

    if vulns:
        lines = [f"Secret scanning on {host}" + (f"{endpoint}" if endpoint else "") + ":", ""]
        for v in vulns:
            lines.extend([
                f"  [SECRET EXPOSED] {v['type']}",
                f"  CWE: {v['cwe']}",
                f"  OWASP: {v['owasp']}",
                f"  Evidence: {v['evidence']}",
                f"  Suggested CVSS: {v['cvss']}",
                f"  Suggested Severity: {v['severity']}",
                "",
            ])
        return "\n".join(lines), [], {}, 0.08
    else:
        target_desc = f"{host}{endpoint}" if endpoint else host
        return f"Secret scanning on {target_desc}: No exposed secrets detected.", [], {}, 0.01


TOOL_HANDLERS = {
    "network_scan": _network_scan,
    "service_fingerprint": _service_fingerprint,
    "web_crawl": _web_crawl,
    "vulnerability_scan": _vulnerability_scan,
    "test_injection": _test_injection,
    "test_xss": _test_xss,
    "test_auth": _test_auth,
    "test_config": _test_config,
    "test_crypto": _test_crypto,
    "check_secrets": _check_secrets,
}
