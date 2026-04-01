"""
Simulated Security Audit Tools.

Each tool reads from the scenario's ground truth data and returns
realistic-looking text output. No real network scanning occurs.
All outputs are deterministic — same inputs always produce same results.
"""

from typing import Any, Dict, List, Optional, Set, Tuple


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


def _filter_by_chain(vulns: List[Dict], discovered_vulns: Optional[Set[str]]) -> List[Dict]:
    """Filter vulnerabilities by chain prerequisites.

    A vuln is visible if it has no requires_found field,
    or all prerequisites are in discovered_vulns.
    """
    if discovered_vulns is None:
        discovered_vulns = set()
    return [
        v for v in vulns
        if not v.get("requires_found") or all(r in discovered_vulns for r in v["requires_found"])
    ]


_PORT_WARNINGS = {
    3306: "WARNING: MySQL accessible externally — verify firewall rules",
    5432: "WARNING: PostgreSQL accessible externally — restrict to app IPs",
    21: "WARNING: FTP (plaintext protocol) detected — consider SFTP",
    445: "NOTE: SMB file sharing detected — verify access controls",
    3389: "NOTE: RDP exposed — ensure strong credentials and NLA",
}


def execute_tool(
    tool_name: str,
    arguments: Dict[str, Any],
    scenario: Dict[str, Any],
    discovered_hosts: List[str],
    discovered_ports: Dict[str, List[int]],
    discovered_vulns: Optional[Set[str]] = None,
) -> Tuple[str, List[str], Dict[str, List[int]], float]:
    """Execute a simulated tool and return (output, new_hosts, new_ports, reward)."""
    handler = TOOL_HANDLERS.get(tool_name)
    if not handler:
        return (f"Error: Unknown tool '{tool_name}'. Use list_tools to see available tools.", [], {}, -0.05)
    return handler(arguments, scenario, discovered_hosts, discovered_ports, discovered_vulns)


def _network_scan(args, scenario, discovered_hosts, discovered_ports, discovered_vulns):
    target = args.get("target", scenario.get("target_network", ""))
    all_hosts = scenario.get("hosts", {})
    ports = scenario.get("ports", {})
    dv = discovered_vulns or set()

    # Progressive discovery: filter out hidden hosts whose prereqs aren't met
    hosts = {}
    hidden_count = 0
    for ip, info in all_hosts.items():
        required = info.get("hidden_until", [])
        if not required or all(r in dv for r in required):
            hosts[ip] = info
        else:
            hidden_count += 1

    total_ports = 0
    lines = [
        f"Starting Nmap 7.94 scan on {target}",
        f"Nmap scan report — {len(hosts)} host(s) responding",
        "",
    ]
    new_hosts = []
    new_ports: Dict[str, List[int]] = {}
    reward = 0.0

    for ip, host_info in hosts.items():
        host_ports = ports.get(ip, [])
        lines.append(f"Nmap scan report for {ip} ({host_info['hostname']})")
        lines.append(f"  OS Detection: {host_info['os']}")
        lines.append(f"  Device Role: {host_info['role']}")
        lines.append(f"  PORT      STATE  SERVICE         VERSION")

        port_nums = []
        for p in host_ports:
            lines.append(f"  {p['port']}/tcp   {p['state']:6s} {p['service']:15s} {p['version']}")
            port_nums.append(p["port"])
            total_ports += 1

            warning = _PORT_WARNINGS.get(p["port"])
            if warning:
                lines.append(f"  |_ {warning}")

            if "Jenkins" in p["version"]:
                lines.append(f"  |_ NOTE: Jenkins CI/CD server detected — check authentication")

        lines.append("")

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
        lines.append(f"  Note: {hidden_count} host(s) may exist on internal segments not directly reachable. Pivot through compromised hosts to discover them.")
    return "\n".join(lines), new_hosts, new_ports, reward


def _service_fingerprint(args, scenario, discovered_hosts, discovered_ports, discovered_vulns):
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


def _web_crawl(args, scenario, discovered_hosts, discovered_ports, discovered_vulns):
    host = args.get("host", "")
    dv = discovered_vulns or set()

    host_info_raw = scenario.get("hosts", {}).get(host)
    if host_info_raw:
        required = host_info_raw.get("hidden_until", [])
        if required and not all(r in dv for r in required):
            return (f"Error: Host {host} not reachable. It may be on an internal network segment.", [], {}, -0.02)

    endpoints = scenario.get("web_endpoints", {}).get(host, [])

    if not endpoints:
        return (f"No web endpoints found on {host}. Host may not run a web server.", [], {}, 0.0)

    lines = [f"Web crawl results for {host}:", f"  Discovered {len(endpoints)} endpoint(s):", ""]
    for ep in endpoints:
        params = ""
        if ep.get("params"):
            params = f" (params: {', '.join(ep['params'])})"
        lines.append(f"  {ep['method']:6s} {ep['path']:30s} — {ep['description']}{params}")

    lines.append(f"\n{len(endpoints)} endpoint(s) discovered. Test each for vulnerabilities.")
    return "\n".join(lines), [], {}, 0.03


def _vulnerability_scan(args, scenario, discovered_hosts, discovered_ports, discovered_vulns):
    host = args.get("host", "")
    ports = scenario.get("ports", {}).get(host, [])

    if not ports:
        return (f"Error: No services known for {host}. Run network_scan first.", [], {}, -0.02)

    vulns = [v for v in scenario.get("vulnerabilities", [])
             if v["host"] == host and "vulnerability_scan" in v.get("discoverable_by", [])]
    vulns = _filter_by_chain(vulns, discovered_vulns)

    lines = [f"Vulnerability scan for {host}:", ""]
    reported = set()
    for p in ports:
        lines.append(f"  {p['service']} {p['version']} on port {p['port']}:")
        found_any = False
        for v in vulns:
            if v["id"] not in reported:
                lines.append(f"    [!] VULNERABLE: {v['type']} (CVSS {v['cvss']}) — {v['cwe']}")
                lines.append(f"        Confidence: High | Source: NVD/OWASP")
                lines.append(f"        Remediation: {v['remediation']}")
                reported.add(v["id"])
                found_any = True
        if not found_any:
            lines.append(f"    No known CVEs for {p['version']} (database current)")
        lines.append("")

    reward = 0.05 if vulns else 0.01
    return "\n".join(lines), [], {}, reward


def _test_injection(args, scenario, discovered_hosts, discovered_ports, discovered_vulns):
    host = args.get("host", "")
    endpoint = args.get("endpoint", "")

    vulns = [
        v for v in scenario.get("vulnerabilities", [])
        if v["host"] == host
        and v.get("endpoint") == endpoint
        and "test_injection" in v.get("discoverable_by", [])
    ]
    vulns = _filter_by_chain(vulns, discovered_vulns)

    if vulns:
        lines = [f"Injection testing on {host}{endpoint}:", ""]
        for v in vulns:
            payload = {"SQL Injection": "' OR 1=1--", "SSRF": "http://169.254.169.254/latest/meta-data/",
                       "SSTI": "{{7*7}}", "Business Logic": "concurrent request replay"}.get(
                v["type"].split("(")[0].strip(), "fuzz pattern set A-F")
            lines.extend([
                f"  [CRITICAL] {v['type']} DETECTED",
                f"  CWE: {v['cwe']}",
                f"  OWASP: {v['owasp']}",
                f"  Exploitation Steps:",
                f"    1. Identified injectable parameter in {endpoint}",
                f"    2. Confirmed with payload: {payload}",
                f"    3. Verified server response indicates vulnerability",
                f"  Evidence: {v['evidence']}",
                f"  Suggested CVSS: {v['cvss']} ({v['severity']})",
                f"  Remediation: {v['remediation']}",
                "",
            ])
        return "\n".join(lines), [], {}, 0.08
    else:
        return (f"Injection testing on {host}{endpoint}:\n"
                f"  Tested: SQLi (error-based, blind, time-based), command injection, SSTI, SSRF\n"
                f"  Payloads: 47 injection patterns tested\n"
                f"  Result: No injection vulnerabilities detected on this endpoint."), [], {}, 0.01


def _test_xss(args, scenario, discovered_hosts, discovered_ports, discovered_vulns):
    host = args.get("host", "")
    endpoint = args.get("endpoint", "")

    vulns = [
        v for v in scenario.get("vulnerabilities", [])
        if v["host"] == host
        and v.get("endpoint") == endpoint
        and "test_xss" in v.get("discoverable_by", [])
    ]
    vulns = _filter_by_chain(vulns, discovered_vulns)

    if vulns:
        lines = [f"XSS testing on {host}{endpoint}:", ""]
        for v in vulns:
            lines.extend([
                f"  [{v['severity'].upper()}] {v['type']} DETECTED",
                f"  CWE: {v['cwe']}",
                f"  OWASP: {v['owasp']}",
                f"  Evidence: {v['evidence']}",
                f"  Suggested CVSS: {v['cvss']} ({v['severity']})",
                f"  Remediation: {v['remediation']}",
                "",
            ])
        return "\n".join(lines), [], {}, 0.08
    else:
        return (f"XSS testing on {host}{endpoint}:\n"
                f"  Tested: reflected XSS, stored XSS, DOM-based XSS\n"
                f"  Payloads: 23 XSS vectors tested across all parameters\n"
                f"  Result: No XSS vulnerabilities detected."), [], {}, 0.01


def _test_auth(args, scenario, discovered_hosts, discovered_ports, discovered_vulns):
    host = args.get("host", "")
    endpoint = args.get("endpoint")

    vulns = [
        v for v in scenario.get("vulnerabilities", [])
        if v["host"] == host
        and "test_auth" in v.get("discoverable_by", [])
        and (endpoint is None or v.get("endpoint") is None or v.get("endpoint") == endpoint)
    ]
    vulns = _filter_by_chain(vulns, discovered_vulns)

    if vulns:
        lines = [f"Auth & access control testing on {host}" + (endpoint or "") + ":", ""]
        for v in vulns:
            lines.extend([
                f"  [ALERT] {v['type']} DETECTED",
                f"  CWE: {v['cwe']}",
                f"  OWASP: {v['owasp']}",
                f"  Evidence: {v['evidence']}",
                f"  Suggested CVSS: {v['cvss']} ({v['severity']})",
                f"  Remediation: {v['remediation']}",
                "",
            ])
        return "\n".join(lines), [], {}, 0.08
    else:
        target = f"{host}{endpoint}" if endpoint else host
        return (f"Auth testing on {target}:\n"
                f"  Default credentials: 15 common sets tested — none accepted\n"
                f"  Session management: tokens properly rotated\n"
                f"  Access controls: authorization checks present\n"
                f"  Brute force: rate limiting detected after 5 attempts\n"
                f"  Result: PASS — no authentication weaknesses found."), [], {}, 0.01


def _test_config(args, scenario, discovered_hosts, discovered_ports, discovered_vulns):
    host = args.get("host", "")

    vulns = [
        v for v in scenario.get("vulnerabilities", [])
        if v["host"] == host
        and "test_config" in v.get("discoverable_by", [])
    ]
    vulns = _filter_by_chain(vulns, discovered_vulns)

    if vulns:
        lines = [f"Configuration audit for {host}:", ""]
        for v in vulns:
            lines.extend([
                f"  [MISCONFIGURATION] {v['type']}",
                f"  CWE: {v['cwe']}",
                f"  OWASP: {v['owasp']}",
                f"  Evidence: {v['evidence']}",
                f"  Suggested CVSS: {v['cvss']} ({v['severity']})",
                f"  Remediation: {v['remediation']}",
                "",
            ])
        return "\n".join(lines), [], {}, 0.08
    else:
        return (f"Configuration audit for {host}:\n"
                f"  Directory listing: disabled\n"
                f"  Debug mode: off\n"
                f"  Server headers: version info suppressed\n"
                f"  Admin panels: not exposed publicly\n"
                f"  Result: PASS — no significant misconfigurations."), [], {}, 0.01


def _test_crypto(args, scenario, discovered_hosts, discovered_ports, discovered_vulns):
    host = args.get("host", "")

    vulns = [
        v for v in scenario.get("vulnerabilities", [])
        if v["host"] == host
        and "test_crypto" in v.get("discoverable_by", [])
    ]
    vulns = _filter_by_chain(vulns, discovered_vulns)

    if vulns:
        lines = [f"Cryptographic analysis for {host}:", ""]
        for v in vulns:
            lines.extend([
                f"  [CRYPTO ISSUE] {v['type']}",
                f"  CWE: {v['cwe']}",
                f"  OWASP: {v['owasp']}",
                f"  Evidence: {v['evidence']}",
                f"  Suggested CVSS: {v['cvss']} ({v['severity']})",
                f"  Remediation: {v['remediation']}",
                "",
            ])
        return "\n".join(lines), [], {}, 0.06
    else:
        return (f"Cryptographic analysis for {host}:\n"
                f"  TLS version: 1.2+ only (1.0/1.1 disabled)\n"
                f"  Cipher suites: strong (AES-256-GCM preferred)\n"
                f"  Certificate: valid, not expired\n"
                f"  HSTS: enabled\n"
                f"  Result: PASS — TLS/SSL configuration is secure."), [], {}, 0.01


def _check_secrets(args, scenario, discovered_hosts, discovered_ports, discovered_vulns):
    host = args.get("host", "")
    endpoint = args.get("endpoint")

    vulns = [
        v for v in scenario.get("vulnerabilities", [])
        if v["host"] == host
        and "check_secrets" in v.get("discoverable_by", [])
        and (endpoint is None or v.get("endpoint") is None or v.get("endpoint") == endpoint)
    ]
    vulns = _filter_by_chain(vulns, discovered_vulns)

    if vulns:
        lines = [f"Secret scanning on {host}" + (endpoint or "") + ":", ""]
        for v in vulns:
            lines.extend([
                f"  [SECRET EXPOSED] {v['type']}",
                f"  CWE: {v['cwe']}",
                f"  OWASP: {v['owasp']}",
                f"  Evidence: {v['evidence']}",
                f"  Suggested CVSS: {v['cvss']} ({v['severity']})",
                f"  Remediation: {v['remediation']}",
                "",
            ])
        return "\n".join(lines), [], {}, 0.08
    else:
        target = f"{host}{endpoint}" if endpoint else host
        return (f"Secret scanning on {target}:\n"
                f"  Scanned: source files, config files, environment variables, HTTP responses\n"
                f"  Patterns: 34 secret patterns checked (AWS, Stripe, JWT, private keys, etc.)\n"
                f"  Entropy analysis: no high-entropy strings detected\n"
                f"  Result: PASS — no exposed secrets found."), [], {}, 0.01


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
