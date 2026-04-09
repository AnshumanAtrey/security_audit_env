"""
Security testing tool handlers.

Handles: test_injection, test_xss, test_auth, test_config, test_crypto,
check_secrets.

Each handler:
 1. Accepts an optional ``parameter`` argument (backward-compatible).
 2. Looks up vulnerabilities in the scenario that match host + endpoint + tool.
 3. Filters by chain prerequisites (requires_found).
 4. Generates output using KB response templates via formatters.
"""

from typing import Any, Dict, List, Optional, Set, Tuple

from .formatters import (
    format_tool_output,
    format_safe_output,
    _map_vuln_to_type,
    _get_sample_payload,
)


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


def _build_context(
    vuln: Dict[str, Any],
    host: str,
    endpoint: str,
    parameter: Optional[str],
) -> Dict[str, str]:
    """Build a template context dict from a vulnerability instance."""
    vuln_type_id = _map_vuln_to_type(vuln)
    return {
        "host": host,
        "endpoint": endpoint or vuln.get("endpoint", ""),
        "parameter": parameter or "multiple",
        "payload": _get_sample_payload(vuln_type_id),
        "cvss": str(vuln.get("cvss", 0)),
        "cwe": vuln.get("cwe", ""),
        "severity": vuln.get("severity", ""),
        "owasp": vuln.get("owasp", ""),
        "evidence_detail": vuln.get("evidence", ""),
        "remediation": vuln.get("remediation", ""),
        "service_version": "",
        "port": "",
    }


# ---------------------------------------------------------------------------
# test_injection
# ---------------------------------------------------------------------------

def handle_test_injection(
    args: Dict[str, Any],
    scenario: Dict[str, Any],
    discovered_hosts: List[str],
    discovered_ports: Dict[str, List[int]],
    discovered_vulns: Optional[Set[str]] = None,
) -> Tuple[str, List[str], Dict[str, List[int]], float]:
    host = args.get("host", "")
    endpoint = args.get("endpoint", "")
    parameter = args.get("parameter")

    if host not in discovered_hosts:
        return ("Error: Host not discovered yet. Run network_scan first.", [], {}, -0.02)

    difficulty = _normalize_difficulty(scenario)

    vulns = [
        v for v in scenario.get("vulnerabilities", [])
        if v["host"] == host
        and v.get("endpoint") == endpoint
        and "test_injection" in v.get("discoverable_by", [])
    ]
    vulns = _filter_by_chain(vulns, discovered_vulns)

    if not vulns:
        return (
            f"Injection testing on {host}{endpoint}:\n"
            f"  Tested: SQLi (error-based, blind, time-based), command injection, SSTI, SSRF\n"
            f"  Payloads: 47 injection patterns tested\n"
            f"  Result: No injection vulnerabilities detected on this endpoint.",
            [], {}, 0.01,
        )

    output_parts = [f"Injection testing on {host}{endpoint}:", ""]
    for v in vulns:
        context = _build_context(v, host, endpoint, parameter)
        output_parts.append(format_tool_output(v, difficulty, context))
        output_parts.append("")

    return "\n".join(output_parts), [], {}, 0.08


# ---------------------------------------------------------------------------
# test_xss
# ---------------------------------------------------------------------------

def handle_test_xss(
    args: Dict[str, Any],
    scenario: Dict[str, Any],
    discovered_hosts: List[str],
    discovered_ports: Dict[str, List[int]],
    discovered_vulns: Optional[Set[str]] = None,
) -> Tuple[str, List[str], Dict[str, List[int]], float]:
    host = args.get("host", "")
    endpoint = args.get("endpoint", "")
    parameter = args.get("parameter")

    if host not in discovered_hosts:
        return ("Error: Host not discovered yet. Run network_scan first.", [], {}, -0.02)

    difficulty = _normalize_difficulty(scenario)

    vulns = [
        v for v in scenario.get("vulnerabilities", [])
        if v["host"] == host
        and v.get("endpoint") == endpoint
        and "test_xss" in v.get("discoverable_by", [])
    ]
    vulns = _filter_by_chain(vulns, discovered_vulns)

    if not vulns:
        return (
            f"XSS testing on {host}{endpoint}:\n"
            f"  Tested: reflected XSS, stored XSS, DOM-based XSS\n"
            f"  Payloads: 23 XSS vectors tested across all parameters\n"
            f"  Result: No XSS vulnerabilities detected.",
            [], {}, 0.01,
        )

    output_parts = [f"XSS testing on {host}{endpoint}:", ""]
    for v in vulns:
        context = _build_context(v, host, endpoint, parameter)
        output_parts.append(format_tool_output(v, difficulty, context))
        output_parts.append("")

    return "\n".join(output_parts), [], {}, 0.08


# ---------------------------------------------------------------------------
# test_auth
# ---------------------------------------------------------------------------

def handle_test_auth(
    args: Dict[str, Any],
    scenario: Dict[str, Any],
    discovered_hosts: List[str],
    discovered_ports: Dict[str, List[int]],
    discovered_vulns: Optional[Set[str]] = None,
) -> Tuple[str, List[str], Dict[str, List[int]], float]:
    host = args.get("host", "")
    endpoint = args.get("endpoint")
    parameter = args.get("parameter")

    if host not in discovered_hosts:
        return ("Error: Host not discovered yet. Run network_scan first.", [], {}, -0.02)

    difficulty = _normalize_difficulty(scenario)

    # test_auth handles both endpoint-level (IDOR) and host-level (default creds)
    vulns = [
        v for v in scenario.get("vulnerabilities", [])
        if v["host"] == host
        and "test_auth" in v.get("discoverable_by", [])
        and (endpoint is None or v.get("endpoint") is None or v.get("endpoint") == endpoint)
    ]
    vulns = _filter_by_chain(vulns, discovered_vulns)

    if not vulns:
        target = f"{host}{endpoint}" if endpoint else host
        return (
            f"Auth testing on {target}:\n"
            f"  Default credentials: 15 common sets tested -- none accepted\n"
            f"  Session management: tokens properly rotated\n"
            f"  Access controls: authorization checks present\n"
            f"  Brute force: rate limiting detected after 5 attempts\n"
            f"  Result: PASS -- no authentication weaknesses found.",
            [], {}, 0.01,
        )

    ep_display = endpoint or ""
    output_parts = [f"Auth & access control testing on {host}{ep_display}:", ""]
    for v in vulns:
        context = _build_context(v, host, endpoint or "", parameter)
        output_parts.append(format_tool_output(v, difficulty, context))
        output_parts.append("")

    return "\n".join(output_parts), [], {}, 0.08


# ---------------------------------------------------------------------------
# test_config
# ---------------------------------------------------------------------------

def handle_test_config(
    args: Dict[str, Any],
    scenario: Dict[str, Any],
    discovered_hosts: List[str],
    discovered_ports: Dict[str, List[int]],
    discovered_vulns: Optional[Set[str]] = None,
) -> Tuple[str, List[str], Dict[str, List[int]], float]:
    host = args.get("host", "")

    if host not in discovered_hosts:
        return ("Error: Host not discovered yet. Run network_scan first.", [], {}, -0.02)

    difficulty = _normalize_difficulty(scenario)

    vulns = [
        v for v in scenario.get("vulnerabilities", [])
        if v["host"] == host
        and "test_config" in v.get("discoverable_by", [])
    ]
    vulns = _filter_by_chain(vulns, discovered_vulns)

    if not vulns:
        return (
            f"Configuration audit for {host}:\n"
            f"  Directory listing: disabled\n"
            f"  Debug mode: off\n"
            f"  Server headers: version info suppressed\n"
            f"  Admin panels: not exposed publicly\n"
            f"  Result: PASS -- no significant misconfigurations.",
            [], {}, 0.01,
        )

    output_parts = [f"Configuration audit for {host}:", ""]
    for v in vulns:
        context = _build_context(v, host, "", None)
        # Enrich with port/service if available from scenario
        host_ports = scenario.get("ports", {}).get(host, [])
        if host_ports:
            context["port"] = str(host_ports[0].get("port", ""))
            context["service_version"] = host_ports[0].get("version", "")
        output_parts.append(format_tool_output(v, difficulty, context))
        output_parts.append("")

    return "\n".join(output_parts), [], {}, 0.08


# ---------------------------------------------------------------------------
# test_crypto
# ---------------------------------------------------------------------------

def handle_test_crypto(
    args: Dict[str, Any],
    scenario: Dict[str, Any],
    discovered_hosts: List[str],
    discovered_ports: Dict[str, List[int]],
    discovered_vulns: Optional[Set[str]] = None,
) -> Tuple[str, List[str], Dict[str, List[int]], float]:
    host = args.get("host", "")

    if host not in discovered_hosts:
        return ("Error: Host not discovered yet. Run network_scan first.", [], {}, -0.02)

    difficulty = _normalize_difficulty(scenario)

    vulns = [
        v for v in scenario.get("vulnerabilities", [])
        if v["host"] == host
        and "test_crypto" in v.get("discoverable_by", [])
    ]
    vulns = _filter_by_chain(vulns, discovered_vulns)

    if not vulns:
        return (
            f"Cryptographic analysis for {host}:\n"
            f"  TLS version: 1.2+ only (1.0/1.1 disabled)\n"
            f"  Cipher suites: strong (AES-256-GCM preferred)\n"
            f"  Certificate: valid, not expired\n"
            f"  HSTS: enabled\n"
            f"  Result: PASS -- TLS/SSL configuration is secure.",
            [], {}, 0.01,
        )

    output_parts = [f"Cryptographic analysis for {host}:", ""]
    for v in vulns:
        context = _build_context(v, host, "", None)
        # Enrich with port info
        host_ports = scenario.get("ports", {}).get(host, [])
        for p in host_ports:
            if p.get("service") in ("https", "ssl", "tls") or p.get("port") in (443, 8443):
                context["port"] = str(p["port"])
                context["service_version"] = p.get("version", "")
                break
        else:
            if host_ports:
                context["port"] = str(host_ports[0].get("port", "443"))
                context["service_version"] = host_ports[0].get("version", "")
        output_parts.append(format_tool_output(v, difficulty, context))
        output_parts.append("")

    return "\n".join(output_parts), [], {}, 0.06


# ---------------------------------------------------------------------------
# check_secrets
# ---------------------------------------------------------------------------

def handle_check_secrets(
    args: Dict[str, Any],
    scenario: Dict[str, Any],
    discovered_hosts: List[str],
    discovered_ports: Dict[str, List[int]],
    discovered_vulns: Optional[Set[str]] = None,
) -> Tuple[str, List[str], Dict[str, List[int]], float]:
    host = args.get("host", "")
    endpoint = args.get("endpoint")
    parameter = args.get("parameter")

    if host not in discovered_hosts:
        return ("Error: Host not discovered yet. Run network_scan first.", [], {}, -0.02)

    difficulty = _normalize_difficulty(scenario)

    vulns = [
        v for v in scenario.get("vulnerabilities", [])
        if v["host"] == host
        and "check_secrets" in v.get("discoverable_by", [])
        and (endpoint is None or v.get("endpoint") is None or v.get("endpoint") == endpoint)
    ]
    vulns = _filter_by_chain(vulns, discovered_vulns)

    if not vulns:
        target = f"{host}{endpoint}" if endpoint else host
        return (
            f"Secret scanning on {target}:\n"
            f"  Scanned: source files, config files, environment variables, HTTP responses\n"
            f"  Patterns: 34 secret patterns checked (AWS, Stripe, JWT, private keys, etc.)\n"
            f"  Entropy analysis: no high-entropy strings detected\n"
            f"  Result: PASS -- no exposed secrets found.",
            [], {}, 0.01,
        )

    ep_display = endpoint or ""
    output_parts = [f"Secret scanning on {host}{ep_display}:", ""]
    for v in vulns:
        context = _build_context(v, host, endpoint or "", parameter)
        output_parts.append(format_tool_output(v, difficulty, context))
        output_parts.append("")

    return "\n".join(output_parts), [], {}, 0.08
