"""
Output formatting by difficulty tier.

Core innovation: generates output from KB response templates instead of
hard-coded strings.  Each vulnerability instance is mapped to its KB
type and rendered through the appropriate difficulty template.
"""

from typing import Any, Dict, List, Optional

from ..knowledge_base.responses import render_vulnerable, render_safe
from ..knowledge_base.payloads import get_payloads


# ---------------------------------------------------------------------------
# Vuln-type mapping: human-readable type strings -> KB vuln_type_ids
# ---------------------------------------------------------------------------

_TYPE_MAP = {
    # SQL Injection
    "sql injection": "sqli",
    "sqli": "sqli",
    "blind sql injection": "sqli",
    # XSS - Reflected
    "cross-site scripting": "xss_reflected",
    "xss": "xss_reflected",
    "reflected xss": "xss_reflected",
    "reflected cross-site scripting": "xss_reflected",
    "reflected cross-site scripting (xss)": "xss_reflected",
    # XSS - Stored
    "stored xss": "xss_stored",
    "stored cross-site scripting": "xss_stored",
    "stored cross-site scripting (xss)": "xss_stored",
    # SSRF
    "server-side request forgery": "ssrf",
    "server-side request forgery (ssrf)": "ssrf",
    "ssrf": "ssrf",
    # SSTI
    "server-side template injection": "ssti",
    "server-side template injection (ssti)": "ssti",
    "ssti": "ssti",
    # Command Injection
    "command injection": "command_injection",
    "os command injection": "command_injection",
    "command_injection": "command_injection",
    # IDOR / BOLA
    "insecure direct object reference": "idor",
    "insecure direct object reference (idor)": "idor",
    "idor": "idor",
    "broken object level authorization": "idor",
    "broken object level authorization (bola)": "idor",
    "bola": "idor",
    # Path Traversal
    "path traversal": "path_traversal",
    "directory traversal": "path_traversal",
    "local file inclusion": "path_traversal",
    "path_traversal": "path_traversal",
    # XXE
    "xml external entity injection": "xxe",
    "xml external entity injection (xxe)": "xxe",
    "xxe": "xxe",
    # Broken Auth
    "broken authentication": "broken_auth",
    "authentication bypass": "broken_auth",
    "broken_auth": "broken_auth",
    # Default Credentials
    "default credentials": "default_credentials",
    "default / well-known credentials": "default_credentials",
    "default_credentials": "default_credentials",
    # Weak Credentials
    "weak credentials": "weak_credentials",
    "weak credential policy": "weak_credentials",
    "weak_credentials": "weak_credentials",
    # Weak TLS
    "weak tls": "weak_tls",
    "weak tls / ssl configuration": "weak_tls",
    "weak tls/ssl configuration": "weak_tls",
    "weak_tls": "weak_tls",
    "cryptographic failures": "weak_tls",
    # Security Misconfiguration
    "security misconfiguration": "security_misconfig",
    "security_misconfig": "security_misconfig",
    "security misconfig": "security_misconfig",
    # Sensitive Data Exposure
    "sensitive data exposure": "sensitive_data_exposure",
    "sensitive_data_exposure": "sensitive_data_exposure",
    "exposed api keys": "sensitive_data_exposure",
    "hardcoded credentials": "sensitive_data_exposure",
    # Vulnerable Component
    "vulnerable component": "vulnerable_component",
    "vulnerable / outdated component": "vulnerable_component",
    "outdated software": "vulnerable_component",
    "vulnerable_component": "vulnerable_component",
    # File Upload
    "unrestricted file upload": "file_upload",
    "file upload": "file_upload",
    "file_upload": "file_upload",
    # CSRF
    "cross-site request forgery": "csrf",
    "cross-site request forgery (csrf)": "csrf",
    "csrf": "csrf",
    # Missing Rate Limiting
    "missing rate limiting": "missing_rate_limiting",
    "missing rate limiting / brute-force protection": "missing_rate_limiting",
    "missing_rate_limiting": "missing_rate_limiting",
    # Business Logic
    "business logic flaw": "security_misconfig",
    "race condition": "security_misconfig",
    # Email Misconfiguration
    "email server misconfiguration": "email_misconfig",
    "email misconfiguration": "email_misconfig",
    "email_misconfig": "email_misconfig",
    "open mail relay": "email_misconfig",
    # Missing Encryption
    "missing encryption": "weak_tls",
    "missing encryption of sensitive data": "weak_tls",
    # Open Redirect
    "open redirect": "open_redirect",
    "open_redirect": "open_redirect",
    # Insufficient Logging
    "insufficient logging": "insufficient_logging",
    "insufficient logging and monitoring": "insufficient_logging",
    "insufficient_logging": "insufficient_logging",
    # Missing Function-Level Access Control
    "missing function-level access control": "broken_auth",
    "missing function level access control": "broken_auth",
}


def _map_vuln_to_type(vuln: Dict[str, Any]) -> str:
    """Map a vulnerability instance's ``type`` string to a KB vuln_type_id.

    Uses case-insensitive fuzzy matching via the lookup dict.  Falls back
    to ``"security_misconfig"`` when no match is found so rendering never
    fails.
    """
    raw_type = vuln.get("type", "")
    key = raw_type.strip().lower()

    # Direct lookup
    if key in _TYPE_MAP:
        return _TYPE_MAP[key]

    # Substring matching for compound names
    for pattern, vuln_type_id in _TYPE_MAP.items():
        if pattern in key or key in pattern:
            return vuln_type_id

    return "security_misconfig"


def _get_sample_payload(vuln_type_id: str) -> str:
    """Get a representative payload string for the given vuln type."""
    try:
        ps = get_payloads(vuln_type_id)
        if ps.payloads:
            return ps.payloads[0]["payload"]
    except KeyError:
        pass
    return "<test-payload>"


def format_tool_output(vuln: Dict[str, Any], difficulty: str, context: Dict[str, str]) -> str:
    """Generate difficulty-appropriate output for a detected vulnerability.

    Maps the vuln's ``type`` to a KB ``vuln_type_id`` and renders through
    the response template system.  Falls back gracefully if the vuln type
    or difficulty tier is not found in the KB.
    """
    vuln_type_id = _map_vuln_to_type(vuln)

    # Ensure context has a payload if not already provided
    if not context.get("payload") or context["payload"] == "multiple":
        context.setdefault("payload", _get_sample_payload(vuln_type_id))

    # Provide defaults for template vars that may be missing
    context.setdefault("status_code", "200")
    context.setdefault("response_body", "...")
    context.setdefault("response_time", "47")

    try:
        return render_vulnerable(vuln_type_id, difficulty, context)
    except (KeyError, ValueError):
        # Fallback if template not found for this vuln/difficulty combo
        if difficulty == "easy":
            tag = {
                "Critical": "CRITICAL", "High": "ALERT",
                "Medium": "WARNING", "Low": "INFO",
            }.get(vuln.get("severity", ""), "FINDING")
            return (
                f"  [{tag}] {vuln.get('type', 'Unknown')} DETECTED\n"
                f"  CWE: {vuln.get('cwe', 'N/A')}\n"
                f"  OWASP: {vuln.get('owasp', 'N/A')}\n"
                f"  Evidence: {vuln.get('evidence', 'N/A')}\n"
                f"  Suggested CVSS: {vuln.get('cvss', 'N/A')} ({vuln.get('severity', 'N/A')})\n"
                f"  Remediation: {vuln.get('remediation', 'N/A')}"
            )
        elif difficulty == "medium":
            return (
                f"  [!] Potential issue detected\n"
                f"  Observation: {vuln.get('evidence', 'N/A')}\n"
                f"  Assess the vulnerability type, severity, and impact."
            )
        else:
            return (
                f"  Observation: {vuln.get('evidence', 'N/A')}\n"
                f"  No further classification available -- manual analysis required."
            )


def format_safe_output(
    tool_name: str,
    host: str,
    endpoint: Optional[str] = None,
    parameter: Optional[str] = None,
    difficulty: str = "easy",
) -> str:
    """Generate a clean / negative result for a tool that found nothing."""
    ep_str = f" {endpoint}" if endpoint else ""
    param_str = f" (parameter: {parameter})" if parameter else ""
    return f"  No issues detected on {host}{ep_str}{param_str}."


def format_port_table(
    host: str,
    host_info: Dict[str, Any],
    host_ports: List[Dict[str, Any]],
    difficulty: str = "easy",
) -> List[str]:
    """Format nmap-style port table for a single host.

    Returns a list of output lines (without trailing newline).
    """
    _PORT_WARNINGS = {
        3306: "WARNING: MySQL accessible externally -- verify firewall rules",
        5432: "WARNING: PostgreSQL accessible externally -- restrict to app IPs",
        21: "WARNING: FTP (plaintext protocol) detected -- consider SFTP",
        445: "NOTE: SMB file sharing detected -- verify access controls",
        3389: "NOTE: RDP exposed -- ensure strong credentials and NLA",
    }

    lines: List[str] = []
    lines.append(f"Nmap scan report for {host} ({host_info['hostname']})")
    lines.append(f"  OS Detection: {host_info['os']}")
    lines.append(f"  Device Role: {host_info['role']}")
    lines.append(f"  PORT      STATE  SERVICE         VERSION")

    for p in host_ports:
        lines.append(
            f"  {p['port']}/tcp   {p['state']:6s} {p['service']:15s} {p['version']}"
        )

        warning = _PORT_WARNINGS.get(p["port"])
        if warning:
            lines.append(f"  |_ {warning}")

        if "Jenkins" in p.get("version", ""):
            lines.append(f"  |_ NOTE: Jenkins CI/CD server detected -- check authentication")

    lines.append("")
    return lines
