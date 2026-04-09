"""
Vulnerability Type Catalog for Security Audit Benchmark.

Each entry defines a VULNERABILITY TYPE (not instance) with metadata from
OWASP Top 10 2021 and MITRE CWE standards.  Used by the scenario generator
and grader to validate agent findings against ground truth.

Sources:
    - OWASP Top 10:2021  https://owasp.org/Top10/2021/
    - MITRE CWE Database  https://cwe.mitre.org/
    - NVD / CVSS v3.1     https://nvd.nist.gov/
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class VulnType:
    """A vulnerability *type* — not a specific instance on a host."""

    id: str
    name: str
    cwe_ids: List[int]
    owasp_category: str  # e.g. "A01:2021 - Broken Access Control"
    severity_range: Tuple[str, str]  # (min_severity, max_severity)
    cvss_range: Tuple[float, float]  # (min_cvss, max_cvss)
    discoverable_by: List[str]  # tool names from TOOL_DEFINITIONS
    applicable_to: List[str]  # "web_endpoint", "host_service", "network"
    requires_params: bool  # True if parameter-level (SQLi, XSS, etc.)
    chain_potential: bool  # True if can be gateway to hidden hosts/services
    description: str
    remediation_template: str


# ---------------------------------------------------------------------------
# Role-to-applicable mapping helpers
# ---------------------------------------------------------------------------

_ROLE_KEYWORDS: Dict[str, List[str]] = {
    "web": ["web_endpoint", "host_service"],
    "database": ["host_service"],
    "mail": ["host_service", "network"],
    "api": ["web_endpoint", "host_service"],
    "file": ["host_service", "network"],
    "dns": ["host_service", "network"],
    "load balancer": ["host_service", "network"],
    "proxy": ["host_service", "network", "web_endpoint"],
    "cache": ["host_service"],
    "firewall": ["host_service", "network"],
}

# Maps normalized role keywords to vuln type ids that are especially
# relevant for that kind of host.
_ROLE_VULN_AFFINITY: Dict[str, List[str]] = {
    "web": [
        "sqli", "command_injection", "ssrf", "ssti", "xxe",
        "xss_reflected", "xss_stored", "csrf", "file_upload",
        "open_redirect", "idor", "bola", "path_traversal",
        "missing_function_level_access", "security_misconfig",
        "default_credentials", "broken_auth", "weak_credentials",
        "missing_rate_limiting", "sensitive_data_exposure",
        "weak_tls", "business_logic_flaw", "insufficient_logging",
        "vulnerable_component",
    ],
    "database": [
        "sqli", "weak_credentials", "default_credentials",
        "security_misconfig", "sensitive_data_exposure",
        "missing_encryption", "insufficient_logging",
        "vulnerable_component",
    ],
    "mail": [
        "email_misconfig", "weak_tls", "security_misconfig",
        "default_credentials", "sensitive_data_exposure",
        "missing_encryption", "broken_auth",
    ],
    "api": [
        "sqli", "command_injection", "ssrf", "ssti", "xxe",
        "idor", "bola", "missing_function_level_access",
        "broken_auth", "weak_credentials", "missing_rate_limiting",
        "security_misconfig", "sensitive_data_exposure",
        "insufficient_logging", "vulnerable_component",
        "xss_reflected", "xss_stored",
    ],
    "file": [
        "path_traversal", "file_upload", "default_credentials",
        "security_misconfig", "weak_credentials",
        "missing_encryption", "sensitive_data_exposure",
    ],
    "dns": [
        "security_misconfig", "default_credentials",
        "vulnerable_component",
    ],
    "load balancer": [
        "weak_tls", "security_misconfig", "ssrf",
        "sensitive_data_exposure",
    ],
    "proxy": [
        "ssrf", "weak_tls", "security_misconfig",
        "sensitive_data_exposure", "open_redirect",
    ],
    "cache": [
        "default_credentials", "security_misconfig",
        "sensitive_data_exposure",
    ],
    "firewall": [
        "security_misconfig", "default_credentials",
        "vulnerable_component",
    ],
}


# ---------------------------------------------------------------------------
# Catalog — at least 20 types covering all OWASP Top 10 2021 categories
# ---------------------------------------------------------------------------

_VULN_TYPES: List[VulnType] = [

    # ── A01:2021 — Broken Access Control ──────────────────────────────────

    VulnType(
        id="idor",
        name="Insecure Direct Object Reference (IDOR)",
        cwe_ids=[639, 284, 285],
        owasp_category="A01:2021 - Broken Access Control",
        severity_range=("Medium", "High"),
        cvss_range=(5.3, 8.8),
        discoverable_by=["test_auth", "web_crawl"],
        applicable_to=["web_endpoint"],
        requires_params=True,
        chain_potential=False,
        description=(
            "The application exposes internal object identifiers (database keys, "
            "file names) in API responses or URLs without verifying that the "
            "authenticated user is authorised to access the referenced object."
        ),
        remediation_template=(
            "Implement object-level authorisation checks on every data-access "
            "endpoint.  Use indirect references (UUIDs / per-session maps) "
            "instead of sequential IDs.  Validate ownership server-side before "
            "returning data."
        ),
    ),

    VulnType(
        id="bola",
        name="Broken Object Level Authorization (BOLA)",
        cwe_ids=[862, 863],
        owasp_category="A01:2021 - Broken Access Control",
        severity_range=("Medium", "Critical"),
        cvss_range=(5.3, 9.8),
        discoverable_by=["test_auth", "web_crawl"],
        applicable_to=["web_endpoint"],
        requires_params=True,
        chain_potential=False,
        description=(
            "API endpoints do not verify that the requesting user has "
            "authorisation for the specific object being accessed, allowing "
            "horizontal or vertical privilege escalation."
        ),
        remediation_template=(
            "Enforce object-level authorisation in every API handler.  Use "
            "policy-based access control (ABAC/RBAC) evaluated server-side.  "
            "Log and alert on repeated authorisation failures."
        ),
    ),

    VulnType(
        id="path_traversal",
        name="Path Traversal",
        cwe_ids=[22, 23, 35],
        owasp_category="A01:2021 - Broken Access Control",
        severity_range=("Medium", "High"),
        cvss_range=(5.3, 7.5),
        discoverable_by=["test_injection", "vulnerability_scan"],
        applicable_to=["web_endpoint", "host_service"],
        requires_params=True,
        chain_potential=True,
        description=(
            "User-supplied file paths are not properly sanitised, allowing "
            "traversal outside the intended directory (e.g. ../../etc/passwd) "
            "to read or write arbitrary files on the server."
        ),
        remediation_template=(
            "Canonicalise and validate all file paths against an allow-list.  "
            "Use chroot jails or sandboxed file-system access.  Reject paths "
            "containing '..' sequences after decoding."
        ),
    ),

    VulnType(
        id="missing_function_level_access",
        name="Missing Function-Level Access Control",
        cwe_ids=[285, 862, 425],
        owasp_category="A01:2021 - Broken Access Control",
        severity_range=("Medium", "Critical"),
        cvss_range=(5.3, 9.8),
        discoverable_by=["test_auth", "web_crawl"],
        applicable_to=["web_endpoint"],
        requires_params=False,
        chain_potential=True,
        description=(
            "Administrative or privileged endpoints lack authentication or "
            "authorisation checks, allowing unauthenticated or low-privilege "
            "users to invoke sensitive functions."
        ),
        remediation_template=(
            "Implement role-based access control for all endpoints.  Default-"
            "deny access to admin functions.  Centralise authorisation logic "
            "in middleware or decorators."
        ),
    ),

    # ── A02:2021 — Cryptographic Failures ─────────────────────────────────

    VulnType(
        id="weak_tls",
        name="Weak TLS / SSL Configuration",
        cwe_ids=[326, 327, 757],
        owasp_category="A02:2021 - Cryptographic Failures",
        severity_range=("Medium", "High"),
        cvss_range=(5.3, 7.5),
        discoverable_by=["test_crypto", "service_fingerprint"],
        applicable_to=["host_service", "network"],
        requires_params=False,
        chain_potential=False,
        description=(
            "The service uses deprecated TLS versions (SSLv3, TLS 1.0/1.1), "
            "weak cipher suites, or missing HSTS headers, making traffic "
            "susceptible to downgrade and man-in-the-middle attacks."
        ),
        remediation_template=(
            "Enforce TLS 1.2+ with strong cipher suites (AEAD).  Enable HSTS "
            "with includeSubDomains and preload.  Disable SSLv3/TLS 1.0/1.1.  "
            "Use automated certificate management."
        ),
    ),

    VulnType(
        id="sensitive_data_exposure",
        name="Sensitive Data Exposure",
        cwe_ids=[200, 319, 312, 359],
        owasp_category="A02:2021 - Cryptographic Failures",
        severity_range=("Medium", "High"),
        cvss_range=(4.3, 7.5),
        discoverable_by=["check_secrets", "web_crawl", "test_config"],
        applicable_to=["web_endpoint", "host_service"],
        requires_params=False,
        chain_potential=True,
        description=(
            "The application transmits or stores sensitive data (credentials, "
            "PII, tokens, API keys) in cleartext or with weak protection, "
            "making it accessible to unauthorised parties."
        ),
        remediation_template=(
            "Encrypt all sensitive data at rest (AES-256) and in transit "
            "(TLS 1.2+).  Classify data by sensitivity; apply appropriate "
            "controls.  Never log secrets or include them in URLs."
        ),
    ),

    VulnType(
        id="missing_encryption",
        name="Missing Encryption of Sensitive Data",
        cwe_ids=[311, 319, 523],
        owasp_category="A02:2021 - Cryptographic Failures",
        severity_range=("Medium", "High"),
        cvss_range=(5.3, 7.5),
        discoverable_by=["test_crypto", "test_config"],
        applicable_to=["host_service", "network"],
        requires_params=False,
        chain_potential=False,
        description=(
            "Sensitive data is stored or transmitted without any encryption, "
            "including plaintext password storage, unencrypted database "
            "connections, or HTTP-only transport for credentials."
        ),
        remediation_template=(
            "Use strong hashing (bcrypt / argon2) for passwords.  Encrypt "
            "database connections with TLS.  Require HTTPS for all "
            "authentication and sensitive data endpoints."
        ),
    ),

    # ── A03:2021 — Injection ──────────────────────────────────────────────

    VulnType(
        id="sqli",
        name="SQL Injection",
        cwe_ids=[89, 564],
        owasp_category="A03:2021 - Injection",
        severity_range=("High", "Critical"),
        cvss_range=(8.1, 9.8),
        discoverable_by=["test_injection", "vulnerability_scan"],
        applicable_to=["web_endpoint"],
        requires_params=True,
        chain_potential=True,
        description=(
            "User input is concatenated directly into SQL queries without "
            "parameterisation or escaping, allowing attackers to read, modify, "
            "or delete database content and potentially execute OS commands."
        ),
        remediation_template=(
            "Use parameterised queries (prepared statements) exclusively.  "
            "Apply least-privilege database accounts.  Validate and sanitise "
            "all input.  Deploy a WAF as defence-in-depth."
        ),
    ),

    VulnType(
        id="command_injection",
        name="OS Command Injection",
        cwe_ids=[78, 77, 88],
        owasp_category="A03:2021 - Injection",
        severity_range=("High", "Critical"),
        cvss_range=(7.5, 10.0),
        discoverable_by=["test_injection", "vulnerability_scan"],
        applicable_to=["web_endpoint", "host_service"],
        requires_params=True,
        chain_potential=True,
        description=(
            "User-supplied data is passed to OS shell commands without "
            "proper sanitisation, enabling attackers to execute arbitrary "
            "system commands with the application's privileges."
        ),
        remediation_template=(
            "Avoid calling OS commands from application code.  If unavoidable, "
            "use safe APIs (subprocess with list args, no shell=True).  "
            "Validate input against a strict allow-list."
        ),
    ),

    VulnType(
        id="ssrf",
        name="Server-Side Request Forgery (SSRF)",
        cwe_ids=[918],
        owasp_category="A10:2021 - Server-Side Request Forgery",
        severity_range=("Medium", "Critical"),
        cvss_range=(5.3, 9.8),
        discoverable_by=["test_injection", "vulnerability_scan"],
        applicable_to=["web_endpoint"],
        requires_params=True,
        chain_potential=True,
        description=(
            "The application fetches a remote resource using a user-supplied "
            "URL without validating the destination, allowing attackers to "
            "reach internal services, cloud metadata endpoints, or perform "
            "port scanning from the server."
        ),
        remediation_template=(
            "Validate and sanitise all user-supplied URLs against an allow-list "
            "of permitted domains and IP ranges.  Block requests to private IP "
            "ranges and cloud metadata IPs (169.254.169.254).  Use network-"
            "level segmentation."
        ),
    ),

    VulnType(
        id="ssti",
        name="Server-Side Template Injection (SSTI)",
        cwe_ids=[94, 917],
        owasp_category="A03:2021 - Injection",
        severity_range=("High", "Critical"),
        cvss_range=(7.5, 9.8),
        discoverable_by=["test_injection"],
        applicable_to=["web_endpoint"],
        requires_params=True,
        chain_potential=True,
        description=(
            "User input is embedded directly into server-side templates "
            "(Jinja2, Thymeleaf, Twig, etc.) and evaluated, enabling "
            "arbitrary code execution on the server."
        ),
        remediation_template=(
            "Never pass raw user input into template engines.  Use sandboxed "
            "template modes.  Separate application logic from presentation.  "
            "Apply input validation and output encoding."
        ),
    ),

    VulnType(
        id="xxe",
        name="XML External Entity Injection (XXE)",
        cwe_ids=[611, 776],
        owasp_category="A05:2021 - Security Misconfiguration",
        severity_range=("High", "Critical"),
        cvss_range=(7.5, 9.8),
        discoverable_by=["test_injection", "vulnerability_scan"],
        applicable_to=["web_endpoint"],
        requires_params=True,
        chain_potential=True,
        description=(
            "XML parsers are configured to resolve external entities, "
            "allowing attackers to read local files, perform SSRF, or "
            "cause denial-of-service via entity expansion (Billion Laughs)."
        ),
        remediation_template=(
            "Disable DTD processing and external entity resolution in all "
            "XML parsers.  Use JSON instead of XML where possible.  Apply "
            "server-side input validation on XML payloads."
        ),
    ),

    # ── A04:2021 — Insecure Design ────────────────────────────────────────

    VulnType(
        id="business_logic_flaw",
        name="Business Logic Flaw",
        cwe_ids=[840, 841],
        owasp_category="A04:2021 - Insecure Design",
        severity_range=("Medium", "High"),
        cvss_range=(5.3, 8.8),
        discoverable_by=["test_auth", "web_crawl"],
        applicable_to=["web_endpoint"],
        requires_params=False,
        chain_potential=False,
        description=(
            "The application's business rules can be bypassed or abused "
            "due to missing or ineffective design controls — e.g. negative "
            "quantities, race conditions, or unlimited privilege escalation "
            "through legitimate-looking workflows."
        ),
        remediation_template=(
            "Perform threat modelling during design.  Validate all business "
            "invariants server-side.  Implement rate limiting and transaction "
            "integrity checks.  Use state machines for multi-step workflows."
        ),
    ),

    # ── A05:2021 — Security Misconfiguration ──────────────────────────────

    VulnType(
        id="security_misconfig",
        name="Security Misconfiguration",
        cwe_ids=[16, 756, 1004, 942],
        owasp_category="A05:2021 - Security Misconfiguration",
        severity_range=("Low", "High"),
        cvss_range=(4.3, 7.5),
        discoverable_by=["test_config", "vulnerability_scan", "service_fingerprint"],
        applicable_to=["web_endpoint", "host_service", "network"],
        requires_params=False,
        chain_potential=True,
        description=(
            "The application, web server, or infrastructure component is "
            "deployed with insecure defaults: verbose error messages, "
            "directory listing enabled, missing security headers, debug "
            "mode in production, or unnecessary features enabled."
        ),
        remediation_template=(
            "Harden all environments with a repeatable process.  Disable "
            "directory listing, debug mode, and unnecessary HTTP methods.  "
            "Set security headers (CSP, X-Frame-Options, X-Content-Type-"
            "Options).  Remove default pages and sample applications."
        ),
    ),

    VulnType(
        id="default_credentials",
        name="Default / Well-Known Credentials",
        cwe_ids=[798, 259],
        owasp_category="A05:2021 - Security Misconfiguration",
        severity_range=("High", "Critical"),
        cvss_range=(7.5, 9.8),
        discoverable_by=["test_auth", "test_config"],
        applicable_to=["web_endpoint", "host_service"],
        requires_params=False,
        chain_potential=True,
        description=(
            "Services or management interfaces are accessible with factory-"
            "default or commonly known credentials (admin/admin, root/root, "
            "etc.) that were never changed after deployment."
        ),
        remediation_template=(
            "Force password change on first login.  Remove or disable default "
            "accounts.  Use unique, strong passwords generated per deployment.  "
            "Implement credential rotation policies."
        ),
    ),

    # ── A06:2021 — Vulnerable and Outdated Components ─────────────────────

    VulnType(
        id="vulnerable_component",
        name="Vulnerable / Outdated Component",
        cwe_ids=[1104, 1035, 937],
        owasp_category="A06:2021 - Vulnerable and Outdated Components",
        severity_range=("Low", "Critical"),
        cvss_range=(3.0, 10.0),
        discoverable_by=["vulnerability_scan", "service_fingerprint"],
        applicable_to=["web_endpoint", "host_service"],
        requires_params=False,
        chain_potential=True,
        description=(
            "The system runs software components (libraries, frameworks, OS "
            "packages) with known CVEs.  Attackers can leverage public exploit "
            "code to compromise the service."
        ),
        remediation_template=(
            "Maintain a software bill of materials (SBOM).  Subscribe to "
            "security advisories for all dependencies.  Patch or upgrade "
            "vulnerable components promptly.  Use SCA tools in CI/CD."
        ),
    ),

    # ── A07:2021 — Identification and Authentication Failures ─────────────

    VulnType(
        id="broken_auth",
        name="Broken Authentication",
        cwe_ids=[287, 306, 304],
        owasp_category="A07:2021 - Identification and Authentication Failures",
        severity_range=("High", "Critical"),
        cvss_range=(7.5, 9.8),
        discoverable_by=["test_auth", "vulnerability_scan"],
        applicable_to=["web_endpoint", "host_service"],
        requires_params=False,
        chain_potential=True,
        description=(
            "Authentication mechanisms can be bypassed entirely — e.g. "
            "missing auth on critical endpoints, predictable session tokens, "
            "or authentication bypass via parameter manipulation."
        ),
        remediation_template=(
            "Require authentication on all non-public endpoints.  Use "
            "proven frameworks for session management.  Implement MFA "
            "for privileged accounts.  Invalidate sessions on logout."
        ),
    ),

    VulnType(
        id="weak_credentials",
        name="Weak Credential Policy",
        cwe_ids=[521, 307, 384],
        owasp_category="A07:2021 - Identification and Authentication Failures",
        severity_range=("Medium", "High"),
        cvss_range=(5.3, 7.5),
        discoverable_by=["test_auth"],
        applicable_to=["web_endpoint", "host_service"],
        requires_params=False,
        chain_potential=False,
        description=(
            "The application permits weak passwords, does not enforce "
            "complexity requirements, or stores credentials insecurely "
            "(plaintext, unsalted hashes)."
        ),
        remediation_template=(
            "Enforce minimum password length (12+) and complexity rules.  "
            "Check against breached-password lists (HIBP API).  Hash "
            "passwords with bcrypt/argon2.  Encourage passphrase use."
        ),
    ),

    VulnType(
        id="missing_rate_limiting",
        name="Missing Rate Limiting / Brute-Force Protection",
        cwe_ids=[307, 799, 1216],
        owasp_category="A07:2021 - Identification and Authentication Failures",
        severity_range=("Medium", "High"),
        cvss_range=(5.3, 7.5),
        discoverable_by=["test_auth"],
        applicable_to=["web_endpoint"],
        requires_params=False,
        chain_potential=False,
        description=(
            "Login, password-reset, or OTP-verification endpoints have no "
            "rate limiting, account lockout, or CAPTCHA, enabling credential "
            "stuffing and brute-force attacks."
        ),
        remediation_template=(
            "Implement progressive delays and account lockout after failed "
            "attempts.  Add CAPTCHA or proof-of-work after a threshold.  "
            "Use IP-based and account-based rate limiting together."
        ),
    ),

    # ── A08:2021 — Software and Data Integrity Failures ───────────────────
    # (Covered primarily by vulnerable_component above; the category also
    #  maps to insecure deserialization which shares CWE-502.  The
    #  vulnerable_component entry carries CWE-1035 and CWE-1104 from A08.)

    # ── A09:2021 — Security Logging and Monitoring Failures ───────────────

    VulnType(
        id="insufficient_logging",
        name="Insufficient Logging and Monitoring",
        cwe_ids=[778, 223, 532],
        owasp_category="A09:2021 - Security Logging and Monitoring Failures",
        severity_range=("Medium", "High"),
        cvss_range=(4.3, 7.5),
        discoverable_by=["test_config", "test_auth"],
        applicable_to=["web_endpoint", "host_service"],
        requires_params=False,
        chain_potential=False,
        description=(
            "Auditable events (login failures, access-control violations, "
            "input-validation failures) are not logged, or logs lack "
            "sufficient detail for forensic analysis and alerting."
        ),
        remediation_template=(
            "Log all authentication events, access-control failures, and "
            "server-side validation failures with context (who, what, when, "
            "where).  Forward logs to a SIEM.  Set up alerts for anomalous "
            "patterns.  Never log sensitive data (passwords, tokens)."
        ),
    ),

    # ── A10:2021 — SSRF (covered by ssrf entry above) ────────────────────

    # ── Additional vulnerability types ────────────────────────────────────

    VulnType(
        id="xss_reflected",
        name="Reflected Cross-Site Scripting (XSS)",
        cwe_ids=[79, 80],
        owasp_category="A03:2021 - Injection",
        severity_range=("Medium", "Medium"),
        cvss_range=(4.3, 6.1),
        discoverable_by=["test_xss", "vulnerability_scan"],
        applicable_to=["web_endpoint"],
        requires_params=True,
        chain_potential=False,
        description=(
            "User input is reflected in HTTP responses without encoding, "
            "allowing attackers to inject client-side scripts that execute "
            "in the victim's browser via crafted URLs."
        ),
        remediation_template=(
            "Apply context-aware output encoding (HTML, JS, URL, CSS).  "
            "Deploy a strict Content-Security-Policy.  Use HTTPOnly and "
            "Secure flags on session cookies."
        ),
    ),

    VulnType(
        id="xss_stored",
        name="Stored Cross-Site Scripting (XSS)",
        cwe_ids=[79, 83, 87],
        owasp_category="A03:2021 - Injection",
        severity_range=("Medium", "High"),
        cvss_range=(5.4, 8.0),
        discoverable_by=["test_xss", "vulnerability_scan"],
        applicable_to=["web_endpoint"],
        requires_params=True,
        chain_potential=False,
        description=(
            "Malicious scripts submitted by an attacker are persisted in "
            "the application (database, file, etc.) and served to other "
            "users, executing in their browsers without interaction."
        ),
        remediation_template=(
            "Sanitise all user input on storage.  Apply context-aware output "
            "encoding on render.  Deploy Content-Security-Policy with nonce-"
            "based script whitelisting.  Use frameworks with auto-escaping."
        ),
    ),

    VulnType(
        id="csrf",
        name="Cross-Site Request Forgery (CSRF)",
        cwe_ids=[352],
        owasp_category="A01:2021 - Broken Access Control",
        severity_range=("Medium", "High"),
        cvss_range=(4.3, 8.8),
        discoverable_by=["test_auth", "test_config"],
        applicable_to=["web_endpoint"],
        requires_params=False,
        chain_potential=False,
        description=(
            "State-changing operations lack anti-CSRF tokens or SameSite "
            "cookie attributes, allowing attackers to forge requests from "
            "a victim's authenticated browser session."
        ),
        remediation_template=(
            "Include anti-CSRF tokens in every state-changing form and AJAX "
            "request.  Set SameSite=Strict or Lax on session cookies.  "
            "Verify the Origin / Referer header server-side."
        ),
    ),

    VulnType(
        id="file_upload",
        name="Unrestricted File Upload",
        cwe_ids=[434],
        owasp_category="A04:2021 - Insecure Design",
        severity_range=("High", "Critical"),
        cvss_range=(7.5, 9.8),
        discoverable_by=["test_injection", "web_crawl"],
        applicable_to=["web_endpoint"],
        requires_params=True,
        chain_potential=True,
        description=(
            "File upload functionality does not restrict file type, size, "
            "or storage location, allowing upload of web shells or "
            "executable content that can lead to remote code execution."
        ),
        remediation_template=(
            "Validate file type by content (magic bytes), not extension.  "
            "Store uploads outside the web root with randomised names.  "
            "Set a maximum file size.  Scan uploads for malware."
        ),
    ),

    VulnType(
        id="open_redirect",
        name="Open Redirect",
        cwe_ids=[601],
        owasp_category="A01:2021 - Broken Access Control",
        severity_range=("Low", "Medium"),
        cvss_range=(4.7, 6.1),
        discoverable_by=["test_injection", "web_crawl"],
        applicable_to=["web_endpoint"],
        requires_params=True,
        chain_potential=False,
        description=(
            "The application accepts a user-controlled URL parameter and "
            "redirects to it without validation, enabling phishing attacks "
            "that abuse the trusted domain name."
        ),
        remediation_template=(
            "Avoid user-controlled redirects.  If required, validate the "
            "target against an allow-list of trusted domains.  Use indirect "
            "references (mapping IDs) instead of raw URLs."
        ),
    ),

    VulnType(
        id="email_misconfig",
        name="Email Server Misconfiguration",
        cwe_ids=[16, 942],
        owasp_category="A05:2021 - Security Misconfiguration",
        severity_range=("Medium", "High"),
        cvss_range=(4.3, 7.5),
        discoverable_by=["test_config", "network_scan", "service_fingerprint"],
        applicable_to=["host_service", "network"],
        requires_params=False,
        chain_potential=False,
        description=(
            "Mail servers are configured as open relays, lack SPF/DKIM/DMARC "
            "records, or expose VRFY/EXPN commands, enabling spam relaying, "
            "email spoofing, and user enumeration."
        ),
        remediation_template=(
            "Disable open relay.  Configure SPF, DKIM, and DMARC DNS records.  "
            "Disable VRFY and EXPN commands.  Require STARTTLS for all "
            "connections.  Restrict SMTP AUTH to authenticated users."
        ),
    ),
]


# ---------------------------------------------------------------------------
# Lookup dictionaries (built once at import time)
# ---------------------------------------------------------------------------

_BY_ID: Dict[str, VulnType] = {vt.id: vt for vt in _VULN_TYPES}
_BY_OWASP: Dict[str, List[VulnType]] = {}
for _vt in _VULN_TYPES:
    _BY_OWASP.setdefault(_vt.owasp_category, []).append(_vt)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_vuln_types() -> Dict[str, VulnType]:
    """Return all vulnerability types keyed by ``id``."""
    return dict(_BY_ID)


def get_vuln_types_for_role(role: str) -> List[VulnType]:
    """Return vulnerability types applicable to a host *role*.

    The *role* string is matched case-insensitively against known keywords
    (e.g. ``"Web Application Server"`` matches ``"web"``).  If no keyword
    matches, all vuln types whose ``applicable_to`` includes
    ``"host_service"`` are returned as a safe default.

    Parameters
    ----------
    role:
        Free-form host role string as used in scenario definitions,
        e.g. ``"Web Application Server"``, ``"Database Server"``,
        ``"Mail Server"``.
    """
    role_lower = role.lower()

    # Find the best-matching keyword.
    matched_ids: List[str] = []
    for keyword, vuln_ids in _ROLE_VULN_AFFINITY.items():
        if keyword in role_lower:
            matched_ids.extend(vuln_ids)

    if matched_ids:
        # Deduplicate while preserving order.
        seen: set[str] = set()
        unique_ids: List[str] = []
        for vid in matched_ids:
            if vid not in seen:
                seen.add(vid)
                unique_ids.append(vid)
        return [_BY_ID[vid] for vid in unique_ids if vid in _BY_ID]

    # Fallback: return all types applicable to host_service.
    return [vt for vt in _VULN_TYPES if "host_service" in vt.applicable_to]


def get_vuln_types_by_owasp(category: str) -> List[VulnType]:
    """Return vulnerability types belonging to the given OWASP category.

    The *category* is matched as a substring (case-insensitive) against
    the stored ``owasp_category`` field so callers can pass either a full
    string like ``"A01:2021 - Broken Access Control"`` or just ``"A01"``.

    Parameters
    ----------
    category:
        Full or partial OWASP Top 10 2021 category identifier.
    """
    cat_lower = category.lower()
    results: List[VulnType] = []
    for owasp_cat, vuln_list in _BY_OWASP.items():
        if cat_lower in owasp_cat.lower():
            results.extend(vuln_list)
    return results
