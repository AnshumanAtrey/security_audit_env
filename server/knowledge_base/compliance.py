"""
Compliance framework mappings for security audit grading.

Maps OWASP Top 10 categories and specific vulnerability types to compliance
controls across PCI-DSS 4.0, SOC 2, HIPAA Security Rule, and ISO 27001:2022.

Sources:
  - PCI-DSS v4.0 Requirements
  - SOC 2 Trust Services Criteria
  - HIPAA Security Rule (45 CFR 164.308-316)
  - ISO 27001:2022 Annex A Controls
"""

from typing import Any, Dict, List


# ---------------------------------------------------------------------------
# Compliance framework mappings -- OWASP category -> framework-specific controls
# ---------------------------------------------------------------------------
COMPLIANCE_MAPPINGS: Dict[str, Dict[str, List[str]]] = {
    "PCI-DSS": {
        "A01:2021": ["PCI-DSS 6.5.8 — Improper Access Control"],
        "A02:2021": [
            "PCI-DSS 4.1 — Strong Cryptography",
            "PCI-DSS 6.5.3 — Insecure Cryptographic Storage",
        ],
        "A03:2021": ["PCI-DSS 6.5.1 — Injection Flaws"],
        "A04:2021": ["PCI-DSS 6.5.5 — Improper Error Handling"],
        "A05:2021": [
            "PCI-DSS 2.2 — Configuration Standards",
            "PCI-DSS 6.5.10 — Broken Auth/Session",
        ],
        "A06:2021": ["PCI-DSS 6.2 — Security Patches"],
        "A07:2021": [
            "PCI-DSS 8.2 — User Authentication",
            "PCI-DSS 2.1 — Default Passwords",
        ],
        "A08:2021": ["PCI-DSS 6.3.1 — Known Vulnerabilities"],
        "A09:2021": ["PCI-DSS 10.2 — Audit Trails"],
        "A10:2021": ["PCI-DSS 6.5.9 — SSRF"],
    },
    "SOC2": {
        "A01:2021": ["CC6.1 — Logical Access Security", "CC6.3 — Role-Based Access"],
        "A02:2021": [
            "CC6.7 — Restrict Data Transmission",
            "C1.1 — Confidentiality Commitments",
        ],
        "A03:2021": [
            "CC6.1 — Logical Access Security",
            "CC6.6 — System Boundaries",
        ],
        "A04:2021": [
            "CC8.1 — Change Management",
            "PI1.1 — Processing Integrity",
        ],
        "A05:2021": [
            "CC6.6 — System Boundaries",
            "CC7.1 — Detect Changes",
        ],
        "A06:2021": [
            "CC7.1 — Detect Changes",
            "CC8.1 — Change Management",
        ],
        "A07:2021": [
            "CC6.1 — Logical Access Security",
            "CC6.2 — Prior to Access",
        ],
        "A08:2021": [
            "CC7.1 — Detect Changes",
            "CC8.1 — Change Management",
        ],
        "A09:2021": [
            "CC4.1 — Monitoring Activities",
            "CC7.2 — System Monitoring",
        ],
        "A10:2021": [
            "CC6.6 — System Boundaries",
            "CC6.1 — Logical Access Security",
        ],
    },
    "HIPAA": {
        "A01:2021": [
            "§164.312(a)(1) — Access Control",
            "§164.308(a)(4) — Information Access Management",
        ],
        "A02:2021": [
            "§164.312(a)(2)(iv) — Encryption and Decryption",
            "§164.312(e)(1) — Transmission Security",
        ],
        "A03:2021": [
            "§164.312(a)(1) — Access Control",
            "§164.308(a)(1) — Security Management Process",
        ],
        "A04:2021": [
            "§164.312(c)(1) — Integrity",
            "§164.308(a)(1) — Security Management Process",
        ],
        "A05:2021": [
            "§164.312(a)(1) — Access Control",
            "§164.308(a)(8) — Evaluation",
        ],
        "A06:2021": [
            "§164.308(a)(1) — Security Management Process",
            "§164.308(a)(8) — Evaluation",
        ],
        "A07:2021": [
            "§164.312(d) — Person or Entity Authentication",
            "§164.312(a)(2)(i) — Unique User Identification",
        ],
        "A08:2021": [
            "§164.308(a)(1) — Security Management Process",
        ],
        "A09:2021": [
            "§164.312(b) — Audit Controls",
            "§164.308(a)(6) — Security Incident Procedures",
        ],
        "A10:2021": [
            "§164.312(a)(1) — Access Control",
            "§164.312(e)(1) — Transmission Security",
        ],
    },
    "Generic": {
        "A01:2021": ["Access Control"],
        "A02:2021": ["Data Protection", "Encryption"],
        "A03:2021": ["Input Validation", "Secure Coding"],
        "A04:2021": ["Secure Design"],
        "A05:2021": ["Configuration Management"],
        "A06:2021": ["Patch Management"],
        "A07:2021": ["Authentication", "Credential Management"],
        "A08:2021": ["Software Composition Analysis"],
        "A09:2021": ["Logging and Monitoring"],
        "A10:2021": ["Network Security"],
    },
}


# ---------------------------------------------------------------------------
# Vulnerability type ID -> compliance controls per framework
# ---------------------------------------------------------------------------
VULN_TYPE_CONTROLS: Dict[str, Dict[str, List[str]]] = {
    "sqli": {
        "PCI-DSS": ["PCI-DSS 6.2.4 — Injection Flaws", "PCI-DSS 6.5.1 — Injection Flaws"],
        "SOC2": ["CC6.1 — Logical Access Security", "CC5.2 — Control Activities"],
        "HIPAA": ["§164.312(a)(1) — Access Control", "§164.308(a)(1) — Security Management Process"],
        "Generic": ["Input Validation", "Secure Coding"],
    },
    "xss": {
        "PCI-DSS": ["PCI-DSS 6.2.4 — Data Attacks", "PCI-DSS 6.5.1 — Injection Flaws"],
        "SOC2": ["CC6.1 — Logical Access Security"],
        "HIPAA": ["§164.312(a)(1) — Access Control"],
        "Generic": ["Input Validation", "Secure Coding"],
    },
    "csrf": {
        "PCI-DSS": ["PCI-DSS 6.2.4 — Data Attacks"],
        "SOC2": ["CC6.1 — Logical Access Security"],
        "HIPAA": ["§164.312(a)(1) — Access Control"],
        "Generic": ["Input Validation", "Secure Coding"],
    },
    "broken_auth": {
        "PCI-DSS": [
            "PCI-DSS 8.2 — User Authentication",
            "PCI-DSS 8.3 — Strong Authentication",
            "PCI-DSS 8.6 — System/Application Accounts",
        ],
        "SOC2": ["CC6.1 — Logical Access Security", "CC6.2 — Prior to Access"],
        "HIPAA": ["§164.312(d) — Person or Entity Authentication"],
        "Generic": ["Authentication", "Credential Management"],
    },
    "broken_access_control": {
        "PCI-DSS": ["PCI-DSS 6.5.8 — Improper Access Control", "PCI-DSS 6.2.4 — Access Control"],
        "SOC2": ["CC6.1 — Logical Access Security", "CC6.3 — Role-Based Access"],
        "HIPAA": ["§164.312(a)(1) — Access Control", "§164.308(a)(4) — Information Access Management"],
        "Generic": ["Access Control"],
    },
    "idor": {
        "PCI-DSS": ["PCI-DSS 6.5.8 — Improper Access Control", "PCI-DSS 6.2.4 — Access Control"],
        "SOC2": ["CC6.1 — Logical Access Security", "CC6.3 — Role-Based Access"],
        "HIPAA": ["§164.312(a)(1) — Access Control", "§164.308(a)(4) — Information Access Management"],
        "Generic": ["Access Control"],
    },
    "security_misconfig": {
        "PCI-DSS": ["PCI-DSS 2.2 — Configuration Standards", "PCI-DSS 6.2.4 — Misconfiguration"],
        "SOC2": ["CC6.1 — Logical Access Security", "CC8.1 — Change Management"],
        "HIPAA": ["§164.312(a)(1) — Access Control"],
        "Generic": ["Configuration Management"],
    },
    "sensitive_data_exposure": {
        "PCI-DSS": [
            "PCI-DSS 3.4 — Render PAN Unreadable",
            "PCI-DSS 3.5 — Protect Encryption Keys",
            "PCI-DSS 4.2 — Protect Data in Transit",
        ],
        "SOC2": ["CC6.1 — Logical Access Security", "CC6.7 — Restrict Data Transmission"],
        "HIPAA": [
            "§164.312(e)(1) — Transmission Security",
            "§164.312(a)(2)(iv) — Encryption and Decryption",
        ],
        "Generic": ["Data Protection", "Encryption"],
    },
    "xxe": {
        "PCI-DSS": ["PCI-DSS 6.2.4 — Injection Flaws"],
        "SOC2": ["CC6.1 — Logical Access Security"],
        "HIPAA": ["§164.312(a)(1) — Access Control"],
        "Generic": ["Input Validation", "Secure Coding"],
    },
    "ssrf": {
        "PCI-DSS": ["PCI-DSS 6.5.9 — SSRF", "PCI-DSS 6.2.4 — Injection Flaws"],
        "SOC2": ["CC6.1 — Logical Access Security"],
        "HIPAA": ["§164.312(a)(1) — Access Control"],
        "Generic": ["Network Security", "Input Validation"],
    },
    "command_injection": {
        "PCI-DSS": ["PCI-DSS 6.2.4 — Injection Flaws", "PCI-DSS 6.5.1 — Injection Flaws"],
        "SOC2": ["CC6.1 — Logical Access Security"],
        "HIPAA": ["§164.312(a)(1) — Access Control"],
        "Generic": ["Input Validation", "Secure Coding"],
    },
    "weak_crypto": {
        "PCI-DSS": [
            "PCI-DSS 4.2 — Protect Data in Transit",
            "PCI-DSS 6.2.4 — Cryptographic Failures",
        ],
        "SOC2": ["CC6.1 — Logical Access Security", "CC6.7 — Restrict Data Transmission"],
        "HIPAA": ["§164.312(e)(1) — Transmission Security"],
        "Generic": ["Data Protection", "Encryption"],
    },
    "session_management": {
        "PCI-DSS": ["PCI-DSS 6.2.4 — Session Management", "PCI-DSS 6.5.10 — Broken Auth/Session"],
        "SOC2": ["CC6.1 — Logical Access Security"],
        "HIPAA": ["§164.312(a)(2)(iii) — Automatic Logoff"],
        "Generic": ["Authentication", "Secure Coding"],
    },
    "missing_headers": {
        "PCI-DSS": ["PCI-DSS 6.2.4 — Security Headers"],
        "SOC2": ["CC6.1 — Logical Access Security"],
        "HIPAA": ["§164.312(a)(1) — Access Control"],
        "Generic": ["Configuration Management"],
    },
    "file_upload": {
        "PCI-DSS": ["PCI-DSS 6.2.4 — Business Logic"],
        "SOC2": ["CC6.8 — Prevent/Detect Unauthorized Software"],
        "HIPAA": ["§164.312(a)(1) — Access Control"],
        "Generic": ["Input Validation", "Secure Coding"],
    },
    "privilege_escalation": {
        "PCI-DSS": ["PCI-DSS 6.5.8 — Improper Access Control", "PCI-DSS 6.2.4 — Access Control"],
        "SOC2": ["CC6.1 — Logical Access Security", "CC6.3 — Role-Based Access"],
        "HIPAA": ["§164.308(a)(4) — Information Access Management"],
        "Generic": ["Access Control"],
    },
    "default_credentials": {
        "PCI-DSS": ["PCI-DSS 2.1 — Default Passwords", "PCI-DSS 8.6 — System/Application Accounts"],
        "SOC2": ["CC6.1 — Logical Access Security", "CC6.2 — Prior to Access"],
        "HIPAA": ["§164.312(d) — Person or Entity Authentication"],
        "Generic": ["Authentication", "Credential Management"],
    },
    "weak_credentials": {
        "PCI-DSS": ["PCI-DSS 8.2 — User Authentication", "PCI-DSS 2.1 — Default Passwords"],
        "SOC2": ["CC6.1 — Logical Access Security", "CC6.2 — Prior to Access"],
        "HIPAA": ["§164.312(d) — Person or Entity Authentication"],
        "Generic": ["Authentication", "Credential Management"],
    },
    "ssti": {
        "PCI-DSS": ["PCI-DSS 6.2.4 — Injection Flaws"],
        "SOC2": ["CC6.1 — Logical Access Security"],
        "HIPAA": ["§164.312(a)(1) — Access Control"],
        "Generic": ["Input Validation", "Secure Coding"],
    },
    "insecure_deserialization": {
        "PCI-DSS": ["PCI-DSS 6.2.4 — Deserialization"],
        "SOC2": ["CC6.1 — Logical Access Security"],
        "HIPAA": ["§164.312(a)(1) — Access Control"],
        "Generic": ["Input Validation", "Secure Coding"],
    },
    "directory_traversal": {
        "PCI-DSS": ["PCI-DSS 6.2.4 — Injection Flaws"],
        "SOC2": ["CC6.1 — Logical Access Security"],
        "HIPAA": ["§164.312(a)(1) — Access Control"],
        "Generic": ["Input Validation", "Access Control"],
    },
    "info_disclosure": {
        "PCI-DSS": ["PCI-DSS 6.5 — Information Exposure"],
        "SOC2": ["CC6.1 — Logical Access Security"],
        "HIPAA": ["§164.312(a)(1) — Access Control"],
        "Generic": ["Configuration Management"],
    },
    "insufficient_logging": {
        "PCI-DSS": ["PCI-DSS 10.1 — Logging", "PCI-DSS 10.2 — Audit Trails"],
        "SOC2": ["CC7.1 — Detect Changes", "CC7.2 — System Monitoring"],
        "HIPAA": ["§164.312(b) — Audit Controls"],
        "Generic": ["Logging and Monitoring"],
    },
    "weak_tls": {
        "PCI-DSS": ["PCI-DSS 4.2.1 — Strong Cryptography in Transit"],
        "SOC2": ["CC6.7 — Restrict Data Transmission"],
        "HIPAA": ["§164.312(e)(1) — Transmission Security"],
        "Generic": ["Data Protection", "Encryption"],
    },
    "cors_misconfig": {
        "PCI-DSS": ["PCI-DSS 6.2.4 — Cross-Origin Security"],
        "SOC2": ["CC6.1 — Logical Access Security"],
        "HIPAA": ["§164.312(a)(1) — Access Control"],
        "Generic": ["Configuration Management"],
    },
    "open_redirect": {
        "PCI-DSS": ["PCI-DSS 6.2.4 — Redirect Flaws"],
        "SOC2": ["CC6.1 — Logical Access Security"],
        "HIPAA": ["§164.312(a)(1) — Access Control"],
        "Generic": ["Input Validation"],
    },
    "clickjacking": {
        "PCI-DSS": ["PCI-DSS 6.2.4 — UI Redressing"],
        "SOC2": ["CC6.1 — Logical Access Security"],
        "HIPAA": ["§164.312(a)(1) — Access Control"],
        "Generic": ["Configuration Management"],
    },
    "unpatched_software": {
        "PCI-DSS": ["PCI-DSS 6.3.3 — Security Patches"],
        "SOC2": ["CC7.1 — Detect Changes"],
        "HIPAA": ["§164.308(a)(1) — Security Management Process"],
        "Generic": ["Patch Management"],
    },
    "vulnerable_component": {
        "PCI-DSS": ["PCI-DSS 6.3.1 — Known Vulnerabilities"],
        "SOC2": ["CC7.1 — Detect Changes", "CC8.1 — Change Management"],
        "HIPAA": ["§164.308(a)(1) — Security Management Process"],
        "Generic": ["Software Composition Analysis"],
    },
    "missing_encryption": {
        "PCI-DSS": [
            "PCI-DSS 4.1 — Strong Cryptography",
            "PCI-DSS 6.5.3 — Insecure Cryptographic Storage",
        ],
        "SOC2": ["CC6.7 — Restrict Data Transmission", "C1.1 — Confidentiality Commitments"],
        "HIPAA": [
            "§164.312(a)(2)(iv) — Encryption and Decryption",
            "§164.312(e)(1) — Transmission Security",
        ],
        "Generic": ["Data Protection", "Encryption"],
    },
    "missing_rate_limiting": {
        "PCI-DSS": ["PCI-DSS 6.2.4 — Business Logic"],
        "SOC2": ["CC6.1 — Logical Access Security"],
        "HIPAA": ["§164.312(a)(1) — Access Control"],
        "Generic": ["Secure Design"],
    },
    "business_logic": {
        "PCI-DSS": ["PCI-DSS 6.2.4 — Business Logic"],
        "SOC2": ["CC8.1 — Change Management", "PI1.1 — Processing Integrity"],
        "HIPAA": ["§164.312(c)(1) — Integrity"],
        "Generic": ["Secure Design"],
    },
    "network_segmentation": {
        "PCI-DSS": ["PCI-DSS 11.4.5 — Network Segmentation Testing"],
        "SOC2": ["CC6.6 — System Boundaries"],
        "HIPAA": ["§164.312(a)(1) — Access Control"],
        "Generic": ["Network Security"],
    },
    "email_security_misconfig": {
        "PCI-DSS": ["PCI-DSS 2.2 — Configuration Standards"],
        "SOC2": ["CC6.1 — Logical Access Security"],
        "HIPAA": ["§164.312(a)(1) — Access Control"],
        "Generic": ["Configuration Management"],
    },
    "bola": {
        "PCI-DSS": ["PCI-DSS 6.5.8 — Improper Access Control"],
        "SOC2": ["CC6.1 — Logical Access Security", "CC6.3 — Role-Based Access"],
        "HIPAA": ["§164.312(a)(1) — Access Control", "§164.308(a)(4) — Information Access Management"],
        "Generic": ["Access Control"],
    },
    "stored_xss": {
        "PCI-DSS": ["PCI-DSS 6.2.4 — Data Attacks", "PCI-DSS 6.5.1 — Injection Flaws"],
        "SOC2": ["CC6.1 — Logical Access Security"],
        "HIPAA": ["§164.312(a)(1) — Access Control"],
        "Generic": ["Input Validation", "Secure Coding"],
    },
    "crypto_failures": {
        "PCI-DSS": [
            "PCI-DSS 4.1 — Strong Cryptography",
            "PCI-DSS 6.5.3 — Insecure Cryptographic Storage",
        ],
        "SOC2": ["CC6.7 — Restrict Data Transmission", "C1.1 — Confidentiality Commitments"],
        "HIPAA": [
            "§164.312(a)(2)(iv) — Encryption and Decryption",
            "§164.312(e)(1) — Transmission Security",
        ],
        "Generic": ["Data Protection", "Encryption"],
    },
}


# ---------------------------------------------------------------------------
# Framework detection keywords
# ---------------------------------------------------------------------------
_FRAMEWORK_KEYWORDS: Dict[str, str] = {
    "PCI-DSS": "PCI-DSS",
    "pci": "PCI-DSS",
    "SOC2": "SOC2",
    "SOC 2": "SOC2",
    "soc2": "SOC2",
    "HIPAA": "HIPAA",
    "hipaa": "HIPAA",
}


# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------


def get_framework_mappings(framework: str) -> Dict[str, List[str]]:
    """Return OWASP category -> controls mapping for *framework*.

    Falls back to ``"Generic"`` if the framework is not recognized.
    """
    return COMPLIANCE_MAPPINGS.get(framework, COMPLIANCE_MAPPINGS["Generic"])


def get_controls_for_vuln(vuln_type_id: str, framework: str) -> List[str]:
    """Return compliance controls that apply to *vuln_type_id* under *framework*.

    Returns an empty list when there is no mapping for the given combination.
    The *vuln_type_id* is matched case-insensitively and with spaces/hyphens
    normalised to underscores so callers can pass e.g. ``"SQL Injection"``
    or ``"sqli"`` interchangeably.
    """
    key = _normalize_vuln_id(vuln_type_id)
    entry = VULN_TYPE_CONTROLS.get(key, {})
    return entry.get(framework, entry.get("Generic", []))


def detect_framework(scenario: Dict[str, Any]) -> str:
    """Detect compliance framework from scenario metadata.

    Inspects the ``compliance_context`` field of *scenario* and returns the
    first matching framework name (``"PCI-DSS"``, ``"SOC2"``, ``"HIPAA"``).
    Returns ``"Generic"`` when no keyword matches.
    """
    ctx = scenario.get("compliance_context", "")
    for keyword, framework in _FRAMEWORK_KEYWORDS.items():
        if keyword.lower() in ctx.lower():
            return framework
    return "Generic"


def get_all_frameworks() -> List[str]:
    """Return all supported compliance framework names."""
    return ["PCI-DSS", "SOC2", "HIPAA", "Generic"]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# Aliases that map human-readable vulnerability names (lowered, underscored)
# to canonical VULN_TYPE_CONTROLS keys.
_VULN_ID_ALIASES: Dict[str, str] = {
    "sql_injection": "sqli",
    "sql injection": "sqli",
    "cross_site_scripting": "xss",
    "reflected_xss": "xss",
    "stored xss": "stored_xss",
    "cross_site_request_forgery": "csrf",
    "broken_authentication": "broken_auth",
    "broken authentication": "broken_auth",
    "broken_access_control": "broken_access_control",
    "broken access control": "broken_access_control",
    "broken access control (idor)": "idor",
    "broken access control (bola)": "bola",
    "security_misconfiguration": "security_misconfig",
    "security misconfiguration": "security_misconfig",
    "sensitive_data_exposure": "sensitive_data_exposure",
    "sensitive data exposure": "sensitive_data_exposure",
    "xml_external_entities": "xxe",
    "server_side_request_forgery": "ssrf",
    "server-side request forgery (ssrf)": "ssrf",
    "server_side_template_injection": "ssti",
    "server-side template injection (ssti)": "ssti",
    "command_injection": "command_injection",
    "weak_cryptography": "weak_crypto",
    "cryptographic failures": "crypto_failures",
    "cryptographic_failures": "crypto_failures",
    "session_management_flaws": "session_management",
    "missing_security_headers": "missing_headers",
    "file_upload_vulnerabilities": "file_upload",
    "unrestricted file upload": "file_upload",
    "unrestricted_file_upload": "file_upload",
    "privilege_escalation": "privilege_escalation",
    "default_credentials": "default_credentials",
    "weak_credentials": "weak_credentials",
    "weak credentials": "weak_credentials",
    "insecure_deserialization": "insecure_deserialization",
    "directory_traversal": "directory_traversal",
    "information_disclosure": "info_disclosure",
    "insufficient_logging": "insufficient_logging",
    "weak_tls": "weak_tls",
    "weak_tls_ssl": "weak_tls",
    "cors_misconfiguration": "cors_misconfig",
    "open_redirect": "open_redirect",
    "clickjacking": "clickjacking",
    "unpatched_software": "unpatched_software",
    "vulnerable_component": "vulnerable_component",
    "vulnerable component": "vulnerable_component",
    "missing_encryption": "missing_encryption",
    "missing encryption": "missing_encryption",
    "missing_rate_limiting": "missing_rate_limiting",
    "missing rate limiting": "missing_rate_limiting",
    "business_logic_flaw": "business_logic",
    "business logic flaw": "business_logic",
    "network_segmentation_failure": "network_segmentation",
    "email_security_misconfiguration": "email_security_misconfig",
    "email security misconfiguration": "email_security_misconfig",
}


def _normalize_vuln_id(raw: str) -> str:
    """Normalize a vulnerability type string to a canonical key.

    Lowercases, replaces hyphens and spaces with underscores, then looks up
    the alias table.  Returns the canonical key if found, otherwise the
    normalised string itself (allowing direct matches against
    ``VULN_TYPE_CONTROLS``).
    """
    lowered = raw.strip().lower()
    # Try exact match first (already a canonical key)
    if lowered in VULN_TYPE_CONTROLS:
        return lowered

    # Try alias table with original casing (for mixed-case entries like "(SSRF)")
    if lowered in _VULN_ID_ALIASES:
        return _VULN_ID_ALIASES[lowered]

    # Normalise separators and retry
    normalised = lowered.replace("-", "_").replace(" ", "_")
    if normalised in VULN_TYPE_CONTROLS:
        return normalised
    return _VULN_ID_ALIASES.get(normalised, normalised)
