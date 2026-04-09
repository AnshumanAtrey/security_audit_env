"""
Response templates for simulated security tool output.

Each vulnerability type has templates for three difficulty tiers:
  - easy:   Labeled output with severity tags, CWE, CVSS, remediation.
  - medium: Evidence-based output requiring analyst interpretation.
  - hard:   Raw HTTP/tool output requiring full analysis.

Templates use Python str.format() named variables.  The tool simulation
engine fills in context variables to generate realistic output.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Data class
# ---------------------------------------------------------------------------

@dataclass
class ResponseTemplate:
    """Response template for a single vulnerability type."""

    vuln_type_id: str
    vulnerable: Dict[str, str]  # keys: "easy", "medium", "hard"
    safe: str  # what a clean / non-vulnerable response looks like
    context_vars: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Template registry (module-level singleton)
# ---------------------------------------------------------------------------

_TEMPLATES: Dict[str, ResponseTemplate] = {}


def _register(t: ResponseTemplate) -> None:
    _TEMPLATES[t.vuln_type_id] = t


# ===================================================================
# 1. SQL Injection
# ===================================================================
_register(ResponseTemplate(
    vuln_type_id="sqli",
    vulnerable={
        "easy": (
            "[CRITICAL] SQL Injection DETECTED\n"
            "  Host: {host}\n"
            "  Endpoint: {endpoint}\n"
            "  Parameter: {parameter}\n"
            "  CWE: {cwe}\n"
            "  CVSS: {cvss}\n"
            "  OWASP: {owasp}\n"
            "  Payload: {payload}\n"
            "  Evidence: {evidence_detail}\n"
            "  Remediation: {remediation}"
        ),
        "medium": (
            "[!] Anomalous database response detected\n"
            "  Host: {host}\n"
            "  Endpoint: {endpoint}\n"
            "  Parameter: {parameter}\n"
            "  Payload sent: {payload}\n"
            "  {evidence_detail}\n"
            "  Assess the vulnerability type, severity, and impact."
        ),
        "hard": (
            "Parameter: {parameter} | Payload: {payload}\n"
            "  Response: HTTP {status_code}\n"
            "  Body (first 200 chars): {response_body}\n"
            "  Timing: {response_time}ms"
        ),
    },
    safe=(
        "HTTP/1.1 400 Bad Request\n"
        "Content-Type: application/json\n\n"
        '{{"error": "Invalid input", "message": "The provided value is not valid"}}\n\n'
        "No SQL injection indicators found on {host} {endpoint}. "
        "Input appears to be parameterized. No database error messages leaked."
    ),
    context_vars=[
        "host", "endpoint", "parameter", "payload", "cvss", "cwe",
        "severity", "owasp", "service_version", "evidence_detail",
        "remediation", "status_code", "response_body", "response_time",
    ],
))

# ===================================================================
# 2. Stored XSS
# ===================================================================
_register(ResponseTemplate(
    vuln_type_id="xss_stored",
    vulnerable={
        "easy": (
            "[HIGH] Stored Cross-Site Scripting (XSS) DETECTED\n"
            "  Host: {host}\n"
            "  Endpoint: {endpoint}\n"
            "  Parameter: {parameter}\n"
            "  CWE: {cwe}\n"
            "  CVSS: {cvss}\n"
            "  OWASP: {owasp}\n"
            "  Payload: {payload}\n"
            "  Evidence: {evidence_detail}\n"
            "  Remediation: {remediation}"
        ),
        "medium": (
            "[!] Unsanitized user input rendered in stored content\n"
            "  Host: {host}\n"
            "  Endpoint: {endpoint}\n"
            "  Parameter: {parameter}\n"
            "  Submitted payload was echoed without encoding in a subsequent page load.\n"
            "  {evidence_detail}\n"
            "  Assess the vulnerability type, severity, and impact."
        ),
        "hard": (
            "Parameter: {parameter} | Payload: {payload}\n"
            "  POST {endpoint} -> HTTP {status_code}\n"
            "  Subsequent GET response body (first 200 chars): {response_body}\n"
            "  Timing: {response_time}ms\n"
            "  Note: Payload present in DOM on later page render."
        ),
    },
    safe=(
        "HTTP/1.1 200 OK\n"
        "Content-Type: text/html; charset=utf-8\n"
        "Content-Security-Policy: default-src 'self'; script-src 'self'\n"
        "X-Content-Type-Options: nosniff\n\n"
        "Stored input was HTML-entity encoded on output. "
        "No executable script rendered. CSP header present on {host} {endpoint}."
    ),
    context_vars=[
        "host", "endpoint", "parameter", "payload", "cvss", "cwe",
        "severity", "owasp", "evidence_detail", "remediation",
        "status_code", "response_body", "response_time",
    ],
))

# ===================================================================
# 3. Reflected XSS
# ===================================================================
_register(ResponseTemplate(
    vuln_type_id="xss_reflected",
    vulnerable={
        "easy": (
            "[HIGH] Reflected Cross-Site Scripting (XSS) DETECTED\n"
            "  Host: {host}\n"
            "  Endpoint: {endpoint}\n"
            "  Parameter: {parameter}\n"
            "  CWE: {cwe}\n"
            "  CVSS: {cvss}\n"
            "  OWASP: {owasp}\n"
            "  Payload: {payload}\n"
            "  Evidence: {evidence_detail}\n"
            "  Remediation: {remediation}"
        ),
        "medium": (
            "[!] Reflected input in HTTP response without encoding\n"
            "  Host: {host}\n"
            "  Endpoint: {endpoint}\n"
            "  Parameter: {parameter}\n"
            "  The payload was reflected directly into the HTML response.\n"
            "  X-XSS-Protection header: not set\n"
            "  Content-Security-Policy: not set\n"
            "  {evidence_detail}\n"
            "  Assess the vulnerability type, severity, and impact."
        ),
        "hard": (
            "Parameter: {parameter} | Payload: {payload}\n"
            "  Response: HTTP {status_code}\n"
            "  Body (first 200 chars): {response_body}\n"
            "  Timing: {response_time}ms"
        ),
    },
    safe=(
        "HTTP/1.1 200 OK\n"
        "X-XSS-Protection: 1; mode=block\n"
        "Content-Security-Policy: default-src 'self'\n\n"
        "Payload was HTML-entity encoded in response "
        "(&lt;script&gt; rendered as text). No reflected XSS on {host} {endpoint}."
    ),
    context_vars=[
        "host", "endpoint", "parameter", "payload", "cvss", "cwe",
        "severity", "owasp", "evidence_detail", "remediation",
        "status_code", "response_body", "response_time",
    ],
))

# ===================================================================
# 4. Server-Side Request Forgery (SSRF)
# ===================================================================
_register(ResponseTemplate(
    vuln_type_id="ssrf",
    vulnerable={
        "easy": (
            "[CRITICAL] Server-Side Request Forgery (SSRF) DETECTED\n"
            "  Host: {host}\n"
            "  Endpoint: {endpoint}\n"
            "  Parameter: {parameter}\n"
            "  CWE: {cwe}\n"
            "  CVSS: {cvss}\n"
            "  OWASP: {owasp}\n"
            "  Payload: {payload}\n"
            "  Evidence: {evidence_detail}\n"
            "  Remediation: {remediation}"
        ),
        "medium": (
            "[!] Internal resource accessible via user-controlled URL\n"
            "  Host: {host}\n"
            "  Endpoint: {endpoint}\n"
            "  Parameter: {parameter}\n"
            "  The server fetched an internal resource and returned its content.\n"
            "  {evidence_detail}\n"
            "  Assess the vulnerability type, severity, and impact."
        ),
        "hard": (
            "Parameter: {parameter} | Payload: {payload}\n"
            "  Response: HTTP {status_code}\n"
            "  Body (first 200 chars): {response_body}\n"
            "  Timing: {response_time}ms"
        ),
    },
    safe=(
        "HTTP/1.1 400 Bad Request\n"
        "Content-Type: application/json\n\n"
        '{{"error": "Invalid URL", "message": "The requested URL is not allowed. '
        'Only external HTTP/HTTPS URLs are permitted."}}\n\n'
        "URL scheme and host validated on {host} {endpoint}. "
        "Internal/private IP ranges blocked."
    ),
    context_vars=[
        "host", "endpoint", "parameter", "payload", "cvss", "cwe",
        "severity", "owasp", "evidence_detail", "remediation",
        "status_code", "response_body", "response_time",
    ],
))

# ===================================================================
# 5. Server-Side Template Injection (SSTI)
# ===================================================================
_register(ResponseTemplate(
    vuln_type_id="ssti",
    vulnerable={
        "easy": (
            "[CRITICAL] Server-Side Template Injection (SSTI) DETECTED\n"
            "  Host: {host}\n"
            "  Endpoint: {endpoint}\n"
            "  Parameter: {parameter}\n"
            "  CWE: {cwe}\n"
            "  CVSS: {cvss}\n"
            "  OWASP: {owasp}\n"
            "  Payload: {payload}\n"
            "  Evidence: {evidence_detail}\n"
            "  Remediation: {remediation}"
        ),
        "medium": (
            "[!] Template expression evaluated in server response\n"
            "  Host: {host}\n"
            "  Endpoint: {endpoint}\n"
            "  Parameter: {parameter}\n"
            "  The input '{{{{7*7}}}}' was rendered as '49' in the response body, "
            "confirming server-side template evaluation.\n"
            "  {evidence_detail}\n"
            "  Assess the vulnerability type, severity, and impact."
        ),
        "hard": (
            "Parameter: {parameter} | Payload: {payload}\n"
            "  Response: HTTP {status_code}\n"
            "  Body (first 200 chars): {response_body}\n"
            "  Timing: {response_time}ms"
        ),
    },
    safe=(
        "HTTP/1.1 200 OK\n"
        "Content-Type: text/html\n\n"
        "Template expression rendered as literal text (not evaluated). "
        "No SSTI on {host} {endpoint}. Sandboxed template engine in use."
    ),
    context_vars=[
        "host", "endpoint", "parameter", "payload", "cvss", "cwe",
        "severity", "owasp", "evidence_detail", "remediation",
        "status_code", "response_body", "response_time",
    ],
))

# ===================================================================
# 6. Command Injection
# ===================================================================
_register(ResponseTemplate(
    vuln_type_id="command_injection",
    vulnerable={
        "easy": (
            "[CRITICAL] OS Command Injection DETECTED\n"
            "  Host: {host}\n"
            "  Endpoint: {endpoint}\n"
            "  Parameter: {parameter}\n"
            "  CWE: {cwe}\n"
            "  CVSS: {cvss}\n"
            "  OWASP: {owasp}\n"
            "  Payload: {payload}\n"
            "  Evidence: {evidence_detail}\n"
            "  Remediation: {remediation}"
        ),
        "medium": (
            "[!] OS command output detected in application response\n"
            "  Host: {host}\n"
            "  Endpoint: {endpoint}\n"
            "  Parameter: {parameter}\n"
            "  Injected shell metacharacters produced unexpected output "
            "consistent with command execution.\n"
            "  {evidence_detail}\n"
            "  Assess the vulnerability type, severity, and impact."
        ),
        "hard": (
            "Parameter: {parameter} | Payload: {payload}\n"
            "  Response: HTTP {status_code}\n"
            "  Body (first 200 chars): {response_body}\n"
            "  Timing: {response_time}ms"
        ),
    },
    safe=(
        "HTTP/1.1 400 Bad Request\n"
        "Content-Type: application/json\n\n"
        '{{"error": "Invalid input", "message": "The hostname contains invalid characters"}}\n\n'
        "Shell metacharacters rejected on {host} {endpoint}. "
        "Input validated against allowlist. No command execution observed."
    ),
    context_vars=[
        "host", "endpoint", "parameter", "payload", "cvss", "cwe",
        "severity", "owasp", "evidence_detail", "remediation",
        "status_code", "response_body", "response_time",
    ],
))

# ===================================================================
# 7. Insecure Direct Object Reference (IDOR)
# ===================================================================
_register(ResponseTemplate(
    vuln_type_id="idor",
    vulnerable={
        "easy": (
            "[HIGH] Insecure Direct Object Reference (IDOR) DETECTED\n"
            "  Host: {host}\n"
            "  Endpoint: {endpoint}\n"
            "  Parameter: {parameter}\n"
            "  CWE: {cwe}\n"
            "  CVSS: {cvss}\n"
            "  OWASP: {owasp}\n"
            "  Evidence: {evidence_detail}\n"
            "  Remediation: {remediation}"
        ),
        "medium": (
            "[!] Unauthorized object access via parameter manipulation\n"
            "  Host: {host}\n"
            "  Endpoint: {endpoint}\n"
            "  Parameter: {parameter}\n"
            "  Modifying the object identifier returned data belonging to a "
            "different user/entity. No authorization check observed.\n"
            "  {evidence_detail}\n"
            "  Assess the vulnerability type, severity, and impact."
        ),
        "hard": (
            "Parameter: {parameter} | Payload: {payload}\n"
            "  Response: HTTP {status_code}\n"
            "  Body (first 200 chars): {response_body}\n"
            "  Timing: {response_time}ms"
        ),
    },
    safe=(
        "HTTP/1.1 403 Forbidden\n"
        "Content-Type: application/json\n\n"
        '{{"error": "Forbidden", "message": "You do not have permission to access this resource"}}\n\n'
        "Object-level authorization enforced on {host} {endpoint}. "
        "Attempts to access other users' resources returned 403."
    ),
    context_vars=[
        "host", "endpoint", "parameter", "payload", "cvss", "cwe",
        "severity", "owasp", "evidence_detail", "remediation",
        "status_code", "response_body", "response_time",
    ],
))

# ===================================================================
# 8. Path Traversal
# ===================================================================
_register(ResponseTemplate(
    vuln_type_id="path_traversal",
    vulnerable={
        "easy": (
            "[HIGH] Path Traversal / Local File Inclusion DETECTED\n"
            "  Host: {host}\n"
            "  Endpoint: {endpoint}\n"
            "  Parameter: {parameter}\n"
            "  CWE: {cwe}\n"
            "  CVSS: {cvss}\n"
            "  OWASP: {owasp}\n"
            "  Payload: {payload}\n"
            "  Evidence: {evidence_detail}\n"
            "  Remediation: {remediation}"
        ),
        "medium": (
            "[!] Unexpected file content returned via path manipulation\n"
            "  Host: {host}\n"
            "  Endpoint: {endpoint}\n"
            "  Parameter: {parameter}\n"
            "  Payload: {payload}\n"
            "  Response contained content consistent with a system file "
            "(e.g., /etc/passwd format).\n"
            "  {evidence_detail}\n"
            "  Assess the vulnerability type, severity, and impact."
        ),
        "hard": (
            "Parameter: {parameter} | Payload: {payload}\n"
            "  Response: HTTP {status_code}\n"
            "  Body (first 200 chars): {response_body}\n"
            "  Timing: {response_time}ms"
        ),
    },
    safe=(
        "HTTP/1.1 400 Bad Request\n"
        "Content-Type: application/json\n\n"
        '{{"error": "Invalid file path", "message": "Path traversal characters are not allowed"}}\n\n'
        "Path traversal sequences stripped/rejected on {host} {endpoint}. "
        "File access restricted to allowed directory."
    ),
    context_vars=[
        "host", "endpoint", "parameter", "payload", "cvss", "cwe",
        "severity", "owasp", "evidence_detail", "remediation",
        "status_code", "response_body", "response_time",
    ],
))

# ===================================================================
# 9. XML External Entity (XXE)
# ===================================================================
_register(ResponseTemplate(
    vuln_type_id="xxe",
    vulnerable={
        "easy": (
            "[HIGH] XML External Entity Injection (XXE) DETECTED\n"
            "  Host: {host}\n"
            "  Endpoint: {endpoint}\n"
            "  Parameter: {parameter}\n"
            "  CWE: {cwe}\n"
            "  CVSS: {cvss}\n"
            "  OWASP: {owasp}\n"
            "  Payload: {payload}\n"
            "  Evidence: {evidence_detail}\n"
            "  Remediation: {remediation}"
        ),
        "medium": (
            "[!] XML parser resolved external entity\n"
            "  Host: {host}\n"
            "  Endpoint: {endpoint}\n"
            "  Parameter: {parameter}\n"
            "  A DOCTYPE declaration with an external entity was processed. "
            "The entity content appeared in the response body.\n"
            "  {evidence_detail}\n"
            "  Assess the vulnerability type, severity, and impact."
        ),
        "hard": (
            "Parameter: {parameter} | Payload: {payload}\n"
            "  Response: HTTP {status_code}\n"
            "  Body (first 200 chars): {response_body}\n"
            "  Timing: {response_time}ms"
        ),
    },
    safe=(
        "HTTP/1.1 400 Bad Request\n"
        "Content-Type: application/json\n\n"
        '{{"error": "XML parsing error", "message": "DOCTYPE declarations are not allowed"}}\n\n'
        "External entity processing disabled on {host} {endpoint}. "
        "DTD processing rejected by parser configuration."
    ),
    context_vars=[
        "host", "endpoint", "parameter", "payload", "cvss", "cwe",
        "severity", "owasp", "evidence_detail", "remediation",
        "status_code", "response_body", "response_time",
    ],
))

# ===================================================================
# 10. Broken Authentication
# ===================================================================
_register(ResponseTemplate(
    vuln_type_id="broken_auth",
    vulnerable={
        "easy": (
            "[CRITICAL] Broken Authentication DETECTED\n"
            "  Host: {host}\n"
            "  Endpoint: {endpoint}\n"
            "  CWE: {cwe}\n"
            "  CVSS: {cvss}\n"
            "  OWASP: {owasp}\n"
            "  Evidence: {evidence_detail}\n"
            "  Remediation: {remediation}"
        ),
        "medium": (
            "[!] Authentication bypass confirmed\n"
            "  Host: {host}\n"
            "  Endpoint: {endpoint}\n"
            "  Login was bypassed using SQL injection in the authentication query. "
            "Session cookie set without valid credentials.\n"
            "  {evidence_detail}\n"
            "  Assess the vulnerability type, severity, and impact."
        ),
        "hard": (
            "POST {endpoint}\n"
            "  Payload: {payload}\n"
            "  Response: HTTP {status_code}\n"
            "  Headers: Set-Cookie: session=eyJhbGciOiJIUzI1NiJ9...; Path=/; HttpOnly\n"
            "  Location: /dashboard\n"
            "  Body (first 200 chars): {response_body}\n"
            "  Timing: {response_time}ms"
        ),
    },
    safe=(
        "HTTP/1.1 401 Unauthorized\n"
        "Content-Type: application/json\n\n"
        '{{"error": "Authentication failed", "message": "Invalid username or password"}}\n\n'
        "Login endpoint on {host} {endpoint} correctly rejected invalid credentials. "
        "Generic error message returned. No session created."
    ),
    context_vars=[
        "host", "endpoint", "parameter", "payload", "cvss", "cwe",
        "severity", "owasp", "evidence_detail", "remediation",
        "status_code", "response_body", "response_time",
    ],
))

# ===================================================================
# 11. Default Credentials
# ===================================================================
_register(ResponseTemplate(
    vuln_type_id="default_credentials",
    vulnerable={
        "easy": (
            "[CRITICAL] Default Credentials DETECTED\n"
            "  Host: {host}\n"
            "  Endpoint: {endpoint}\n"
            "  Service: {service_version}\n"
            "  CWE: {cwe}\n"
            "  CVSS: {cvss}\n"
            "  OWASP: {owasp}\n"
            "  Evidence: {evidence_detail}\n"
            "  Remediation: {remediation}"
        ),
        "medium": (
            "[!] Service login accepted well-known default credentials\n"
            "  Host: {host}\n"
            "  Endpoint: {endpoint}\n"
            "  Service: {service_version}\n"
            "  Login succeeded with a commonly known default username/password pair. "
            "Administrative access was granted.\n"
            "  {evidence_detail}\n"
            "  Assess the vulnerability type, severity, and impact."
        ),
        "hard": (
            "POST {endpoint}\n"
            "  Credentials tested: {payload}\n"
            "  Response: HTTP {status_code}\n"
            "  Headers: Set-Cookie: JSESSIONID=ABC123; Path=/\n"
            "  Location: /manager/html\n"
            "  Body (first 200 chars): {response_body}\n"
            "  Timing: {response_time}ms"
        ),
    },
    safe=(
        "HTTP/1.1 401 Unauthorized\n"
        "Content-Type: text/html\n\n"
        "All tested default credential pairs were rejected on {host} {endpoint}. "
        "Service {service_version} appears to have had its default password changed."
    ),
    context_vars=[
        "host", "endpoint", "parameter", "payload", "cvss", "cwe",
        "severity", "owasp", "service_version", "evidence_detail",
        "remediation", "status_code", "response_body", "response_time",
    ],
))

# ===================================================================
# 12. Weak Credentials
# ===================================================================
_register(ResponseTemplate(
    vuln_type_id="weak_credentials",
    vulnerable={
        "easy": (
            "[HIGH] Weak Credentials DETECTED\n"
            "  Host: {host}\n"
            "  Endpoint: {endpoint}\n"
            "  Service: {service_version}\n"
            "  CWE: {cwe}\n"
            "  CVSS: {cvss}\n"
            "  OWASP: {owasp}\n"
            "  Evidence: {evidence_detail}\n"
            "  Remediation: {remediation}"
        ),
        "medium": (
            "[!] Weak password accepted for user account\n"
            "  Host: {host}\n"
            "  Endpoint: {endpoint}\n"
            "  Service: {service_version}\n"
            "  A commonly guessable password was accepted after minimal brute-force "
            "attempts. No account lockout or rate limiting was observed.\n"
            "  {evidence_detail}\n"
            "  Assess the vulnerability type, severity, and impact."
        ),
        "hard": (
            "POST {endpoint}\n"
            "  Attempt #{payload}\n"
            "  Response: HTTP {status_code}\n"
            "  Body (first 200 chars): {response_body}\n"
            "  Timing: {response_time}ms\n"
            "  Note: No X-RateLimit-* headers. No CAPTCHA challenge. "
            "No account lockout after 100+ failed attempts."
        ),
    },
    safe=(
        "HTTP/1.1 401 Unauthorized\n"
        "X-RateLimit-Remaining: 0\n"
        "Retry-After: 300\n\n"
        "Brute-force testing on {host} {endpoint} was rate-limited after 5 attempts. "
        "Account lockout triggered. Strong password policy enforced."
    ),
    context_vars=[
        "host", "endpoint", "parameter", "payload", "cvss", "cwe",
        "severity", "owasp", "service_version", "evidence_detail",
        "remediation", "status_code", "response_body", "response_time",
    ],
))

# ===================================================================
# 13. Weak TLS / Cryptographic Failures
# ===================================================================
_register(ResponseTemplate(
    vuln_type_id="weak_tls",
    vulnerable={
        "easy": (
            "[MEDIUM] Weak TLS Configuration DETECTED\n"
            "  Host: {host}\n"
            "  Port: {port}\n"
            "  CWE: {cwe}\n"
            "  CVSS: {cvss}\n"
            "  OWASP: {owasp}\n"
            "  Evidence: {evidence_detail}\n"
            "  Remediation: {remediation}"
        ),
        "medium": (
            "[!] Deprecated TLS protocol and/or weak cipher suites offered\n"
            "  Host: {host}\n"
            "  Port: {port}\n"
            "  ssl-enum-ciphers results:\n"
            "    SSLv3: OFFERED (insecure)\n"
            "    TLSv1.0: OFFERED (deprecated)\n"
            "    TLSv1.1: OFFERED (deprecated)\n"
            "    TLSv1.2: offered\n"
            "    TLSv1.3: not offered\n"
            "  Weak ciphers: RC4, 3DES detected\n"
            "  {evidence_detail}\n"
            "  Assess the vulnerability type, severity, and impact."
        ),
        "hard": (
            "PORT    STATE SERVICE\n"
            "{port}/tcp open  https\n"
            "| ssl-enum-ciphers:\n"
            "|   SSLv3:\n"
            "|     ciphers:\n"
            "|       TLS_RSA_WITH_RC4_128_SHA (rsa 2048) - C\n"
            "|       TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C\n"
            "|     warnings:\n"
            "|       Broken cipher RC4 is deprecated by RFC 7465\n"
            "|   TLSv1.0:\n"
            "|     ciphers:\n"
            "|       TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A\n"
            "|       TLS_RSA_WITH_RC4_128_SHA (rsa 2048) - C\n"
            "|   TLSv1.2:\n"
            "|     ciphers:\n"
            "|       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (secp256r1) - A\n"
            "|_  least strength: C"
        ),
    },
    safe=(
        "PORT    STATE SERVICE\n"
        "{port}/tcp open  https\n"
        "| ssl-enum-ciphers:\n"
        "|   TLSv1.2:\n"
        "|     ciphers:\n"
        "|       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (ecdh_x25519) - A\n"
        "|       TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (ecdh_x25519) - A\n"
        "|   TLSv1.3:\n"
        "|     ciphers:\n"
        "|       TLS_AES_256_GCM_SHA384 (ecdh_x25519) - A\n"
        "|_  least strength: A\n\n"
        "TLS configuration on {host}:{port} is strong. "
        "Only TLS 1.2+ with AEAD ciphers offered. No deprecated protocols."
    ),
    context_vars=[
        "host", "port", "cvss", "cwe", "severity", "owasp",
        "evidence_detail", "remediation",
    ],
))

# ===================================================================
# 14. Security Misconfiguration
# ===================================================================
_register(ResponseTemplate(
    vuln_type_id="security_misconfig",
    vulnerable={
        "easy": (
            "[HIGH] Security Misconfiguration DETECTED\n"
            "  Host: {host}\n"
            "  Endpoint: {endpoint}\n"
            "  CWE: {cwe}\n"
            "  CVSS: {cvss}\n"
            "  OWASP: {owasp}\n"
            "  Evidence: {evidence_detail}\n"
            "  Remediation: {remediation}"
        ),
        "medium": (
            "[!] Insecure server configuration identified\n"
            "  Host: {host}\n"
            "  Endpoint: {endpoint}\n"
            "  Findings:\n"
            "    - Missing security headers (HSTS, CSP, X-Frame-Options)\n"
            "    - Server version disclosed in headers\n"
            "    - Sensitive endpoint accessible without authentication\n"
            "  {evidence_detail}\n"
            "  Assess the vulnerability type, severity, and impact."
        ),
        "hard": (
            "- Nikto v2.5.0\n"
            "---------------------------------------------------------------------------\n"
            "+ Target IP:          {host}\n"
            "+ Target Hostname:    {host}\n"
            "+ Target Port:        {port}\n"
            "---------------------------------------------------------------------------\n"
            "+ Server: {service_version}\n"
            "+ /: The anti-clickjacking X-Frame-Options header is not present.\n"
            "+ /: The X-Content-Type-Options header is not set.\n"
            "+ /: Uncommon header 'x-powered-by' found, with contents: PHP/7.4.3.\n"
            "+ {endpoint}: {evidence_detail}\n"
            "+ 8945 requests: 0 error(s) and 6 item(s) reported on remote host\n"
            "---------------------------------------------------------------------------\n"
            "+ 1 host(s) tested"
        ),
    },
    safe=(
        "HTTP/1.1 200 OK\n"
        "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload\n"
        "Content-Security-Policy: default-src 'self'\n"
        "X-Content-Type-Options: nosniff\n"
        "X-Frame-Options: DENY\n"
        "Referrer-Policy: strict-origin-when-cross-origin\n\n"
        "All required security headers present on {host}. "
        "Server version hidden. Debug endpoints disabled. "
        "No misconfiguration issues identified."
    ),
    context_vars=[
        "host", "endpoint", "port", "cvss", "cwe", "severity", "owasp",
        "service_version", "evidence_detail", "remediation",
    ],
))

# ===================================================================
# 15. Vulnerable Component
# ===================================================================
_register(ResponseTemplate(
    vuln_type_id="vulnerable_component",
    vulnerable={
        "easy": (
            "[CRITICAL] Vulnerable Component DETECTED\n"
            "  Host: {host}\n"
            "  Service: {service_version}\n"
            "  CWE: {cwe}\n"
            "  CVSS: {cvss}\n"
            "  OWASP: {owasp}\n"
            "  Evidence: {evidence_detail}\n"
            "  Remediation: {remediation}"
        ),
        "medium": (
            "[!] Outdated software version with known CVEs\n"
            "  Host: {host}\n"
            "  Service: {service_version}\n"
            "  The detected service version has publicly disclosed vulnerabilities "
            "with available exploits.\n"
            "  {evidence_detail}\n"
            "  Assess the vulnerability type, severity, and impact."
        ),
        "hard": (
            "PORT     STATE SERVICE    VERSION\n"
            "{port}/tcp  open  {service_version}\n"
            "| vulners:\n"
            "|   {evidence_detail}\n"
            "|\n"
            "Nmap done: 1 IP address (1 host up) scanned in 12.45 seconds"
        ),
    },
    safe=(
        "PORT     STATE SERVICE    VERSION\n"
        "{port}/tcp  open  {service_version}\n"
        "| vulners:\n"
        "|   No known vulnerabilities for this version\n"
        "|\n"
        "Component {service_version} on {host} is up to date. "
        "No known CVEs found."
    ),
    context_vars=[
        "host", "port", "cvss", "cwe", "severity", "owasp",
        "service_version", "evidence_detail", "remediation",
    ],
))

# ===================================================================
# 16. File Upload
# ===================================================================
_register(ResponseTemplate(
    vuln_type_id="file_upload",
    vulnerable={
        "easy": (
            "[HIGH] Unrestricted File Upload DETECTED\n"
            "  Host: {host}\n"
            "  Endpoint: {endpoint}\n"
            "  CWE: {cwe}\n"
            "  CVSS: {cvss}\n"
            "  OWASP: {owasp}\n"
            "  Evidence: {evidence_detail}\n"
            "  Remediation: {remediation}"
        ),
        "medium": (
            "[!] Executable file uploaded and accessible on server\n"
            "  Host: {host}\n"
            "  Endpoint: {endpoint}\n"
            "  A PHP file was uploaded with a spoofed Content-Type (image/jpeg). "
            "The file was stored in a web-accessible directory and executed "
            "when accessed.\n"
            "  {evidence_detail}\n"
            "  Assess the vulnerability type, severity, and impact."
        ),
        "hard": (
            "POST {endpoint}\n"
            "  Content-Type: multipart/form-data\n"
            "  Filename: shell.php.jpg | Content-Type (declared): image/jpeg\n"
            "  Response: HTTP {status_code}\n"
            "  Body (first 200 chars): {response_body}\n"
            "  Timing: {response_time}ms\n\n"
            "GET /uploads/shell.php.jpg?cmd=id\n"
            "  Response: HTTP 200\n"
            "  Body: uid=33(www-data) gid=33(www-data) groups=33(www-data)"
        ),
    },
    safe=(
        "HTTP/1.1 400 Bad Request\n"
        "Content-Type: application/json\n\n"
        '{{"error": "Invalid file type", "message": "Only .jpg, .png, '
        'and .gif files are allowed"}}\n\n'
        "File extension and magic bytes validated on {host} {endpoint}. "
        "Uploaded files stored outside webroot with randomized names."
    ),
    context_vars=[
        "host", "endpoint", "parameter", "payload", "cvss", "cwe",
        "severity", "owasp", "evidence_detail", "remediation",
        "status_code", "response_body", "response_time",
    ],
))

# ===================================================================
# 17. Cross-Site Request Forgery (CSRF)
# ===================================================================
_register(ResponseTemplate(
    vuln_type_id="csrf",
    vulnerable={
        "easy": (
            "[MEDIUM] Cross-Site Request Forgery (CSRF) DETECTED\n"
            "  Host: {host}\n"
            "  Endpoint: {endpoint}\n"
            "  CWE: {cwe}\n"
            "  CVSS: {cvss}\n"
            "  OWASP: {owasp}\n"
            "  Evidence: {evidence_detail}\n"
            "  Remediation: {remediation}"
        ),
        "medium": (
            "[!] State-changing request accepted without CSRF token\n"
            "  Host: {host}\n"
            "  Endpoint: {endpoint}\n"
            "  A POST request to a state-changing endpoint succeeded without "
            "any anti-CSRF token. The session cookie does not have the SameSite "
            "attribute set.\n"
            "  {evidence_detail}\n"
            "  Assess the vulnerability type, severity, and impact."
        ),
        "hard": (
            "POST {endpoint}\n"
            "  Origin: https://attacker.com\n"
            "  Referer: https://attacker.com/csrf-poc.html\n"
            "  Cookie: session=victim_session_abc123\n"
            "  Body: email=attacker@evil.com\n"
            "  Response: HTTP {status_code}\n"
            "  Body (first 200 chars): {response_body}\n"
            "  Timing: {response_time}ms"
        ),
    },
    safe=(
        "HTTP/1.1 403 Forbidden\n"
        "Content-Type: application/json\n\n"
        '{{"error": "CSRF token validation failed", "message": "Invalid or missing CSRF token"}}\n\n'
        "Anti-CSRF token required and validated on {host} {endpoint}. "
        "SameSite=Strict set on session cookies."
    ),
    context_vars=[
        "host", "endpoint", "parameter", "cvss", "cwe",
        "severity", "owasp", "evidence_detail", "remediation",
        "status_code", "response_body", "response_time",
    ],
))

# ===================================================================
# 18. Missing Rate Limiting
# ===================================================================
_register(ResponseTemplate(
    vuln_type_id="missing_rate_limiting",
    vulnerable={
        "easy": (
            "[HIGH] Missing Rate Limiting DETECTED\n"
            "  Host: {host}\n"
            "  Endpoint: {endpoint}\n"
            "  CWE: {cwe}\n"
            "  CVSS: {cvss}\n"
            "  OWASP: {owasp}\n"
            "  Evidence: {evidence_detail}\n"
            "  Remediation: {remediation}"
        ),
        "medium": (
            "[!] No rate limiting or account lockout on authentication endpoint\n"
            "  Host: {host}\n"
            "  Endpoint: {endpoint}\n"
            "  Over 100 login attempts were processed without any blocking, "
            "CAPTCHA challenge, or account lockout. No X-RateLimit-* headers observed.\n"
            "  {evidence_detail}\n"
            "  Assess the vulnerability type, severity, and impact."
        ),
        "hard": (
            "POST {endpoint} x500 (brute-force test)\n"
            "  Request #1:   HTTP 401 | 143 bytes | 52ms\n"
            "  Request #100: HTTP 401 | 143 bytes | 48ms\n"
            "  Request #500: HTTP 401 | 143 bytes | 51ms\n"
            "  No 429 responses. No Retry-After header. "
            "No X-RateLimit-* headers.\n"
            "  {evidence_detail}"
        ),
    },
    safe=(
        "HTTP/1.1 429 Too Many Requests\n"
        "Retry-After: 300\n"
        "X-RateLimit-Limit: 5\n"
        "X-RateLimit-Remaining: 0\n"
        "Content-Type: application/json\n\n"
        '{{"error": "Too many login attempts", "message": "Account temporarily locked. '
        'Try again in 5 minutes."}}\n\n'
        "Rate limiting enforced on {host} {endpoint} after 5 failed attempts. "
        "Account lockout and exponential backoff observed."
    ),
    context_vars=[
        "host", "endpoint", "parameter", "cvss", "cwe",
        "severity", "owasp", "evidence_detail", "remediation",
    ],
))

# ===================================================================
# 19. Email Security Misconfiguration
# ===================================================================
_register(ResponseTemplate(
    vuln_type_id="email_misconfig",
    vulnerable={
        "easy": (
            "[MEDIUM] Email Security Misconfiguration DETECTED\n"
            "  Host: {host}\n"
            "  CWE: {cwe}\n"
            "  CVSS: {cvss}\n"
            "  OWASP: {owasp}\n"
            "  Evidence: {evidence_detail}\n"
            "  Remediation: {remediation}"
        ),
        "medium": (
            "[!] Missing or weak email authentication records\n"
            "  Host: {host}\n"
            "  DNS checks:\n"
            "    SPF: missing or overly permissive (+all)\n"
            "    DKIM: no DKIM record found\n"
            "    DMARC: no DMARC record found (or p=none)\n"
            "  {evidence_detail}\n"
            "  Assess the vulnerability type, severity, and impact."
        ),
        "hard": (
            "dig TXT {host}\n"
            "  ;; ANSWER SECTION:\n"
            "  {host}. 300 IN TXT \"v=spf1 +all\"\n\n"
            "dig TXT _dmarc.{host}\n"
            "  ;; ANSWER SECTION:\n"
            "  (empty - no DMARC record)\n\n"
            "dig TXT default._domainkey.{host}\n"
            "  ;; ANSWER SECTION:\n"
            "  (empty - no DKIM record)"
        ),
    },
    safe=(
        "dig TXT {host}\n"
        "  ;; ANSWER SECTION:\n"
        "  {host}. 300 IN TXT \"v=spf1 include:_spf.google.com -all\"\n\n"
        "dig TXT _dmarc.{host}\n"
        "  ;; ANSWER SECTION:\n"
        "  _dmarc.{host}. 300 IN TXT \"v=DMARC1; p=reject; rua=mailto:dmarc@{host}\"\n\n"
        "Email authentication properly configured on {host}. "
        "SPF strict (-all), DKIM present, DMARC p=reject."
    ),
    context_vars=[
        "host", "cvss", "cwe", "severity", "owasp",
        "evidence_detail", "remediation",
    ],
))

# ===================================================================
# 20. Sensitive Data Exposure
# ===================================================================
_register(ResponseTemplate(
    vuln_type_id="sensitive_data_exposure",
    vulnerable={
        "easy": (
            "[HIGH] Sensitive Data Exposure DETECTED\n"
            "  Host: {host}\n"
            "  Endpoint: {endpoint}\n"
            "  CWE: {cwe}\n"
            "  CVSS: {cvss}\n"
            "  OWASP: {owasp}\n"
            "  Evidence: {evidence_detail}\n"
            "  Remediation: {remediation}"
        ),
        "medium": (
            "[!] Sensitive information disclosed in server response\n"
            "  Host: {host}\n"
            "  Endpoint: {endpoint}\n"
            "  Sensitive data was found exposed, including credentials, API keys, "
            "or internal configuration details in a publicly accessible location.\n"
            "  {evidence_detail}\n"
            "  Assess the vulnerability type, severity, and impact."
        ),
        "hard": (
            "GET {endpoint}\n"
            "  Response: HTTP {status_code}\n"
            "  Body (first 200 chars): {response_body}\n"
            "  Timing: {response_time}ms\n"
            "  Headers: Server: {service_version}\n"
            "  X-Powered-By: PHP/7.4.3"
        ),
    },
    safe=(
        "HTTP/1.1 404 Not Found\n"
        "Content-Type: application/json\n\n"
        '{{"error": "Not Found"}}\n\n'
        "No sensitive data exposed on {host} {endpoint}. "
        "Debug endpoints disabled. Sensitive files (.env, .git) return 404. "
        "Error responses use generic messages without stack traces."
    ),
    context_vars=[
        "host", "endpoint", "cvss", "cwe", "severity", "owasp",
        "service_version", "evidence_detail", "remediation",
        "status_code", "response_body", "response_time",
    ],
))

# ===================================================================
# 21. Insufficient Logging
# ===================================================================
_register(ResponseTemplate(
    vuln_type_id="insufficient_logging",
    vulnerable={
        "easy": (
            "[MEDIUM] Insufficient Logging and Monitoring DETECTED\n"
            "  Host: {host}\n"
            "  CWE: {cwe}\n"
            "  CVSS: {cvss}\n"
            "  OWASP: {owasp}\n"
            "  Evidence: {evidence_detail}\n"
            "  Remediation: {remediation}"
        ),
        "medium": (
            "[!] Security events not adequately logged\n"
            "  Host: {host}\n"
            "  Multiple failed login attempts and suspicious activity did not "
            "trigger any alerts or produce audit log entries. "
            "No centralized logging infrastructure detected.\n"
            "  {evidence_detail}\n"
            "  Assess the vulnerability type, severity, and impact."
        ),
        "hard": (
            "Tested: 50 failed logins, 10 SQL injection attempts, "
            "5 path traversal attempts on {host}\n"
            "  Log review: /var/log/auth.log — no entries for web app events\n"
            "  Log review: /var/log/app/audit.log — file does not exist\n"
            "  SIEM integration: not detected\n"
            "  Alert triggers: none observed\n"
            "  {evidence_detail}"
        ),
    },
    safe=(
        "Security logging verified on {host}:\n"
        "  - Failed login attempts logged with IP, timestamp, and user agent\n"
        "  - Suspicious requests trigger alerts via SIEM integration\n"
        "  - Audit trail covers authentication, authorization, and data access\n"
        "  - Log integrity protected (append-only, centralized)\n"
        "  Logging and monitoring adequate."
    ),
    context_vars=[
        "host", "cvss", "cwe", "severity", "owasp",
        "evidence_detail", "remediation",
    ],
))

# ===================================================================
# 22. Open Redirect
# ===================================================================
_register(ResponseTemplate(
    vuln_type_id="open_redirect",
    vulnerable={
        "easy": (
            "[LOW] Open Redirect DETECTED\n"
            "  Host: {host}\n"
            "  Endpoint: {endpoint}\n"
            "  Parameter: {parameter}\n"
            "  CWE: {cwe}\n"
            "  CVSS: {cvss}\n"
            "  OWASP: {owasp}\n"
            "  Payload: {payload}\n"
            "  Evidence: {evidence_detail}\n"
            "  Remediation: {remediation}"
        ),
        "medium": (
            "[!] Application redirects to user-controlled external URL\n"
            "  Host: {host}\n"
            "  Endpoint: {endpoint}\n"
            "  Parameter: {parameter}\n"
            "  The server issued a 302 redirect to an attacker-controlled domain "
            "based on user input in the URL parameter.\n"
            "  {evidence_detail}\n"
            "  Assess the vulnerability type, severity, and impact."
        ),
        "hard": (
            "Parameter: {parameter} | Payload: {payload}\n"
            "  Response: HTTP 302 Found\n"
            "  Location: https://evil.com\n"
            "  Body: (empty)\n"
            "  Timing: {response_time}ms"
        ),
    },
    safe=(
        "HTTP/1.1 400 Bad Request\n"
        "Content-Type: application/json\n\n"
        '{{"error": "Invalid redirect URL", "message": "Redirect to external domains is not allowed"}}\n\n'
        "Redirect parameter validated on {host} {endpoint}. "
        "Only relative paths and allowlisted domains accepted."
    ),
    context_vars=[
        "host", "endpoint", "parameter", "payload", "cvss", "cwe",
        "severity", "owasp", "evidence_detail", "remediation",
        "response_time",
    ],
))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_response_template(vuln_type_id: str) -> ResponseTemplate:
    """Return the ResponseTemplate for a given vulnerability type ID.

    Raises KeyError if the vuln_type_id is not registered.
    """
    if vuln_type_id not in _TEMPLATES:
        raise KeyError(
            f"Unknown vuln_type_id '{vuln_type_id}'. "
            f"Available: {sorted(_TEMPLATES.keys())}"
        )
    return _TEMPLATES[vuln_type_id]


def get_all_response_templates() -> Dict[str, ResponseTemplate]:
    """Return a copy of the full template registry."""
    return dict(_TEMPLATES)


def render_vulnerable(
    vuln_type_id: str,
    difficulty: str,
    context: Dict[str, str],
) -> str:
    """Render the vulnerable-response template for a given difficulty tier.

    Parameters
    ----------
    vuln_type_id : str
        Vulnerability type identifier (e.g. "sqli", "xss_stored").
    difficulty : str
        One of "easy", "medium", "hard".
    context : dict
        Template variables to fill in.  Missing keys are replaced with
        a placeholder so rendering never raises.

    Returns
    -------
    str
        The fully rendered template string.
    """
    template = get_response_template(vuln_type_id)
    if difficulty not in template.vulnerable:
        raise ValueError(
            f"Unknown difficulty '{difficulty}'. "
            f"Expected one of: {sorted(template.vulnerable.keys())}"
        )
    raw = template.vulnerable[difficulty]
    return _safe_format(raw, context)


def render_safe(
    vuln_type_id: str,
    context: Dict[str, str],
) -> str:
    """Render the safe / non-vulnerable response template.

    Parameters
    ----------
    vuln_type_id : str
        Vulnerability type identifier.
    context : dict
        Template variables to fill in.

    Returns
    -------
    str
        The fully rendered safe-response string.
    """
    template = get_response_template(vuln_type_id)
    return _safe_format(template.safe, context)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

class _DefaultDict(dict):
    """Dict subclass that returns a placeholder for missing keys."""

    def __missing__(self, key: str) -> str:
        return f"<{key}>"


def _safe_format(template: str, context: Dict[str, str]) -> str:
    """Format *template* with *context*, substituting placeholders for
    any variables that are absent from *context*."""
    safe_ctx = _DefaultDict(context)
    return template.format_map(safe_ctx)
