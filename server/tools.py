"""
Simulated Security Audit Tools.

Each tool reads from the scenario's ground truth data and returns
realistic-looking text output. No real network scanning occurs.
All outputs are deterministic — same inputs always produce same results.

Output detail varies by scenario difficulty:
- Easy: labeled findings with CWE, CVSS, remediation (training mode)
- Medium: raw evidence with hints — agent must classify and assess
- Hard: raw tool output only — agent must infer everything from evidence
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
    """Filter vulnerabilities by chain prerequisites."""
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


# ---------------------------------------------------------------------------
# Raw output templates for medium/hard (keyed by vuln ID)
# Medium: shows evidence + partial context, no CWE/CVSS/remediation
# Hard:   raw tool output — HTTP responses, timing, errors — agent infers
# ---------------------------------------------------------------------------
_RAW_OUTPUTS = {
    # ---- MEDIUM: E-commerce Platform ----
    "VULN-M001": {
        "medium": (
            "  [!] Anomalous response from server\n"
            "  Parameter: image_url\n"
            "  Payload: image_url=http://10.0.2.30:8080\n"
            "  Response: HTTP 200 — body contains HTML from internal Jenkins server\n"
            "  Payload: image_url=http://169.254.169.254/latest/meta-data/\n"
            "  Response: HTTP 200 — body contains AWS metadata (ami-id, instance-type)\n"
            "  The server fetched and returned content from internal/cloud URLs via the image_url parameter.\n"
            "  Assess the vulnerability type, severity, and impact."
        ),
        "hard": (
            "  Parameter: image_url | Payload: http://10.0.2.30:8080\n"
            "  Response: HTTP 200\n"
            '  Body (first 200 chars): <!DOCTYPE html><html><head><title>Dashboard [Jenkins]</title><link rel="stylesheet" href="/static/css/jenkins...\n'
            "\n"
            "  Parameter: image_url | Payload: http://169.254.169.254/latest/meta-data/\n"
            "  Response: HTTP 200\n"
            "  Body: ami-id\\ninstance-type\\nlocal-ipv4\\nplacement/availability-zone\n"
            "\n"
            "  Parameter: image_url | Payload: http://10.0.2.40:5432\n"
            "  Response: HTTP 200 (non-HTTP binary data in body, connection established)\n"
            "\n"
            "  Parameter: image_url | Payload: https://example.com/image.png\n"
            "  Response: HTTP 200 (valid image returned as expected)"
        ),
    },
    "VULN-M002": {
        "medium": (
            "  [!] Authorization bypass detected\n"
            "  Authenticated as user_id=100\n"
            '  GET /api/v1/orders/5001 (own) → HTTP 200 {"order_id":5001,"user_id":100,"total":"$149.99"}\n'
            '  GET /api/v1/orders/5002 (other) → HTTP 200 {"order_id":5002,"user_id":101,"email":"other@shop.com","card_last4":"7823"}\n'
            "  Other users' PII and payment data accessible by changing the ID parameter.\n"
            "  Assess the vulnerability type, severity, and impact."
        ),
        "hard": (
            "  Authenticated as user_id=100 (session token: eyJhbGciOiJIUz...)\n"
            '  GET /api/v1/orders/5001 → HTTP 200 {"order_id":5001,"user_id":100,"total":"$149.99","items":[...]}\n'
            '  GET /api/v1/orders/5002 → HTTP 200 {"order_id":5002,"user_id":101,"email":"other@shop.com","card_last4":"7823","total":"$89.50"}\n'
            '  GET /api/v1/orders/5003 → HTTP 200 {"order_id":5003,"user_id":102,"email":"bob@shop.com","card_last4":"1234","total":"$210.00"}\n'
            "  GET /api/v1/orders/9999 → HTTP 404\n"
            "  Note: Same session token used for all requests. No authorization header variation."
        ),
    },
    "VULN-M003": {
        "medium": (
            "  [!] Sensitive data found in client-side code\n"
            "  File: /static/js/app.bundle.js (847KB, minified)\n"
            '  Line 1847: const STRIPE_KEY = "sk_live_51HG3jK2eZvKYlo2C0EXAMPLE_REDACTED";\n'
            '  Line 2103: const API_INTERNAL = "http://10.0.2.20:8080/api/v1";\n'
            "  Line 2210: // TODO: remove hardcoded keys before production\n"
            "  Hardcoded API keys and internal URLs found in publicly accessible JavaScript.\n"
            "  Assess the vulnerability type, severity, and impact."
        ),
        "hard": (
            "  Analyzing /static/js/app.bundle.js (847KB, minified)\n"
            "\n"
            "  High-entropy strings detected:\n"
            '    Line 1847: const STRIPE_KEY = "sk_live_51HG3jK2eZvKYlo2C0EXAMPLE_REDACTED";\n'
            '    Line 2103: const API_INTERNAL = "http://10.0.2.20:8080/api/v1";\n'
            "    Line 2210: // TODO: remove hardcoded keys before production\n"
            '    Line 3891: const JWT_SECRET = "shopfast-jwt-secret-2024";\n'
            "\n"
            '  Shannon entropy analysis:\n'
            '    "sk_live_51HG3jK..." — entropy: 5.2 bits/char\n'
            '    "shopfast-jwt-secret..." — entropy: 3.8 bits/char\n'
            "  Total: 4 suspicious strings across 1 file"
        ),
    },
    "VULN-M004": {
        "medium": (
            "  [!] Service accessible without authentication\n"
            "  GET / → HTTP 200 (Jenkins 2.235.1 dashboard rendered)\n"
            "  GET /script → HTTP 200 (Groovy script console accessible)\n"
            "  GET /manage → HTTP 200 (management interface rendered)\n"
            "  No authentication challenge (WWW-Authenticate header absent).\n"
            "  CI/CD system with script execution capability is fully open.\n"
            "  Assess the vulnerability type, severity, and impact."
        ),
        "hard": (
            "  GET / → HTTP 200\n"
            "  Headers: X-Jenkins: 2.235.1, X-Hudson: 1.395\n"
            '  Body (excerpt): <div id="main-panel">...Welcome to Jenkins!...2 jobs configured...\n'
            "\n"
            "  GET /script → HTTP 200\n"
            '  Body (excerpt): <textarea name="script" id="script">...</textarea>\n'
            "  Note: No redirect to /login, no 401/403 status\n"
            "\n"
            "  GET /manage → HTTP 200\n"
            '  Body (excerpt): ...Manage Jenkins...Configure System...Manage Plugins...\n'
            "\n"
            "  GET /credentials → HTTP 200\n"
            '  Body (excerpt): ...Stored credentials: 3 items...\n'
            "\n"
            "  Cookie: no JSESSIONID set (no session management active)"
        ),
    },
    "VULN-M005": {
        "medium": (
            "  [!] Database accepts weak credentials\n"
            "  PostgreSQL (port 5432):\n"
            "    dbuser:dbpass123 → authentication successful\n"
            "    Connected — 23 tables visible, no connection rate limiting detected\n"
            "  Assess the vulnerability type, severity, and impact."
        ),
        "hard": (
            "  PostgreSQL (port 5432):\n"
            "    postgres:postgres → FATAL: password authentication failed\n"
            "    admin:admin → FATAL: password authentication failed\n"
            "    dbuser:dbuser → FATAL: password authentication failed\n"
            "    dbuser:dbpass123 → connection established\n"
            "\n"
            '    SELECT current_user; → "dbuser"\n'
            "    \\dt → 23 tables (users, orders, payments, sessions, ...)\n"
            "    SELECT count(*) FROM users; → 12,847\n"
            "\n"
            "  Brute force timing: 50 attempts in 3.1s, no lockout or delay increase"
        ),
    },
    "VULN-M006": {
        "medium": (
            "  [!] Outdated TLS configuration detected\n"
            "  Server accepts TLSv1.0 and TLSv1.1 (deprecated protocols)\n"
            "  Weak cipher suite accepted: TLS_RSA_WITH_3DES_EDE_CBC_SHA\n"
            "  HSTS header not present in responses.\n"
            "  Assess the vulnerability type, severity, and impact."
        ),
        "hard": (
            "  TLS handshake analysis:\n"
            "    Protocol: TLSv1.0 → ServerHello (accepted)\n"
            "    Protocol: TLSv1.1 → ServerHello (accepted)\n"
            "    Protocol: TLSv1.2 → ServerHello (accepted)\n"
            "    Protocol: TLSv1.3 → handshake failure\n"
            "\n"
            "  Cipher suites (port 443):\n"
            "    TLS_RSA_WITH_3DES_EDE_CBC_SHA → accepted\n"
            "    TLS_RSA_WITH_AES_128_CBC_SHA → accepted\n"
            "    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 → accepted\n"
            "\n"
            "  Certificate: CN=shopfast.com, expires 2025-12-01, issuer=Let's Encrypt\n"
            "  HSTS: not present\n"
            "  OCSP stapling: not enabled"
        ),
    },
    # ---- HARD: Enterprise SOC2 Pre-Audit ----
    "VULN-H001": {
        "hard": (
            "  Parameter: message\n"
            "  Payload: <img src=x onerror=alert(1)>\n"
            "  POST /support/ticket → HTTP 200\n"
            "\n"
            "  Verification: GET /support/tickets?latest=true\n"
            '  Response body excerpt:\n'
            '    <div class="ticket-body"><img src=x onerror=alert(1)></div>\n'
            "  Note: Payload persisted in database and rendered without encoding\n"
            "  Note: Response headers — no Content-Security-Policy, X-XSS-Protection: 0"
        ),
    },
    "VULN-H002": {
        "hard": (
            "  Authenticated as user_id=1001 (Bearer token: eyJhbG...)\n"
            '  GET /api/v2/accounts/1001 → HTTP 200 {"account_id":1001,"name":"Test User","balance":"$12,450.00"}\n'
            '  GET /api/v2/accounts/1002 → HTTP 200 {"account_id":1002,"name":"Jane Smith","balance":"$87,230.50","ssn_last4":"4829"}\n'
            '  GET /api/v2/accounts/1003 → HTTP 200 {"account_id":1003,"name":"Bob Jones","balance":"$3,100.00","ssn_last4":"7712"}\n'
            "  GET /api/v2/accounts/9999 → HTTP 404\n"
            "\n"
            "  Note: Sequential integer IDs. Same Bearer token used for all requests.\n"
            "  Note: PII (SSN, balance) exposed in cross-account responses."
        ),
    },
    "VULN-H003": {
        "hard": (
            "  Concurrency testing on /api/v2/transfer:\n"
            "  Initial balance (account 1001): $1,000.00\n"
            "\n"
            "  Sent 5 concurrent POST requests:\n"
            '    {"from_account":"1001","to_account":"1002","amount":800}\n'
            "\n"
            '  Request 1: HTTP 200 {"status":"success","new_balance":"$200.00"}\n'
            '  Request 2: HTTP 200 {"status":"success","new_balance":"$200.00"}\n'
            '  Request 3: HTTP 200 {"status":"success","new_balance":"$200.00"}\n'
            '  Request 4: HTTP 402 {"error":"insufficient_funds"}\n'
            '  Request 5: HTTP 402 {"error":"insufficient_funds"}\n'
            "\n"
            "  Final balance (account 1001): -$1,400.00\n"
            "  Total transferred: $2,400.00 from initial $1,000.00\n"
            "  Note: Balance check and deduction are not atomic operations"
        ),
    },
    "VULN-H004": {
        "hard": (
            "  Parameter: template\n"
            "\n"
            "  Payload: {{7*7}}\n"
            '  Response body (excerpt): ...Report generated: 49...\n'
            "\n"
            "  Payload: {{config}}\n"
            "  Response body (excerpt): ...Report generated: <Config {'ENV': 'production', "
            "'DEBUG': False, 'SECRET_KEY': 'finsecure-prod-key-2024'}>...\n"
            "\n"
            '  Payload: {{"test".__class__.__mro__}}\n'
            "  Response body (excerpt): ...(<class 'str'>, <class 'object'>)...\n"
            "\n"
            "  Server headers: X-Powered-By: Flask/Jinja2"
        ),
    },
    "VULN-H005": {
        "hard": (
            "  File upload testing:\n"
            '  test.txt (text/plain, 12B) → HTTP 200 {"path":"/uploads/test.txt"}\n'
            '  test.php (application/x-php, 45B) → HTTP 200 {"path":"/uploads/test.php"}\n'
            '  test.jsp (text/plain, 38B) → HTTP 200 {"path":"/uploads/test.jsp"}\n'
            '  test.exe (application/octet-stream, 1KB) → HTTP 200 {"path":"/uploads/test.exe"}\n'
            "\n"
            "  Verification: GET /uploads/test.php\n"
            "  Response: HTTP 200, Content-Type: text/html\n"
            "  Body: PHP output rendered (file was executed server-side, not served as static)"
        ),
    },
    "VULN-H006": {
        "hard": (
            "  FTP (port 21):\n"
            "    USER anonymous → 331 Please specify the password\n"
            "    PASS anonymous → 230 Login successful\n"
            "    LIST → drwxr-xr-x  /reports/\n"
            "           drwxr-xr-x  /employee_data/\n"
            "           drwxr-xr-x  /financial/\n"
            "    SIZE /financial/Q4_2024_revenue.xlsx → 2,371,584 bytes\n"
            "\n"
            "  SMB (port 445):\n"
            "    Guest session → \\\\10.0.3.40\\Documents accessible (read/write)\n"
            "    Files: employee_roster.csv, salary_data.xlsx, board_minutes_2024.pdf\n"
            "    Share permissions: Everyone:FullControl"
        ),
    },
    "VULN-H007": {
        "hard": (
            "  FTP (port 21):\n"
            "    AUTH TLS → 502 Command not implemented\n"
            "    FEAT → no TLS/SSL features advertised\n"
            "\n"
            "  Captured transfer: RETR /financial/Q4_2024_revenue.xlsx\n"
            "  Transfer protocol: plaintext FTP (no encryption layer)\n"
            "  Wireshark excerpt: PASS command visible in cleartext in packet capture\n"
            "\n"
            "  SFTP (port 22): connection refused\n"
            "  FTPS: not available"
        ),
    },
    "VULN-H008": {
        "hard": (
            "  SMTP (port 25, Postfix 3.4.13):\n"
            "    EHLO test.local → 250 mail.finsecure.com\n"
            "    MAIL FROM:<attacker@external.com> → 250 2.1.0 Ok\n"
            "    RCPT TO:<ceo@finsecure.com> → 250 2.1.5 Ok\n"
            "    DATA → 354 End data with <CR><LF>.<CR><LF>\n"
            "    (message accepted from unauthenticated external sender)\n"
            "\n"
            "  DNS records for finsecure.com:\n"
            "    SPF: no record found\n"
            "    DKIM: no record found\n"
            "    DMARC: no record found\n"
            "    MX: mail.finsecure.com → 10.0.3.50"
        ),
    },
    "VULN-H009": {
        "hard": (
            "  Port 8080: Apache Tomcat/9.0.31\n"
            "\n"
            "  NVD database results:\n"
            "    CVE-2020-1938 — Base Score: 9.8 — AJP connector file read/inclusion\n"
            "    CVE-2020-9484 — Base Score: 7.0 — session persistence deserialization\n"
            "    CVE-2020-11996 — Base Score: 7.5 — HTTP/2 request handling DoS\n"
            "\n"
            "  Port 8009/tcp: open (AJP13 protocol response received)\n"
            "  Note: AJP connector externally accessible from scan origin"
        ),
    },
    "VULN-H010": {
        "hard": (
            "  POST /login — rate limit testing:\n"
            "  Batch 1: 100 requests with invalid creds in 2.3s\n"
            "    Result: 100x HTTP 401 (all processed, none blocked)\n"
            "    Avg response time: 23ms (consistent, no throttling)\n"
            "\n"
            "  Batch 2: 1000 requests in 18.7s\n"
            "    Result: 1000x HTTP 401\n"
            "    No CAPTCHA challenge\n"
            "    No account lockout triggered\n"
            "    No IP-based blocking detected\n"
            "\n"
            "  Response headers: no X-RateLimit-* headers present"
        ),
    },
}


def _labeled_output(v: Dict) -> str:
    """Easy mode: full labeled finding with CWE, CVSS, remediation."""
    tag = {
        "Critical": "CRITICAL", "High": "ALERT",
        "Medium": "WARNING", "Low": "INFO",
    }.get(v["severity"], "FINDING")
    return (
        f"  [{tag}] {v['type']} DETECTED\n"
        f"  CWE: {v['cwe']}\n"
        f"  OWASP: {v['owasp']}\n"
        f"  Evidence: {v['evidence']}\n"
        f"  Suggested CVSS: {v['cvss']} ({v['severity']})\n"
        f"  Remediation: {v['remediation']}"
    )


def _format_detection(v: Dict, scenario: Dict, header: str) -> str:
    """Pick output format based on scenario difficulty."""
    difficulty = scenario.get("id", "easy")

    if difficulty == "easy":
        return _labeled_output(v)

    raw = _RAW_OUTPUTS.get(v["id"], {}).get(difficulty)
    if raw:
        return raw

    # Fallback for medium vulns without explicit raw output
    if difficulty == "medium":
        return (
            f"  [!] Potential issue detected\n"
            f"  Observation: {v['evidence']}\n"
            f"  Assess the vulnerability type, severity, and impact."
        )

    # Fallback for hard vulns without explicit raw output
    return (
        f"  Observation: {v['evidence']}\n"
        f"  No further classification available — manual analysis required."
    )


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
    difficulty = scenario.get("id", "easy")

    lines = [f"Vulnerability scan for {host}:", ""]
    reported = set()
    for p in ports:
        lines.append(f"  {p['service']} {p['version']} on port {p['port']}:")
        found_any = False
        for v in vulns:
            if v["id"] not in reported:
                if difficulty == "easy":
                    lines.append(f"    [!] VULNERABLE: {v['type']} (CVSS {v['cvss']}) — {v['cwe']}")
                    lines.append(f"        Confidence: High | Source: NVD/OWASP")
                    lines.append(f"        Remediation: {v['remediation']}")
                else:
                    raw = _RAW_OUTPUTS.get(v["id"], {}).get(difficulty)
                    if raw:
                        lines.append(raw)
                    else:
                        # Generic CVE-style output without explicit classification
                        lines.append(f"    NVD match for {p['version']}")
                        lines.append(f"    See output details for assessment.")
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
            lines.append(_format_detection(v, scenario, f"Injection testing on {host}{endpoint}"))
            lines.append("")
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
            lines.append(_format_detection(v, scenario, f"XSS testing on {host}{endpoint}"))
            lines.append("")
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
            lines.append(_format_detection(v, scenario, f"Auth testing on {host}"))
            lines.append("")
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
            lines.append(_format_detection(v, scenario, f"Configuration audit for {host}"))
            lines.append("")
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
            lines.append(_format_detection(v, scenario, f"Cryptographic analysis for {host}"))
            lines.append("")
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
            lines.append(_format_detection(v, scenario, f"Secret scanning on {host}"))
            lines.append("")
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
