"""
Security Audit Scenarios — Ground truth network definitions.

Each scenario defines a simulated corporate network with hosts, services,
endpoints, and vulnerabilities. The agent must discover these through
tool calls.
"""

from typing import Any, Dict, List


def get_scenario(scenario_id: str) -> Dict[str, Any]:
    """Get a scenario by ID."""
    scenarios = {
        "easy": _scenario_easy(),
        "medium": _scenario_medium(),
        "hard": _scenario_hard(),
    }
    return scenarios.get(scenario_id, scenarios["easy"])


def list_scenarios() -> List[Dict[str, str]]:
    """List all available scenarios with descriptions."""
    return [
        {
            "id": "easy",
            "name": "Startup Web App Audit",
            "description": "Basic security audit of a small startup's web application. 2 hosts, 3 known vulnerabilities.",
            "difficulty": "easy",
            "max_steps": 30,
        },
        {
            "id": "medium",
            "name": "E-commerce Platform Audit",
            "description": "Security compliance audit of an e-commerce platform. 4 hosts, 6 vulnerabilities including chained attacks.",
            "difficulty": "medium",
            "max_steps": 50,
        },
        {
            "id": "hard",
            "name": "Enterprise SOC2 Pre-Audit",
            "description": "Full-scope pre-SOC2 audit of enterprise infrastructure. 6 hosts, 10 vulnerabilities, honeypots, and time pressure.",
            "difficulty": "hard",
            "max_steps": 60,
        },
    ]


def _scenario_easy() -> Dict[str, Any]:
    return {
        "id": "easy",
        "name": "Startup Web App Audit",
        "company": "QuickLaunch SaaS Inc.",
        "compliance_context": "Pre-launch security review",
        "target_network": "10.0.1.0/24",
        "max_steps": 30,
        "briefing": (
            "You are conducting a pre-launch security audit for QuickLaunch SaaS Inc. "
            "Target network: 10.0.1.0/24. The company runs a simple web application "
            "with a backend database. Identify all security vulnerabilities, assess "
            "their severity, and submit structured findings."
        ),
        "hosts": {
            "10.0.1.10": {
                "hostname": "web-app-01",
                "os": "Ubuntu 20.04 LTS",
                "role": "Web Application Server",
            },
            "10.0.1.20": {
                "hostname": "db-server-01",
                "os": "Ubuntu 18.04 LTS",
                "role": "Database Server",
            },
        },
        "ports": {
            "10.0.1.10": [
                {"port": 22, "service": "ssh", "version": "OpenSSH 8.2p1", "state": "open"},
                {"port": 80, "service": "http", "version": "Apache 2.4.41", "state": "open"},
                {"port": 443, "service": "https", "version": "Apache 2.4.41", "state": "open"},
            ],
            "10.0.1.20": [
                {"port": 22, "service": "ssh", "version": "OpenSSH 7.6p1", "state": "open"},
                {"port": 3306, "service": "mysql", "version": "MySQL 5.7.28", "state": "open"},
            ],
        },
        "web_endpoints": {
            "10.0.1.10": [
                {"path": "/", "method": "GET", "description": "Homepage"},
                {"path": "/api/login", "method": "POST", "description": "User login endpoint", "params": ["username", "password"]},
                {"path": "/api/search", "method": "GET", "description": "Product search", "params": ["query"]},
                {"path": "/admin", "method": "GET", "description": "Admin panel"},
                {"path": "/api/users", "method": "GET", "description": "User listing API"},
            ],
        },
        "vulnerabilities": [
            {
                "id": "VULN-E001",
                "host": "10.0.1.10",
                "endpoint": "/api/login",
                "type": "SQL Injection",
                "cwe": "CWE-89",
                "owasp": "A03:2021 - Injection",
                "cvss": 9.8,
                "severity": "Critical",
                "evidence": "Parameter 'username' vulnerable: ' OR 1=1-- bypasses authentication. MySQL error exposed in response.",
                "remediation": "Use parameterized queries or prepared statements for all database operations.",
                "discoverable_by": ["test_injection"],
            },
            {
                "id": "VULN-E002",
                "host": "10.0.1.10",
                "endpoint": "/admin",
                "type": "Broken Authentication",
                "cwe": "CWE-798",
                "owasp": "A07:2021 - Identification and Authentication Failures",
                "cvss": 8.1,
                "severity": "High",
                "evidence": "Admin panel accessible with default credentials admin:admin123. No account lockout after failed attempts.",
                "remediation": "Change default credentials immediately. Implement account lockout and MFA.",
                "discoverable_by": ["test_auth"],
            },
            {
                "id": "VULN-E003",
                "host": "10.0.1.20",
                "endpoint": None,
                "type": "Security Misconfiguration",
                "cwe": "CWE-200",
                "owasp": "A05:2021 - Security Misconfiguration",
                "cvss": 9.1,
                "severity": "Critical",
                "evidence": "MySQL port 3306 is accessible from the public internet. No firewall rules restricting access. Remote root login enabled.",
                "remediation": "Restrict MySQL access to application server IPs only using firewall rules. Disable remote root login.",
                "discoverable_by": ["network_scan", "test_config"],
            },
        ],
        "honeypots": [],
    }


def _scenario_medium() -> Dict[str, Any]:
    return {
        "id": "medium",
        "name": "E-commerce Platform Audit",
        "company": "ShopFast Commerce Ltd.",
        "compliance_context": "PCI-DSS compliance assessment",
        "target_network": "10.0.2.0/24",
        "max_steps": 50,
        "briefing": (
            "You are conducting a PCI-DSS compliance security audit for ShopFast Commerce Ltd. "
            "Target network: 10.0.2.0/24. The company operates an e-commerce platform with "
            "a web frontend, REST API, CI/CD pipeline, and internal database. Some vulnerabilities "
            "may require discovering one system to find others. Submit all findings with "
            "severity ratings and compliance framework references."
        ),
        "hosts": {
            "10.0.2.10": {
                "hostname": "web-frontend",
                "os": "Ubuntu 22.04 LTS",
                "role": "Web Frontend + API Server",
            },
            "10.0.2.20": {
                "hostname": "api-backend",
                "os": "Ubuntu 20.04 LTS",
                "role": "REST API Backend",
            },
            "10.0.2.30": {
                "hostname": "ci-jenkins",
                "os": "Ubuntu 20.04 LTS",
                "role": "CI/CD Server (Jenkins)",
            },
            "10.0.2.40": {
                "hostname": "db-primary",
                "os": "Ubuntu 20.04 LTS",
                "role": "PostgreSQL Database",
            },
        },
        "ports": {
            "10.0.2.10": [
                {"port": 22, "service": "ssh", "version": "OpenSSH 8.9p1", "state": "open"},
                {"port": 80, "service": "http", "version": "nginx 1.18.0", "state": "open"},
                {"port": 443, "service": "https", "version": "nginx 1.18.0", "state": "open"},
            ],
            "10.0.2.20": [
                {"port": 22, "service": "ssh", "version": "OpenSSH 8.2p1", "state": "open"},
                {"port": 8080, "service": "http", "version": "Express.js 4.17.1 (Node.js)", "state": "open"},
            ],
            "10.0.2.30": [
                {"port": 22, "service": "ssh", "version": "OpenSSH 8.2p1", "state": "open"},
                {"port": 8080, "service": "http", "version": "Jenkins 2.235.1", "state": "open"},
            ],
            "10.0.2.40": [
                {"port": 22, "service": "ssh", "version": "OpenSSH 8.2p1", "state": "open"},
                {"port": 5432, "service": "postgresql", "version": "PostgreSQL 13.4", "state": "open"},
            ],
        },
        "web_endpoints": {
            "10.0.2.10": [
                {"path": "/", "method": "GET", "description": "Store homepage"},
                {"path": "/login", "method": "POST", "description": "User login", "params": ["email", "password"]},
                {"path": "/api/products", "method": "GET", "description": "Product listing"},
                {"path": "/api/upload/image", "method": "POST", "description": "Product image upload", "params": ["image_url"]},
                {"path": "/static/js/app.bundle.js", "method": "GET", "description": "Frontend JavaScript bundle"},
            ],
            "10.0.2.20": [
                {"path": "/api/v1/orders", "method": "GET", "description": "Order listing"},
                {"path": "/api/v1/orders/{id}", "method": "GET", "description": "Order details by ID", "params": ["id"]},
                {"path": "/api/v1/users/profile", "method": "GET", "description": "User profile"},
                {"path": "/api/v1/payment/process", "method": "POST", "description": "Payment processing"},
            ],
            "10.0.2.30": [
                {"path": "/", "method": "GET", "description": "Jenkins dashboard"},
                {"path": "/script", "method": "GET", "description": "Groovy script console"},
                {"path": "/manage", "method": "GET", "description": "Jenkins management"},
            ],
        },
        "vulnerabilities": [
            {
                "id": "VULN-M001",
                "host": "10.0.2.10",
                "endpoint": "/api/upload/image",
                "type": "Server-Side Request Forgery (SSRF)",
                "cwe": "CWE-918",
                "owasp": "A10:2021 - Server-Side Request Forgery",
                "cvss": 8.6,
                "severity": "High",
                "evidence": "The image_url parameter accepts internal URLs. Requesting image_url=http://10.0.2.30:8080 returns Jenkins dashboard HTML. Can be used to scan internal network.",
                "remediation": "Validate and whitelist allowed URL schemes and domains. Block requests to private IP ranges.",
                "discoverable_by": ["test_injection"],
            },
            {
                "id": "VULN-M002",
                "host": "10.0.2.20",
                "endpoint": "/api/v1/orders/{id}",
                "type": "Broken Access Control (IDOR)",
                "cwe": "CWE-639",
                "owasp": "A01:2021 - Broken Access Control",
                "cvss": 7.5,
                "severity": "High",
                "evidence": "Changing the order ID parameter to another user's order ID returns their order details including PII and payment info. No authorization check on resource ownership.",
                "remediation": "Implement proper authorization checks. Verify the authenticated user owns the requested resource.",
                "discoverable_by": ["test_auth"],
            },
            {
                "id": "VULN-M003",
                "host": "10.0.2.10",
                "endpoint": "/static/js/app.bundle.js",
                "type": "Sensitive Data Exposure",
                "cwe": "CWE-798",
                "owasp": "A02:2021 - Cryptographic Failures",
                "cvss": 7.8,
                "severity": "High",
                "evidence": "Hardcoded API key found in JavaScript bundle: STRIPE_SECRET_KEY=sk_live_EXAMPLE_REDACTED_KEY_HERE. Also contains internal API URLs.",
                "remediation": "Remove hardcoded secrets from client-side code. Use environment variables and server-side proxies for API keys.",
                "discoverable_by": ["check_secrets"],
            },
            {
                "id": "VULN-M004",
                "host": "10.0.2.30",
                "endpoint": "/script",
                "type": "Security Misconfiguration",
                "cwe": "CWE-306",
                "owasp": "A05:2021 - Security Misconfiguration",
                "cvss": 9.9,
                "severity": "Critical",
                "evidence": "Jenkins Groovy script console accessible without authentication. Allows arbitrary command execution on the CI/CD server. Full RCE via: 'cmd'.execute().text",
                "remediation": "Enable authentication on Jenkins. Restrict script console access to admin users. Place Jenkins behind VPN.",
                "discoverable_by": ["test_auth", "test_config"],
            },
            {
                "id": "VULN-M005",
                "host": "10.0.2.40",
                "endpoint": None,
                "type": "Weak Credentials",
                "cwe": "CWE-521",
                "owasp": "A07:2021 - Identification and Authentication Failures",
                "cvss": 8.2,
                "severity": "High",
                "evidence": "PostgreSQL accepts connections with weak credentials: dbuser/dbpass123. Password found via brute force. No connection rate limiting.",
                "remediation": "Enforce strong password policy. Restrict database access to application IPs. Use certificate-based authentication.",
                "discoverable_by": ["test_auth"],
            },
            {
                "id": "VULN-M006",
                "host": "10.0.2.10",
                "endpoint": "/",
                "type": "Cryptographic Failures",
                "cwe": "CWE-326",
                "owasp": "A02:2021 - Cryptographic Failures",
                "cvss": 5.3,
                "severity": "Medium",
                "evidence": "Server supports TLS 1.0 and TLS 1.1 which are deprecated. Weak cipher suites detected: TLS_RSA_WITH_3DES_EDE_CBC_SHA.",
                "remediation": "Disable TLS 1.0 and 1.1. Configure server to support only TLS 1.2+ with strong cipher suites.",
                "discoverable_by": ["test_crypto"],
            },
        ],
        "honeypots": [],
    }


def _scenario_hard() -> Dict[str, Any]:
    return {
        "id": "hard",
        "name": "Enterprise SOC2 Pre-Audit",
        "company": "FinSecure Corp.",
        "compliance_context": "SOC2 Type II pre-assessment",
        "target_network": "10.0.3.0/24",
        "max_steps": 60,
        "briefing": (
            "You are conducting a comprehensive SOC2 Type II pre-assessment for FinSecure Corp., "
            "a financial services company. Target network: 10.0.3.0/24. The infrastructure includes "
            "web applications, APIs, internal services, file storage, and a mail server. "
            "WARNING: Some services may be honeypots — false positive findings will be penalized. "
            "Conduct a thorough but careful audit. Map all findings to OWASP and CWE classifications."
        ),
        "hosts": {
            "10.0.3.10": {
                "hostname": "web-portal",
                "os": "Ubuntu 22.04 LTS",
                "role": "Customer Portal",
            },
            "10.0.3.20": {
                "hostname": "api-gateway",
                "os": "Ubuntu 22.04 LTS",
                "role": "API Gateway",
            },
            "10.0.3.30": {
                "hostname": "internal-app",
                "os": "Ubuntu 20.04 LTS",
                "role": "Internal Application Server",
            },
            "10.0.3.40": {
                "hostname": "file-server",
                "os": "Windows Server 2019",
                "role": "File Storage Server",
            },
            "10.0.3.50": {
                "hostname": "mail-server",
                "os": "Ubuntu 20.04 LTS",
                "role": "Email Server",
            },
            "10.0.3.99": {
                "hostname": "monitoring-01",
                "os": "Ubuntu 22.04 LTS",
                "role": "Monitoring & Alerting",
                "is_honeypot": True,
            },
        },
        "ports": {
            "10.0.3.10": [
                {"port": 22, "service": "ssh", "version": "OpenSSH 8.9p1", "state": "open"},
                {"port": 443, "service": "https", "version": "nginx 1.22.0", "state": "open"},
            ],
            "10.0.3.20": [
                {"port": 22, "service": "ssh", "version": "OpenSSH 8.9p1", "state": "open"},
                {"port": 8443, "service": "https", "version": "Kong Gateway 3.4", "state": "open"},
            ],
            "10.0.3.30": [
                {"port": 22, "service": "ssh", "version": "OpenSSH 8.2p1", "state": "open"},
                {"port": 8080, "service": "http", "version": "Apache Tomcat 9.0.31", "state": "open"},
                {"port": 5000, "service": "http", "version": "Flask 2.0.1", "state": "open"},
            ],
            "10.0.3.40": [
                {"port": 445, "service": "microsoft-ds", "version": "Windows Server 2019 SMB", "state": "open"},
                {"port": 3389, "service": "ms-wbt-server", "version": "Microsoft RDP", "state": "open"},
                {"port": 21, "service": "ftp", "version": "FileZilla 0.9.60", "state": "open"},
            ],
            "10.0.3.50": [
                {"port": 25, "service": "smtp", "version": "Postfix 3.4.13", "state": "open"},
                {"port": 143, "service": "imap", "version": "Dovecot 2.3.13", "state": "open"},
                {"port": 993, "service": "imaps", "version": "Dovecot 2.3.13", "state": "open"},
            ],
            "10.0.3.99": [
                {"port": 22, "service": "ssh", "version": "OpenSSH 8.9p1", "state": "open"},
                {"port": 9090, "service": "http", "version": "Prometheus 2.40.0", "state": "open"},
                {"port": 3000, "service": "http", "version": "Grafana 9.3.0", "state": "open"},
            ],
        },
        "web_endpoints": {
            "10.0.3.10": [
                {"path": "/", "method": "GET", "description": "Customer portal homepage"},
                {"path": "/login", "method": "POST", "description": "Customer login", "params": ["email", "password"]},
                {"path": "/dashboard", "method": "GET", "description": "Customer dashboard"},
                {"path": "/support/ticket", "method": "POST", "description": "Create support ticket", "params": ["subject", "message"]},
                {"path": "/profile/update", "method": "PUT", "description": "Update user profile", "params": ["name", "email", "phone"]},
            ],
            "10.0.3.20": [
                {"path": "/api/v2/accounts", "method": "GET", "description": "Account listing"},
                {"path": "/api/v2/accounts/{id}", "method": "GET", "description": "Account details"},
                {"path": "/api/v2/transfer", "method": "POST", "description": "Fund transfer", "params": ["from_account", "to_account", "amount"]},
                {"path": "/api/v2/statements", "method": "GET", "description": "Account statements"},
            ],
            "10.0.3.30": [
                {"path": "/", "method": "GET", "description": "Internal app dashboard"},
                {"path": "/admin/users", "method": "GET", "description": "User management"},
                {"path": "/reports/generate", "method": "POST", "description": "Generate report", "params": ["template", "date_range"]},
                {"path": "/upload", "method": "POST", "description": "File upload", "params": ["file"]},
            ],
        },
        "vulnerabilities": [
            {
                "id": "VULN-H001",
                "host": "10.0.3.10",
                "endpoint": "/support/ticket",
                "type": "Stored XSS",
                "cwe": "CWE-79",
                "owasp": "A03:2021 - Injection",
                "cvss": 6.1,
                "severity": "Medium",
                "evidence": "The 'message' field in support tickets does not sanitize HTML. Payload <script>document.cookie</script> is stored and rendered to support agents.",
                "remediation": "Sanitize all user input. Use output encoding. Implement Content-Security-Policy headers.",
                "discoverable_by": ["test_xss"],
            },
            {
                "id": "VULN-H002",
                "host": "10.0.3.20",
                "endpoint": "/api/v2/accounts/{id}",
                "type": "Broken Access Control (BOLA)",
                "cwe": "CWE-639",
                "owasp": "A01:2021 - Broken Access Control",
                "cvss": 7.5,
                "severity": "High",
                "evidence": "Enumerating account IDs (sequential integers) returns other customers' account details including balance, transaction history, and PII.",
                "remediation": "Use UUIDs instead of sequential IDs. Implement authorization checks verifying account ownership.",
                "discoverable_by": ["test_auth"],
            },
            {
                "id": "VULN-H003",
                "host": "10.0.3.20",
                "endpoint": "/api/v2/transfer",
                "type": "Business Logic Flaw",
                "cwe": "CWE-362",
                "owasp": "A04:2021 - Insecure Design",
                "cvss": 8.1,
                "severity": "High",
                "evidence": "Race condition in transfer endpoint. Sending multiple concurrent transfer requests allows double-spending — balance check and deduction are not atomic.",
                "remediation": "Implement database-level locking on balance operations. Use idempotency keys for transfer requests.",
                "discoverable_by": ["test_injection"],
            },
            {
                "id": "VULN-H004",
                "host": "10.0.3.30",
                "endpoint": "/reports/generate",
                "type": "Server-Side Template Injection (SSTI)",
                "cwe": "CWE-1336",
                "owasp": "A03:2021 - Injection",
                "cvss": 9.8,
                "severity": "Critical",
                "evidence": "The 'template' parameter is processed by Jinja2 without sandboxing. Payload {{7*7}} returns 49. Full RCE possible via __import__('os').popen('id').read().",
                "remediation": "Use Jinja2 SandboxedEnvironment. Never pass user input directly as template content.",
                "discoverable_by": ["test_injection"],
            },
            {
                "id": "VULN-H005",
                "host": "10.0.3.30",
                "endpoint": "/upload",
                "type": "Unrestricted File Upload",
                "cwe": "CWE-434",
                "owasp": "A04:2021 - Insecure Design",
                "cvss": 8.8,
                "severity": "High",
                "evidence": "File upload accepts .php and .jsp files without validation. Uploaded files are accessible at /uploads/<filename> and are executed by the server.",
                "remediation": "Whitelist allowed file types. Store uploads outside webroot. Rename files with random UUIDs.",
                "discoverable_by": ["test_config"],
            },
            {
                "id": "VULN-H006",
                "host": "10.0.3.40",
                "endpoint": None,
                "type": "Weak Credentials",
                "cwe": "CWE-521",
                "owasp": "A07:2021 - Identification and Authentication Failures",
                "cvss": 8.5,
                "severity": "High",
                "evidence": "FTP server accepts anonymous login. SMB share 'Documents' accessible with guest credentials. Contains sensitive financial reports and employee data.",
                "remediation": "Disable anonymous FTP access. Require authentication for all SMB shares. Implement least privilege access.",
                "discoverable_by": ["test_auth"],
            },
            {
                "id": "VULN-H007",
                "host": "10.0.3.40",
                "endpoint": None,
                "type": "Missing Encryption",
                "cwe": "CWE-319",
                "owasp": "A02:2021 - Cryptographic Failures",
                "cvss": 6.5,
                "severity": "Medium",
                "evidence": "FTP service (port 21) transfers data in plaintext. Sensitive files including financial reports are transmitted without encryption.",
                "remediation": "Replace FTP with SFTP or FTPS. Enforce TLS for all file transfers.",
                "discoverable_by": ["test_crypto"],
            },
            {
                "id": "VULN-H008",
                "host": "10.0.3.50",
                "endpoint": None,
                "type": "Email Security Misconfiguration",
                "cwe": "CWE-345",
                "owasp": "A05:2021 - Security Misconfiguration",
                "cvss": 5.8,
                "severity": "Medium",
                "evidence": "SMTP server allows open relay from internal network. No SPF, DKIM, or DMARC records configured. Susceptible to email spoofing.",
                "remediation": "Configure SPF, DKIM, and DMARC records. Restrict SMTP relay to authenticated users only.",
                "discoverable_by": ["test_config"],
            },
            {
                "id": "VULN-H009",
                "host": "10.0.3.30",
                "endpoint": None,
                "type": "Vulnerable Component",
                "cwe": "CWE-1035",
                "owasp": "A06:2021 - Vulnerable and Outdated Components",
                "cvss": 9.8,
                "severity": "Critical",
                "evidence": "Apache Tomcat 9.0.31 is vulnerable to CVE-2020-1938 (GhostCat). AJP connector on port 8009 allows file read and potential RCE.",
                "remediation": "Upgrade Tomcat to latest version. Disable AJP connector if not needed. Restrict AJP access to localhost.",
                "discoverable_by": ["vulnerability_scan"],
            },
            {
                "id": "VULN-H010",
                "host": "10.0.3.10",
                "endpoint": "/login",
                "type": "Missing Rate Limiting",
                "cwe": "CWE-307",
                "owasp": "A07:2021 - Identification and Authentication Failures",
                "cvss": 7.3,
                "severity": "High",
                "evidence": "Login endpoint allows unlimited authentication attempts. No CAPTCHA, no account lockout, no rate limiting detected after 1000+ requests.",
                "remediation": "Implement rate limiting (e.g., 5 attempts per minute). Add account lockout after 10 failed attempts. Deploy CAPTCHA.",
                "discoverable_by": ["test_auth"],
            },
        ],
        "honeypots": ["10.0.3.99"],
    }
