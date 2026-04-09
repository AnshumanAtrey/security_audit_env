"""
Service and web-endpoint generator for security audit scenarios.

Assigns realistic ports, service versions, and parameterised web endpoints
to each host based on its role.  All randomness is driven by the
caller-supplied ``rng``.
"""

from __future__ import annotations

import random
from typing import Dict, List, Tuple

# ---------------------------------------------------------------------------
# Port / service templates by role keyword
# ---------------------------------------------------------------------------

_ROLE_PORTS: Dict[str, List[Dict]] = {
    "web": [
        {"port": 22, "service": "ssh"},
        {"port": 80, "service": "http"},
        {"port": 443, "service": "https"},
    ],
    "api": [
        {"port": 22, "service": "ssh"},
        {"port": 8080, "service": "http"},
        {"port": 443, "service": "https"},
    ],
    "database": [
        {"port": 22, "service": "ssh"},
        # mysql or postgres chosen at runtime
    ],
    "ci/cd": [
        {"port": 22, "service": "ssh"},
        {"port": 8080, "service": "http"},
    ],
    "mail": [
        {"port": 22, "service": "ssh"},
        {"port": 25, "service": "smtp"},
        {"port": 143, "service": "imap"},
        {"port": 993, "service": "imaps"},
    ],
    "file": [
        {"port": 22, "service": "ssh"},
        {"port": 21, "service": "ftp"},
        {"port": 445, "service": "smb"},
    ],
    "monitoring": [
        {"port": 22, "service": "ssh"},
        {"port": 9090, "service": "http"},
    ],
}

# ---------------------------------------------------------------------------
# Realistic version strings
# ---------------------------------------------------------------------------

_VERSIONS: Dict[str, List[str]] = {
    "ssh": [
        "OpenSSH 8.9p1", "OpenSSH 8.2p1", "OpenSSH 9.0p1",
        "OpenSSH 7.9p1", "OpenSSH 8.4p1",
    ],
    "http": [
        "nginx 1.24.0", "nginx 1.22.0", "Apache 2.4.57",
        "Apache 2.4.41", "Express.js 4.18.2 (Node.js)",
        "Apache Tomcat 9.0.73", "Flask 2.3.2",
    ],
    "https": [
        "nginx 1.24.0", "nginx 1.22.0", "Apache 2.4.57",
        "Apache 2.4.41", "Kong Gateway 3.4",
    ],
    "mysql": ["MySQL 8.0.33", "MySQL 5.7.42", "MariaDB 10.11.4"],
    "postgres": ["PostgreSQL 15.3", "PostgreSQL 14.8", "PostgreSQL 13.11"],
    "smtp": ["Postfix 3.7.6", "Postfix 3.4.13", "Exim 4.96"],
    "imap": ["Dovecot 2.3.20", "Dovecot 2.3.13"],
    "imaps": ["Dovecot 2.3.20", "Dovecot 2.3.13"],
    "ftp": ["vsftpd 3.0.5", "FileZilla 1.7.0", "ProFTPD 1.3.8"],
    "smb": ["Windows Server 2019 SMB", "Samba 4.18.5"],
    "jenkins": ["Jenkins 2.401.1", "Jenkins 2.375.3"],
    "gitlab": ["GitLab 16.2.1"],
}

# ---------------------------------------------------------------------------
# Web endpoint pools by role keyword
# ---------------------------------------------------------------------------

_ENDPOINT_POOLS: Dict[str, List[Dict]] = {
    "web": [
        {"path": "/", "method": "GET", "description": "Homepage", "params": []},
        {"path": "/login", "method": "POST", "description": "User login",
         "params": ["username", "password"]},
        {"path": "/register", "method": "POST", "description": "User registration",
         "params": ["username", "email", "password"]},
        {"path": "/api/search", "method": "GET", "description": "Search functionality",
         "params": ["q", "page", "sort"]},
        {"path": "/api/products", "method": "GET", "description": "Product listing",
         "params": ["category", "page"]},
        {"path": "/api/products/{id}", "method": "GET", "description": "Product details",
         "params": ["id"]},
        {"path": "/profile/update", "method": "PUT", "description": "Update user profile",
         "params": ["name", "email", "phone"]},
        {"path": "/support/ticket", "method": "POST", "description": "Create support ticket",
         "params": ["subject", "message"]},
        {"path": "/admin", "method": "GET", "description": "Admin panel", "params": []},
        {"path": "/api/upload", "method": "POST", "description": "File upload",
         "params": ["file", "type"]},
        {"path": "/dashboard", "method": "GET", "description": "User dashboard", "params": []},
        {"path": "/logout", "method": "POST", "description": "User logout", "params": []},
    ],
    "api": [
        {"path": "/api/v1/auth/login", "method": "POST",
         "description": "API authentication", "params": ["username", "password"]},
        {"path": "/api/v1/users", "method": "GET", "description": "User listing",
         "params": ["page", "limit"]},
        {"path": "/api/v1/users/{id}", "method": "GET", "description": "User profile",
         "params": ["id"]},
        {"path": "/api/v1/users/{id}", "method": "PUT", "description": "Update user",
         "params": ["id", "name", "email", "role"]},
        {"path": "/api/v1/orders", "method": "GET", "description": "Order listing",
         "params": ["status", "page"]},
        {"path": "/api/v1/orders/{id}", "method": "GET", "description": "Order details",
         "params": ["id"]},
        {"path": "/api/v1/transfer", "method": "POST", "description": "Fund transfer",
         "params": ["from_account", "to_account", "amount"]},
        {"path": "/api/v1/statements", "method": "GET",
         "description": "Account statements", "params": ["account_id", "from", "to"]},
        {"path": "/api/v1/export", "method": "GET", "description": "Data export",
         "params": ["format", "filename"]},
        {"path": "/api/v1/webhook", "method": "POST", "description": "Webhook receiver",
         "params": ["url", "event"]},
        {"path": "/api/v1/config", "method": "GET", "description": "API configuration",
         "params": []},
        {"path": "/healthcheck", "method": "GET", "description": "Health check",
         "params": []},
    ],
    "ci/cd": [
        {"path": "/", "method": "GET", "description": "CI/CD dashboard", "params": []},
        {"path": "/script", "method": "GET", "description": "Script console", "params": []},
        {"path": "/manage", "method": "GET", "description": "Management panel", "params": []},
        {"path": "/job/build", "method": "POST", "description": "Trigger build",
         "params": ["project", "branch"]},
        {"path": "/credentials", "method": "GET",
         "description": "Stored credentials", "params": []},
        {"path": "/api/json", "method": "GET", "description": "API info endpoint",
         "params": []},
    ],
    "file": [
        {"path": "/files", "method": "GET", "description": "File browser",
         "params": ["path"]},
        {"path": "/files/download", "method": "GET", "description": "File download",
         "params": ["path", "filename"]},
        {"path": "/files/upload", "method": "POST", "description": "File upload",
         "params": ["file", "destination"]},
        {"path": "/shares", "method": "GET", "description": "List network shares",
         "params": []},
    ],
    "mail": [
        # Mail servers typically don't have web endpoints; leave empty.
    ],
    "database": [
        # Database servers typically don't have web endpoints; leave empty.
    ],
    "monitoring": [
        {"path": "/", "method": "GET", "description": "Monitoring dashboard", "params": []},
        {"path": "/api/targets", "method": "GET", "description": "Monitored targets",
         "params": []},
        {"path": "/api/alerts", "method": "GET", "description": "Active alerts",
         "params": ["severity", "status"]},
        {"path": "/api/query", "method": "POST", "description": "Query metrics",
         "params": ["query", "start", "end"]},
    ],
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _role_keyword(role: str) -> str:
    """Map a free-form role string to a canonical keyword."""
    lower = role.lower()
    for keyword in ("ci/cd", "database", "mail", "file", "monitoring", "api", "web"):
        if keyword in lower:
            return keyword
    # Generic application server -> web
    if "application" in lower:
        return "web"
    return "web"


def _pick_version(service: str, rng: random.Random) -> str:
    """Return a deterministic version string for *service*."""
    candidates = _VERSIONS.get(service, [])
    if not candidates:
        return service
    return rng.choice(candidates)


def _pick_db_port(rng: random.Random) -> Dict:
    """Return either a MySQL or PostgreSQL port dict."""
    if rng.random() < 0.5:
        return {"port": 3306, "service": "mysql"}
    return {"port": 5432, "service": "postgres"}


# ---------------------------------------------------------------------------
# Endpoint count by difficulty
# ---------------------------------------------------------------------------

_ENDPOINT_COUNTS = {
    "easy": (3, 4),
    "medium": (5, 8),
    "hard": (6, 10),
}

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_services(
    hosts: Dict, difficulty: str, rng: random.Random
) -> Tuple[Dict, Dict]:
    """Generate port/service configs and web endpoints for every host.

    Parameters
    ----------
    hosts : dict
        ``{ip: {hostname, os, role, ...}}`` as returned by
        :func:`generate_topology`.
    difficulty : str
        One of ``"easy"``, ``"medium"``, ``"hard"``.
    rng : random.Random
        Seeded RNG instance for deterministic output.

    Returns
    -------
    tuple[dict, dict]
        ``(ports_by_host, web_endpoints_by_host)``

        *ports_by_host*: ``{ip: [{port, service, version, state}, ...]}``
        *web_endpoints_by_host*: ``{ip: [{path, method, description, params}, ...]}``
    """
    ports_by_host: Dict[str, List[Dict]] = {}
    endpoints_by_host: Dict[str, List[Dict]] = {}

    for ip, host_info in hosts.items():
        role = host_info.get("role", "Web Application Server")
        kw = _role_keyword(role)

        # --- ports ---
        base_ports = list(_ROLE_PORTS.get(kw, _ROLE_PORTS["web"]))
        if kw == "database":
            base_ports.append(_pick_db_port(rng))

        port_list: List[Dict] = []
        for bp in base_ports:
            port_list.append({
                "port": bp["port"],
                "service": bp["service"],
                "version": _pick_version(bp["service"], rng),
                "state": "open",
            })
        ports_by_host[ip] = port_list

        # --- web endpoints ---
        pool = list(_ENDPOINT_POOLS.get(kw, _ENDPOINT_POOLS["web"]))
        if not pool:
            endpoints_by_host[ip] = []
            continue

        rng.shuffle(pool)
        ep_min, ep_max = _ENDPOINT_COUNTS[difficulty]
        count = min(rng.randint(ep_min, ep_max), len(pool))
        chosen = pool[:count]

        # Ensure the chosen list is sorted by path for stability.
        chosen.sort(key=lambda e: e["path"])
        endpoints_by_host[ip] = chosen

    return ports_by_host, endpoints_by_host
