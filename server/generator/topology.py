"""
Network topology generator for security audit scenarios.

Generates hosts with IPs, hostnames, OS, roles, honeypots, and hidden-host
metadata.  All randomness is driven by the caller-supplied ``rng`` so that
identical seeds produce identical topologies.
"""

from __future__ import annotations

import random
from typing import Dict, List, Tuple

# ---------------------------------------------------------------------------
# Pools
# ---------------------------------------------------------------------------

_HOSTNAMES = [
    "web-01", "web-02", "api-gateway", "api-backend",
    "db-primary", "db-replica", "jenkins-ci", "gitlab-ci",
    "file-server", "mail-server", "staging-app", "monitoring-01",
    "auth-service", "cache-01", "proxy-01", "internal-app",
    "log-collector", "build-runner",
]

_OS_CHOICES = [
    "Ubuntu 22.04 LTS",
    "CentOS 8",
    "Debian 12",
    "Windows Server 2019",
    "Alpine 3.18",
]

_ROLES = [
    "Web Application Server",
    "API Gateway",
    "Database Server",
    "CI/CD Server",
    "File Server",
    "Mail Server",
    "Application Server",
    "Monitoring Server",
]

# Honeypots get real-sounding names to fool the agent.
_HONEYPOT_HOSTNAMES = [
    "staging-app-02", "dev-portal", "backup-db",
    "legacy-api", "test-web-01", "qa-service",
]

# ---------------------------------------------------------------------------
# Difficulty presets
# ---------------------------------------------------------------------------

_DIFFICULTY_PARAMS: Dict[str, Dict] = {
    "easy": {
        "host_count": (2, 2),
        "hidden_count": (0, 0),
        "honeypot_count": (0, 0),
        "subnet": 1,
    },
    "medium": {
        "host_count": (3, 5),
        "hidden_count": (1, 2),
        "honeypot_count": (0, 0),
        "subnet": 2,
    },
    "hard": {
        "host_count": (5, 8),
        "hidden_count": (2, 4),
        "honeypot_count": (1, 2),
        "subnet": 3,
    },
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_topology(difficulty: str, rng: random.Random) -> Dict:
    """Generate a network topology for *difficulty*.

    Returns
    -------
    dict
        ``{"hosts": {ip: {hostname, os, role, ...}},
          "honeypots": [ip],
          "target_network": str}``
    """
    params = _DIFFICULTY_PARAMS[difficulty]
    subnet = params["subnet"]

    total_hosts = rng.randint(*params["host_count"])
    hidden_count = min(rng.randint(*params["hidden_count"]), total_hosts - 1)
    honeypot_count = rng.randint(*params["honeypot_count"])

    # Shuffle pools deterministically.
    hostnames = list(_HOSTNAMES)
    rng.shuffle(hostnames)
    os_pool = list(_OS_CHOICES)
    roles = list(_ROLES)
    rng.shuffle(roles)

    hosts: Dict[str, Dict] = {}
    honeypots: List[str] = []

    # --- regular hosts ---
    visible_count = total_hosts - hidden_count
    for idx in range(total_hosts):
        ip = f"10.0.{subnet}.{10 + idx * 10}"
        host: Dict = {
            "hostname": hostnames[idx % len(hostnames)],
            "os": os_pool[rng.randint(0, len(os_pool) - 1)],
            "role": roles[idx % len(roles)],
        }
        if idx >= visible_count:
            # Hidden host — will be given a concrete ``hidden_until`` list
            # once vulnerabilities are placed.  Mark with a sentinel for now.
            host["hidden_until"] = []  # placeholder; placement fills this in
        hosts[ip] = host

    # --- honeypots ---
    hp_hostnames = list(_HONEYPOT_HOSTNAMES)
    rng.shuffle(hp_hostnames)
    for hp_idx in range(honeypot_count):
        hp_ip = f"10.0.{subnet}.{90 + hp_idx * 3}"
        hp_host: Dict = {
            "hostname": hp_hostnames[hp_idx % len(hp_hostnames)],
            "os": os_pool[rng.randint(0, len(os_pool) - 1)],
            "role": rng.choice(["Application Server", "Web Application Server",
                                "Monitoring Server"]),
            "is_honeypot": True,
        }
        hosts[hp_ip] = hp_host
        honeypots.append(hp_ip)

    return {
        "hosts": hosts,
        "honeypots": honeypots,
        "target_network": f"10.0.{subnet}.0/24",
    }
