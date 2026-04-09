"""
Vulnerability placement engine for security audit scenarios.

Selects vulnerability types from the knowledge-base catalog, assigns them to
specific hosts/endpoints in the generated topology, and produces instances
that conform to the canonical vulnerability schema used by ``scenarios.py``.
"""

from __future__ import annotations

import math
import random
from typing import Any, Dict, List, Optional, Tuple

from ..knowledge_base.vulnerabilities import get_vuln_types, get_vuln_types_for_role
from ..knowledge_base.compliance import get_controls_for_vuln


# ---------------------------------------------------------------------------
# Difficulty presets
# ---------------------------------------------------------------------------

_DIFFICULTY_PARAMS = {
    "easy": {
        "vuln_count": (3, 3),
        "chain_count": (0, 0),
        "prefix": "E",
    },
    "medium": {
        "vuln_count": (5, 7),
        "chain_count": (1, 2),
        "prefix": "M",
    },
    "hard": {
        "vuln_count": (8, 12),
        "chain_count": (2, 4),
        "prefix": "H",
    },
}

# Severity thresholds for CVSS (matching NVD v3.1 qualitative scale).
_SEVERITY_SCALE = [
    (0.0, "None"),
    (0.1, "Low"),
    (4.0, "Medium"),
    (7.0, "High"),
    (9.0, "Critical"),
]

# Compliance frameworks to cycle through.
_FRAMEWORKS = ["PCI-DSS", "SOC2", "HIPAA", "Generic"]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _cvss_to_severity(cvss: float) -> str:
    """Map a CVSS score to a qualitative severity string."""
    severity = "Low"
    for threshold, label in _SEVERITY_SCALE:
        if cvss >= threshold:
            severity = label
    return severity


def _role_keyword(role: str) -> str:
    """Extract a canonical keyword from a free-form role string."""
    lower = role.lower()
    for kw in ("ci/cd", "database", "mail", "file", "monitoring", "api", "web"):
        if kw in lower:
            return kw
    if "application" in lower:
        return "web"
    return "web"


def _generate_evidence(vt: Any, host_ip: str, endpoint: Optional[str],
                       param: Optional[str], rng: random.Random) -> str:
    """Produce a human-readable evidence string from a VulnType."""
    parts: List[str] = []

    if param:
        parts.append(f"Parameter '{param}' is vulnerable to {vt.name}.")
    elif endpoint:
        parts.append(f"Endpoint '{endpoint}' on {host_ip} is vulnerable to {vt.name}.")
    else:
        parts.append(f"Host {host_ip} is vulnerable to {vt.name}.")

    # Append a trimmed excerpt of the type description.
    desc_sentences = vt.description.split(".")
    if desc_sentences:
        parts.append(desc_sentences[0].strip() + ".")

    return " ".join(parts)


def _pick_param_for_endpoint(endpoint: Dict, rng: random.Random) -> Optional[str]:
    """Return a parameter name from an endpoint's param list, or None."""
    params = endpoint.get("params", [])
    if not params:
        return None
    return rng.choice(params)


def _pick_cwe(vt: Any, rng: random.Random) -> str:
    """Pick one CWE-ID string from the VulnType's list."""
    cwe_id = rng.choice(vt.cwe_ids)
    return f"CWE-{cwe_id}"


def _pick_cvss(vt: Any, rng: random.Random) -> float:
    """Generate a CVSS score within the VulnType's range."""
    lo, hi = vt.cvss_range
    # Round to one decimal.
    return round(lo + rng.random() * (hi - lo), 1)


def _pick_compliance_controls(vt: Any, rng: random.Random) -> List[str]:
    """Return compliance controls for this vuln type from the KB."""
    framework = rng.choice(_FRAMEWORKS)
    controls = get_controls_for_vuln(vt.id, framework)
    if not controls:
        # Fallback: try Generic.
        controls = get_controls_for_vuln(vt.id, "Generic")
    return controls if controls else [f"{vt.owasp_category}"]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def place_vulnerabilities(
    hosts: Dict,
    ports: Dict,
    endpoints: Dict,
    difficulty: str,
    rng: random.Random,
    vuln_catalog: Optional[Dict] = None,
) -> List[Dict]:
    """Place vulnerability instances onto the generated topology.

    Parameters
    ----------
    hosts : dict
        ``{ip: {hostname, os, role, hidden_until?, is_honeypot?}}``
    ports : dict
        ``{ip: [{port, service, version, state}, ...]}``
    endpoints : dict
        ``{ip: [{path, method, description, params}, ...]}``
    difficulty : str
        ``"easy"`` | ``"medium"`` | ``"hard"``
    rng : random.Random
        Seeded RNG for deterministic output.
    vuln_catalog : dict, optional
        Override for ``get_vuln_types()``; mainly for testing.

    Returns
    -------
    list[dict]
        Vulnerability instances in the canonical schema.
    """
    params = _DIFFICULTY_PARAMS[difficulty]
    prefix = params["prefix"]
    total_vulns = rng.randint(*params["vuln_count"])
    chain_count = rng.randint(*params["chain_count"])

    catalog = vuln_catalog or get_vuln_types()

    # Separate hosts into visible, hidden, and honeypots.
    visible_ips: List[str] = []
    hidden_ips: List[str] = []
    honeypot_ips: List[str] = []

    for ip, info in hosts.items():
        if info.get("is_honeypot"):
            honeypot_ips.append(ip)
        elif "hidden_until" in info:
            hidden_ips.append(ip)
        else:
            visible_ips.append(ip)

    # Sort for determinism.
    visible_ips.sort()
    hidden_ips.sort()
    honeypot_ips.sort()

    # We need at least one visible host.
    if not visible_ips:
        raise ValueError("Topology must have at least one visible host.")

    # --- Plan chain structure ---
    # Each chain: one gateway vuln on a visible host -> unlocks a hidden host.
    chain_count = min(chain_count, len(hidden_ips))
    # Reserve slots: chain_count gateway vulns + chain_count chained vulns.
    independent_count = max(0, total_vulns - chain_count * 2)

    vulns: List[Dict] = []
    vuln_index = 1

    # Gateway vulns are placed on visible hosts and unlock hidden hosts.
    gateway_vuln_ids: List[str] = []
    for chain_idx in range(chain_count):
        gateway_ip = visible_ips[chain_idx % len(visible_ips)]
        hidden_ip = hidden_ips[chain_idx]
        role = hosts[gateway_ip]["role"]

        # Pick a vuln type with chain_potential=True.
        role_vulns = get_vuln_types_for_role(role)
        chain_candidates = [v for v in role_vulns if v.chain_potential]
        if not chain_candidates:
            chain_candidates = [v for v in catalog.values() if v.chain_potential]
        vt = rng.choice(chain_candidates)

        vuln_id = f"VULN-{prefix}{vuln_index:03d}"
        vuln_index += 1

        # Pick endpoint if applicable.
        host_eps = endpoints.get(gateway_ip, [])
        endpoint_path = None
        param = None
        if vt.requires_params and host_eps:
            ep = rng.choice(host_eps)
            endpoint_path = ep["path"]
            param = _pick_param_for_endpoint(ep, rng)
        elif host_eps:
            ep = rng.choice(host_eps)
            endpoint_path = ep["path"]

        cvss = _pick_cvss(vt, rng)

        vuln_dict = {
            "id": vuln_id,
            "host": gateway_ip,
            "endpoint": endpoint_path,
            "type": vt.name,
            "cwe": _pick_cwe(vt, rng),
            "owasp": vt.owasp_category,
            "cvss": cvss,
            "severity": _cvss_to_severity(cvss),
            "evidence": _generate_evidence(vt, gateway_ip, endpoint_path, param, rng),
            "remediation": vt.remediation_template,
            "discoverable_by": list(vt.discoverable_by),
            "requires_found": [],
            "compliance_controls": _pick_compliance_controls(vt, rng),
        }
        vulns.append(vuln_dict)
        gateway_vuln_ids.append(vuln_id)

        # Mark the hidden host.
        hosts[hidden_ip]["hidden_until"] = [vuln_id]

    # --- Chained vulns on hidden hosts ---
    for chain_idx in range(chain_count):
        hidden_ip = hidden_ips[chain_idx]
        gateway_vuln_id = gateway_vuln_ids[chain_idx]
        role = hosts[hidden_ip]["role"]

        role_vulns = get_vuln_types_for_role(role)
        if not role_vulns:
            role_vulns = list(catalog.values())
        vt = rng.choice(role_vulns)

        vuln_id = f"VULN-{prefix}{vuln_index:03d}"
        vuln_index += 1

        host_eps = endpoints.get(hidden_ip, [])
        endpoint_path = None
        param = None
        if vt.requires_params and host_eps:
            ep = rng.choice(host_eps)
            endpoint_path = ep["path"]
            param = _pick_param_for_endpoint(ep, rng)
        elif host_eps:
            ep = rng.choice(host_eps)
            endpoint_path = ep["path"]

        cvss = _pick_cvss(vt, rng)

        vuln_dict = {
            "id": vuln_id,
            "host": hidden_ip,
            "endpoint": endpoint_path,
            "type": vt.name,
            "cwe": _pick_cwe(vt, rng),
            "owasp": vt.owasp_category,
            "cvss": cvss,
            "severity": _cvss_to_severity(cvss),
            "evidence": _generate_evidence(vt, hidden_ip, endpoint_path, param, rng),
            "remediation": vt.remediation_template,
            "discoverable_by": list(vt.discoverable_by),
            "requires_found": [gateway_vuln_id],
            "compliance_controls": _pick_compliance_controls(vt, rng),
        }
        vulns.append(vuln_dict)

    # --- Independent vulns on all non-honeypot hosts ---
    all_real_ips = visible_ips + hidden_ips
    for _ in range(independent_count):
        target_ip = rng.choice(all_real_ips)
        role = hosts[target_ip]["role"]

        role_vulns = get_vuln_types_for_role(role)
        if not role_vulns:
            role_vulns = list(catalog.values())

        # Avoid duplicating the exact same vuln type on the same host if possible.
        used_types_on_host = {v["type"] for v in vulns if v["host"] == target_ip}
        candidates = [v for v in role_vulns if v.name not in used_types_on_host]
        if not candidates:
            candidates = role_vulns
        vt = rng.choice(candidates)

        vuln_id = f"VULN-{prefix}{vuln_index:03d}"
        vuln_index += 1

        host_eps = endpoints.get(target_ip, [])
        endpoint_path = None
        param = None
        if vt.requires_params and host_eps:
            ep = rng.choice(host_eps)
            endpoint_path = ep["path"]
            param = _pick_param_for_endpoint(ep, rng)
        elif "web_endpoint" in vt.applicable_to and host_eps:
            ep = rng.choice(host_eps)
            endpoint_path = ep["path"]
        else:
            endpoint_path = None

        cvss = _pick_cvss(vt, rng)

        # For vulns on hidden hosts, they require the gateway.
        requires: List[str] = []
        if target_ip in hidden_ips:
            idx = hidden_ips.index(target_ip)
            if idx < len(gateway_vuln_ids):
                requires = [gateway_vuln_ids[idx]]

        vuln_dict = {
            "id": vuln_id,
            "host": target_ip,
            "endpoint": endpoint_path,
            "type": vt.name,
            "cwe": _pick_cwe(vt, rng),
            "owasp": vt.owasp_category,
            "cvss": cvss,
            "severity": _cvss_to_severity(cvss),
            "evidence": _generate_evidence(vt, target_ip, endpoint_path, param, rng),
            "remediation": vt.remediation_template,
            "discoverable_by": list(vt.discoverable_by),
            "requires_found": requires,
            "compliance_controls": _pick_compliance_controls(vt, rng),
        }
        vulns.append(vuln_dict)

    return vulns
