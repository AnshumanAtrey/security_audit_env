"""
Procedural scenario generator for the Security Audit Benchmark.

Generates complete security audit scenarios from a seed, producing
deterministic output: the same seed always yields the same topology,
services, and vulnerability placements.

Usage::

    from server.generator import generate_scenario

    scenario = generate_scenario("custom-easy-001", seed=42)
"""

from __future__ import annotations

import random
from typing import Any, Dict, List, Optional

from .topology import generate_topology
from .services import generate_services
from .placement import place_vulnerabilities

__all__ = ["generate_scenario"]

# ---------------------------------------------------------------------------
# Name / company / briefing generation pools
# ---------------------------------------------------------------------------

_SCENARIO_NAMES = {
    "easy": [
        "Startup Web App Audit",
        "Small Business Security Review",
        "MVP Launch Security Check",
        "Pre-Launch Vulnerability Assessment",
        "Seed-Stage Security Scan",
    ],
    "medium": [
        "E-commerce Platform Audit",
        "SaaS Platform Compliance Check",
        "Fintech API Security Assessment",
        "Healthcare Portal Audit",
        "Multi-Tier Application Review",
    ],
    "hard": [
        "Enterprise SOC2 Pre-Audit",
        "Financial Services Pen Test",
        "Critical Infrastructure Assessment",
        "Full-Scope Compliance Audit",
        "Enterprise Red Team Simulation",
    ],
}

_COMPANY_NAMES = {
    "easy": [
        "QuickLaunch SaaS Inc.",
        "NovaByte Solutions",
        "GreenField Apps Ltd.",
        "CloudPilot Startup",
        "BrightPath Technologies",
    ],
    "medium": [
        "ShopFast Commerce Ltd.",
        "MedSecure Health Systems",
        "PayStream Financial Inc.",
        "DataBridge Analytics Corp.",
        "OmniRetail Platforms",
    ],
    "hard": [
        "FinSecure Corp.",
        "GlobalTrust Banking Group",
        "Sentinel Defense Solutions",
        "ClearVault Financial Services",
        "NexGen Enterprise Holdings",
    ],
}

_COMPLIANCE_CONTEXTS = {
    "easy": [
        "Pre-launch security review",
        "Internal security baseline check",
        "Initial vulnerability assessment",
    ],
    "medium": [
        "PCI-DSS compliance assessment",
        "SOC2 readiness review",
        "Annual security audit",
        "HIPAA security risk analysis",
    ],
    "hard": [
        "SOC2 Type II pre-assessment",
        "PCI-DSS Level 1 certification audit",
        "Full-scope penetration test for regulatory compliance",
        "HIPAA Security Rule comprehensive audit",
    ],
}

_BRIEFING_TEMPLATE = (
    "You are conducting a {context} for {company}. "
    "Target network: {network}. {extra} "
    "Identify all security vulnerabilities, assess their severity, "
    "and submit structured findings with OWASP and CWE classifications."
)

_BRIEFING_EXTRAS = {
    "easy": (
        "The company runs a small web application stack. "
        "Focus on identifying common vulnerabilities."
    ),
    "medium": (
        "The infrastructure includes multiple services and an API layer. "
        "Some systems may only be discoverable after exploiting initial findings. "
        "Map all findings to the applicable compliance framework."
    ),
    "hard": (
        "The enterprise infrastructure spans web applications, APIs, internal "
        "services, file storage, and communication systems. "
        "WARNING: Some services may be honeypots — false positive findings "
        "will be penalised. Conduct a thorough but precise audit."
    ),
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DIFFICULTY_KEYWORDS = {
    "easy": "easy",
    "simple": "easy",
    "basic": "easy",
    "beginner": "easy",
    "medium": "medium",
    "moderate": "medium",
    "intermediate": "medium",
    "hard": "hard",
    "difficult": "hard",
    "advanced": "hard",
    "expert": "hard",
    "enterprise": "hard",
}


def _infer_difficulty(scenario_id: str) -> str:
    """Infer difficulty from scenario_id string.

    Checks for known keywords; defaults to ``"easy"`` when ambiguous.
    """
    sid_lower = scenario_id.lower()
    for keyword, diff in _DIFFICULTY_KEYWORDS.items():
        if keyword in sid_lower:
            return diff
    return "easy"


def _generate_name(difficulty: str, rng: random.Random) -> str:
    return rng.choice(_SCENARIO_NAMES[difficulty])


def _generate_company(difficulty: str, rng: random.Random) -> str:
    return rng.choice(_COMPANY_NAMES[difficulty])


def _pick_compliance(difficulty: str, rng: random.Random) -> str:
    return rng.choice(_COMPLIANCE_CONTEXTS[difficulty])


def _generate_briefing(
    difficulty: str, company: str, target_network: str,
    compliance_context: str,
) -> str:
    return _BRIEFING_TEMPLATE.format(
        context=compliance_context.lower(),
        company=company,
        network=target_network,
        extra=_BRIEFING_EXTRAS[difficulty],
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_scenario(
    scenario_id: str, seed: Optional[int] = None
) -> Dict[str, Any]:
    """Generate a complete security audit scenario.

    Parameters
    ----------
    scenario_id : str
        Unique identifier for the scenario.  The difficulty level is inferred
        from keywords in the ID (e.g. ``"custom-easy-001"`` -> easy).
    seed : int, optional
        Explicit RNG seed.  When *None*, a deterministic seed is derived
        from ``scenario_id`` via ``hash()``.

    Returns
    -------
    dict
        A complete scenario dictionary matching the schema used by
        ``scenarios.py``, including hosts, ports, web_endpoints,
        vulnerabilities, and honeypots.
    """
    difficulty = _infer_difficulty(scenario_id)
    rng = random.Random(seed if seed is not None else hash(scenario_id) & 0xFFFFFFFF)

    # 1. Topology.
    topo = generate_topology(difficulty, rng)

    # 2. Services and endpoints.
    ports, web_endpoints = generate_services(topo["hosts"], difficulty, rng)

    # 3. Vulnerability placement.
    vulns = place_vulnerabilities(
        topo["hosts"], ports, web_endpoints, difficulty, rng,
    )

    # 4. Metadata (use the same rng so order is deterministic).
    name = _generate_name(difficulty, rng)
    company = _generate_company(difficulty, rng)
    compliance_context = _pick_compliance(difficulty, rng)
    target_network = topo["target_network"]

    max_steps = {"easy": 30, "medium": 50, "hard": 60}[difficulty]

    briefing = _generate_briefing(
        difficulty, company, target_network, compliance_context,
    )

    return {
        "id": scenario_id,
        "name": name,
        "company": company,
        "compliance_context": compliance_context,
        "target_network": target_network,
        "max_steps": max_steps,
        "briefing": briefing,
        "hosts": topo["hosts"],
        "ports": ports,
        "web_endpoints": web_endpoints,
        "vulnerabilities": vulns,
        "honeypots": topo["honeypots"],
    }
