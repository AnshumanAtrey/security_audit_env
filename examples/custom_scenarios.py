"""
Example: Dynamic Scenario Generation
=====================================
Demonstrates how any string generates a unique, deterministic scenario.
Same ID always produces the same network topology, vulnerabilities, and
attack chains -- enabling reproducible benchmarks with infinite variety.

Usage:
    PYTHONPATH=. python examples/custom_scenarios.py
"""

from server.scenarios import get_scenario


def show_scenario(scenario_id: str):
    """Display key details of a generated scenario."""
    s = get_scenario(scenario_id)
    print(f"\n{'='*60}")
    print(f"Scenario ID: {s['id']}")
    print(f"Name:        {s['name']}")
    print(f"Company:     {s['company']}")
    print(f"Compliance:  {s['compliance_context']}")
    print(f"Network:     {s['target_network']}")
    print(f"Max Steps:   {s['max_steps']}")
    print(f"Hosts:       {len(s['hosts'])} ({len(s['honeypots'])} honeypots)")
    print(f"Vulns:       {len(s['vulnerabilities'])}")

    print(f"\nHosts:")
    for ip, info in s["hosts"].items():
        hidden = f" [HIDDEN until {info.get('hidden_until', [])}]" if info.get("hidden_until") else ""
        honeypot = " [HONEYPOT]" if info.get("is_honeypot") else ""
        print(f"  {ip:15s} {info['hostname']:20s} {info['role']}{hidden}{honeypot}")

    print(f"\nVulnerabilities:")
    for v in s["vulnerabilities"]:
        chain = f" (requires: {v['requires_found']})" if v.get("requires_found") else ""
        print(f"  {v['id']:12s} {v['type']:35s} {v['host']:15s} CVSS {v['cvss']}{chain}")


def main():
    # Built-in scenarios
    for sid in ["easy", "medium", "hard"]:
        show_scenario(sid)

    # Custom scenarios -- any string works
    for sid in ["fintech-startup-2024", "healthcare-enterprise-audit", "hard-ecommerce-pentest"]:
        show_scenario(sid)

    # Determinism check
    s1 = get_scenario("reproducibility-test")
    s2 = get_scenario("reproducibility-test")
    hosts_match = list(s1["hosts"].keys()) == list(s2["hosts"].keys())
    vulns_match = len(s1["vulnerabilities"]) == len(s2["vulnerabilities"])
    print(f"\n{'='*60}")
    print(f"Determinism check: hosts={'PASS' if hosts_match else 'FAIL'}, vulns={'PASS' if vulns_match else 'FAIL'}")


if __name__ == "__main__":
    main()
