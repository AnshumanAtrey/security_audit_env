"""
Example: Three-Tier Difficulty Comparison
==========================================
Runs the same vulnerability type (SQL Injection) across all three
difficulty tiers to show how tool output changes from labeled (easy)
to evidence-based (medium) to raw HTTP (hard).

This demonstrates the core innovation: measuring whether an AI agent
can reason from raw evidence, not just parse labels.

Usage:
    PYTHONPATH=. python examples/difficulty_comparison.py
"""

from security_audit_env import SecurityAuditEnv, SecurityAuditAction


def run_injection_test(env_url: str, scenario_id: str):
    """Run a single injection test and show the output."""
    with SecurityAuditEnv(base_url=env_url).sync() as env:
        result = env.reset(scenario_id=scenario_id)

        # Scan network
        result = env.step(SecurityAuditAction(
            action_type="use_tool",
            tool_name="network_scan",
            arguments={"target": result.observation.message.split("network: ")[1].split(".")[0] + ".0/24"
                        if "network: " in (result.observation.message or "") else "10.0.1.0/24"},
        ))

        hosts = result.observation.discovered_hosts
        if not hosts:
            print(f"  No hosts found for {scenario_id}")
            return

        # Test injection on first host
        result = env.step(SecurityAuditAction(
            action_type="use_tool",
            tool_name="test_injection",
            arguments={"host": hosts[0], "endpoint": "/api/login"},
        ))

        return result.observation.tool_output


def main():
    env_url = "http://localhost:8000"

    for scenario_id in ["easy", "medium", "hard"]:
        print(f"\n{'='*60}")
        print(f"DIFFICULTY: {scenario_id.upper()}")
        print(f"{'='*60}")

        output = run_injection_test(env_url, scenario_id)
        if output:
            # Show first 500 chars
            preview = output[:500] + ("..." if len(output) > 500 else "")
            print(preview)
        else:
            print("  (no injection test output)")

    print(f"\n{'='*60}")
    print("OBSERVATION:")
    print("  Easy:   Agent sees labeled output with CWE, CVSS, remediation")
    print("  Medium: Agent sees evidence of anomaly, must classify it")
    print("  Hard:   Agent sees raw HTTP response, must infer everything")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
