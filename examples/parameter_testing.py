"""
Example: Parameter-Level Security Testing
==========================================
Demonstrates how an agent can test individual parameters on endpoints,
rather than testing entire endpoints at once. This provides more precise
vulnerability identification.

Usage:
    PYTHONPATH=. python examples/parameter_testing.py
"""

from security_audit_env import SecurityAuditEnv, SecurityAuditAction


def main():
    env_url = "http://localhost:8000"

    with SecurityAuditEnv(base_url=env_url).sync() as env:
        result = env.reset(scenario_id="easy")
        print(f"Scenario: {result.observation.message[:80]}...")

        # Step 1: Discover the network
        result = env.step(SecurityAuditAction(
            action_type="use_tool",
            tool_name="network_scan",
            arguments={"target": "10.0.1.0/24"},
        ))
        hosts = result.observation.discovered_hosts
        print(f"\nDiscovered hosts: {hosts}")

        # Step 2: Crawl to find endpoints WITH parameters
        host = hosts[0]
        result = env.step(SecurityAuditAction(
            action_type="use_tool",
            tool_name="web_crawl",
            arguments={"host": host},
        ))
        print(f"\nWeb crawl output:\n{result.observation.tool_output}")

        # Step 3: Test a specific parameter for injection
        result = env.step(SecurityAuditAction(
            action_type="use_tool",
            tool_name="test_injection",
            arguments={
                "host": host,
                "endpoint": "/api/login",
                "parameter": "username",  # test this specific parameter
            },
        ))
        print(f"\nInjection test on 'username' parameter:")
        print(result.observation.tool_output[:300])

        # Step 4: Test a different parameter on the same endpoint
        result = env.step(SecurityAuditAction(
            action_type="use_tool",
            tool_name="test_injection",
            arguments={
                "host": host,
                "endpoint": "/api/login",
                "parameter": "password",  # different parameter
            },
        ))
        print(f"\nInjection test on 'password' parameter:")
        print(result.observation.tool_output[:300])

        # Step 5: Submit finding based on parameter-level evidence
        result = env.step(SecurityAuditAction(
            action_type="submit_finding",
            arguments={
                "title": "SQL Injection in username parameter",
                "host": host,
                "endpoint": "/api/login",
                "type": "SQL Injection",
                "severity": "Critical",
                "cvss_score": 9.8,
                "cwe": "CWE-89",
                "owasp": "A03:2021 - Injection",
                "evidence": "MySQL error triggered via username parameter with payload ' OR 1=1--",
                "remediation": "Use parameterized queries for all database operations",
            },
        ))
        print(f"\nFinding submitted. Reward: {result.reward}")

        # Step 6: Generate report
        result = env.step(SecurityAuditAction(action_type="generate_report"))
        print(f"\n{result.observation.tool_output}")


if __name__ == "__main__":
    main()
