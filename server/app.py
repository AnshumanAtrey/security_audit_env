# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""
FastAPI application for the Security Audit Environment.
"""

try:
    from openenv.core.env_server.http_server import create_app
except Exception as e:
    raise ImportError(
        "openenv is required. Install with: pip install openenv-core"
    ) from e

try:
    from models import SecurityAuditAction, SecurityAuditObservation
    from server.security_audit_env_environment import SecurityAuditEnvironment
    from server.scenarios import list_scenarios
except ImportError:
    from ..models import SecurityAuditAction, SecurityAuditObservation
    from .security_audit_env_environment import SecurityAuditEnvironment
    from .scenarios import list_scenarios

from fastapi.responses import JSONResponse

app = create_app(
    SecurityAuditEnvironment,
    SecurityAuditAction,
    SecurityAuditObservation,
    env_name="security_audit_env",
    max_concurrent_envs=4,
)


# --- Custom Hackathon Endpoints ---

@app.get("/tasks")
async def get_tasks():
    """Return list of available tasks and the action schema."""
    scenarios = list_scenarios()
    action_schema = SecurityAuditAction.model_json_schema()
    return JSONResponse({
        "tasks": scenarios,
        "action_schema": action_schema,
        "tools": [
            "network_scan", "service_fingerprint", "web_crawl",
            "vulnerability_scan", "test_injection", "test_xss",
            "test_auth", "test_config", "test_crypto", "check_secrets",
        ],
    })


@app.post("/grader")
async def run_grader(data: dict = None):
    """Return grader scores for a completed episode.

    Expects: { "scenario_id": "easy"|"medium"|"hard",
               "findings": [...], "discovered_hosts": [...],
               "discovered_ports": {...} }
    """
    if not data:
        return JSONResponse({"error": "POST body required"}, status_code=400)

    try:
        from server.scenarios import get_scenario
        from server.grader import grade_episode
    except ImportError:
        from .scenarios import get_scenario
        from .grader import grade_episode

    scenario_id = data.get("scenario_id", "easy")
    scenario = get_scenario(scenario_id)
    grades = grade_episode(
        scenario,
        data.get("findings", []),
        data.get("discovered_hosts", []),
        data.get("discovered_ports", {}),
    )
    return JSONResponse(grades)


@app.post("/baseline")
async def run_baseline():
    """Trigger baseline inference and return scores for all 3 tasks.

    Runs a deterministic audit agent (no LLM) that scans, tests endpoints,
    parses tool output for detections, submits findings, and pivots through
    discovered vulns to unlock hidden hosts.
    """
    import re

    try:
        from server.scenarios import get_scenario
    except ImportError:
        from .scenarios import get_scenario

    def _do_step(env, **kwargs):
        """Step and return (obs, done)."""
        obs = env.step(SecurityAuditAction(**kwargs))
        return obs, getattr(obs, "done", False)

    def _parse_and_submit(env, host, endpoint, tool_name, obs_text):
        """Parse tool output for detections and submit findings."""
        # Patterns that indicate a vulnerability was found
        patterns = {
            "CRITICAL": re.compile(r"\[CRITICAL\]\s*(.+?)(?:\n|$)"),
            "ALERT": re.compile(r"\[ALERT\]\s*(.+?)(?:\n|$)"),
            "MISCONFIGURATION": re.compile(r"\[MISCONFIGURATION\]\s*(.+?)(?:\n|$)"),
            "CRYPTO ISSUE": re.compile(r"\[CRYPTO ISSUE\]\s*(.+?)(?:\n|$)"),
            "SECRET EXPOSED": re.compile(r"\[SECRET EXPOSED\]\s*(.+?)(?:\n|$)"),
            "VULNERABLE": re.compile(r"\[!\] VULNERABLE:\s*(.+?)(?:\n|$)"),
            "DETECTED": re.compile(r"\[\w+\]\s*(.+?)\s*DETECTED", re.IGNORECASE),
        }
        cwe_match = re.search(r"CWE:\s*(CWE-\d+)", obs_text)
        owasp_match = re.search(r"OWASP:\s*(.+?)(?:\n|$)", obs_text)
        cvss_match = re.search(r"Suggested CVSS:\s*([\d.]+)\s*\((\w+)\)", obs_text)
        evidence_match = re.search(r"Evidence:\s*(.+?)(?:\n|$)", obs_text)
        remediation_match = re.search(r"Remediation:\s*(.+?)(?:\n|$)", obs_text)

        for severity_hint, pat in patterns.items():
            m = pat.search(obs_text)
            if m:
                title = m.group(1).strip()
                # Also check for HIGH/MEDIUM severity labels
                sev_label_match = re.search(r"\[(\w+)\].*DETECTED", obs_text)
                severity = "High"
                if cvss_match:
                    severity = cvss_match.group(2)
                elif sev_label_match:
                    severity = sev_label_match.group(1).capitalize()

                finding = {
                    "title": title,
                    "host": host,
                    "type": title,
                    "severity": severity,
                }
                if endpoint:
                    finding["endpoint"] = endpoint
                if cwe_match:
                    finding["cwe"] = cwe_match.group(1)
                if owasp_match:
                    finding["owasp"] = owasp_match.group(1).strip()
                if cvss_match:
                    finding["cvss_score"] = float(cvss_match.group(1))
                if evidence_match:
                    finding["evidence"] = evidence_match.group(1).strip()
                if remediation_match:
                    finding["remediation"] = remediation_match.group(1).strip()

                sub_obs = env.step(SecurityAuditAction(
                    action_type="submit_finding",
                    arguments=finding,
                ))
                return True, getattr(sub_obs, "done", False)
        return False, False

    results = {}
    for scenario_id in ["easy", "medium", "hard"]:
        env = SecurityAuditEnvironment()
        env.reset(scenario_id=scenario_id)
        scenario = get_scenario(scenario_id)
        done = False

        # Phase 1: Initial network scan
        obs, done = _do_step(env,
            action_type="use_tool", tool_name="network_scan",
            arguments={"target": scenario["target_network"]}
        )

        # We may need multiple passes to unlock hidden hosts
        for _pass in range(3):
            if done:
                break
            hosts_snapshot = list(env._discovered_hosts)

            for host in hosts_snapshot:
                if done:
                    break
                # Crawl endpoints
                crawl_obs, done = _do_step(env,
                    action_type="use_tool", tool_name="web_crawl",
                    arguments={"host": host}
                )
                if done:
                    break

                # Extract discovered endpoints from crawl output
                endpoints = []
                for line in crawl_obs.tool_output.split("\n"):
                    ep_match = re.search(r"(?:GET|POST|PUT|DELETE|PATCH)\s+(/\S+)", line)
                    if ep_match:
                        endpoints.append(ep_match.group(1).strip())

                # Test each endpoint with injection/xss tools
                for ep in endpoints:
                    if done:
                        break
                    for tool in ["test_injection", "test_xss"]:
                        if done:
                            break
                        obs, done = _do_step(env,
                            action_type="use_tool", tool_name=tool,
                            arguments={"host": host, "endpoint": ep}
                        )
                        if not done:
                            _, done = _parse_and_submit(env, host, ep, tool, obs.tool_output)

                    # check_secrets per endpoint
                    if not done:
                        obs, done = _do_step(env,
                            action_type="use_tool", tool_name="check_secrets",
                            arguments={"host": host, "endpoint": ep}
                        )
                        if not done:
                            _, done = _parse_and_submit(env, host, ep, "check_secrets", obs.tool_output)

                # Host-level tools (no endpoint needed)
                for tool in ["test_auth", "test_config", "test_crypto", "vulnerability_scan"]:
                    if done:
                        break
                    obs, done = _do_step(env,
                        action_type="use_tool", tool_name=tool,
                        arguments={"host": host}
                    )
                    if not done:
                        _, done = _parse_and_submit(env, host, None, tool, obs.tool_output)

            if done:
                break

            # Re-scan to discover newly unlocked hosts
            obs, done = _do_step(env,
                action_type="use_tool", tool_name="network_scan",
                arguments={"target": scenario["target_network"]}
            )

            # If no new hosts appeared, stop iterating
            if set(env._discovered_hosts) == set(hosts_snapshot):
                break

        # Generate final report (safe to call even after step limit —
        # step() returns _finish_episode with grades regardless)
        obs = env.step(SecurityAuditAction(action_type="generate_report"))
        grades = obs.metadata.get("grades", {}) if obs.metadata else {}
        results[scenario_id] = grades

    scores = {sid: g.get("final_score", 0) for sid, g in results.items()}

    # Reasoning gap: how much does performance drop when labels are removed?
    # A perfect reasoning agent: gap = 0 (same score regardless of output format)
    # A pure pattern matcher: gap = 1.0 (scores high on labeled, zero on raw)
    easy_score = scores.get("easy", 0)
    hard_score = scores.get("hard", 0)
    reasoning_gap = round(easy_score - hard_score, 4) if easy_score > 0 else 0.0

    return JSONResponse({
        "baseline_scores": scores,
        "reasoning_gap": reasoning_gap,
        "reasoning_gap_interpretation": (
            "Score difference between easy (labeled output) and hard (raw output). "
            "Gap of 1.0 = pure pattern matcher. Gap of 0.0 = genuine reasoning."
        ),
        "details": results,
    })


def main(host: str = "0.0.0.0", port: int = 8000):
    """Entry point for direct execution."""
    import uvicorn
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
