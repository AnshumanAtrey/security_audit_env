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

    Runs a simple deterministic audit agent (no LLM) across all scenarios
    and returns the grader scores.
    """
    try:
        from server.scenarios import get_scenario
        from server.grader import grade_episode
    except ImportError:
        from .scenarios import get_scenario
        from .grader import grade_episode

    results = {}
    for scenario_id in ["easy", "medium", "hard"]:
        env = SecurityAuditEnvironment()
        env.reset(scenario_id=scenario_id)

        # Deterministic baseline: scan → test all endpoints → submit basic findings
        env.step(SecurityAuditAction(
            action_type="use_tool", tool_name="network_scan",
            arguments={"target": get_scenario(scenario_id)["target_network"]}
        ))

        for host in list(env._discovered_hosts):
            env.step(SecurityAuditAction(
                action_type="use_tool", tool_name="web_crawl",
                arguments={"host": host}
            ))
            for tool in ["test_injection", "test_auth", "test_config", "test_crypto", "check_secrets"]:
                env.step(SecurityAuditAction(
                    action_type="use_tool", tool_name=tool,
                    arguments={"host": host}
                ))

        obs = env.step(SecurityAuditAction(action_type="generate_report"))
        grades = obs.metadata.get("grades", {})
        results[scenario_id] = grades

    return JSONResponse({
        "baseline_scores": {sid: g.get("final_score", 0) for sid, g in results.items()},
        "details": results,
    })


def main(host: str = "0.0.0.0", port: int = 8000):
    """Entry point for direct execution."""
    import uvicorn
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
