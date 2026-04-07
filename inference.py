"""
Security Audit Environment — Baseline Inference Script
=======================================================
MANDATORY for hackathon submission.

Uses OpenAI Client to run an LLM agent against the security audit
environment. Reads API credentials from environment variables.

ENV VARS (required):
    API_BASE_URL  — The API endpoint for the LLM
    MODEL_NAME    — The model identifier to use
    HF_TOKEN      — Your Hugging Face / API key
"""

import json
import os
import re
import sys
import textwrap
from typing import Any, Dict, List, Optional

from openai import OpenAI


def _log(tag: str, data: dict) -> None:
    """Emit structured log line for programmatic evaluation parsing."""
    print(f"[{tag}] {json.dumps(data, default=str)}", flush=True)

# --- ENV VARS ---
API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
API_KEY = os.getenv("HF_TOKEN") or os.getenv("API_KEY") or os.getenv("OPENAI_API_KEY", "")
MODEL_NAME = os.getenv("MODEL_NAME", "meta-llama/Llama-3.3-70B-Instruct")

# --- CONFIG ---
SCENARIO_MAX_STEPS = {"easy": 25, "medium": 35, "hard": 45}
TEMPERATURE = 0.1
MAX_TOKENS = 1024
SCENARIOS = ["easy", "medium", "hard"]

# --- SYSTEM PROMPT ---
SYSTEM_PROMPT = textwrap.dedent("""\
You are a professional security auditor. You interact with the environment using JSON actions.

ACTIONS (respond with exactly ONE JSON object, no other text):

1. {"action_type": "use_tool", "tool_name": "TOOL", "arguments": {...}}
   Tools: network_scan (target: CIDR), web_crawl (host: IP), test_injection (host, endpoint),
   test_xss (host, endpoint), test_auth (host), test_config (host), test_crypto (host),
   check_secrets (host, endpoint), vulnerability_scan (host), service_fingerprint (host)

2. {"action_type": "submit_finding", "arguments": {"title": "...", "host": "IP",
   "type": "Vuln Type", "severity": "Critical|High|Medium|Low", "cvss_score": 9.8,
   "cwe": "CWE-XXX", "owasp": "AXX:2021 - ...", "endpoint": "/path",
   "evidence": "...", "remediation": "..."}}

3. {"action_type": "generate_report"}  (call this when done to get your score)

STRICT WORKFLOW — follow this order, do NOT repeat steps:
Phase 1: network_scan the target CIDR (do this ONCE, never again)
Phase 2: web_crawl each discovered host (once per host)
Phase 3: For each endpoint found, run test_injection, test_xss, check_secrets.
         For each host, run test_auth, test_config, test_crypto, vulnerability_scan.
Phase 4: For EVERY anomaly or issue in tool output, submit_finding with your assessment.
         You MUST infer the vulnerability type, CWE, CVSS, and severity from the evidence.
Phase 5: generate_report

CRITICAL RULES:
- NEVER run network_scan or service_fingerprint more than once.
- After web_crawl, immediately start testing endpoints — do NOT re-scan.
- When tool output shows anomalies (unusual HTTP responses, errors, data leaks), ALWAYS submit a finding.
- You are scored on findings submitted, not on tools run. Running tools without submitting findings = 0 score.
""").strip()


def parse_action(response_text: str) -> Optional[Dict[str, Any]]:
    """Extract a JSON action from the LLM's response."""
    if not response_text:
        return None

    # Try to find JSON in the response
    text = response_text.strip()

    # Remove markdown code blocks if present
    text = re.sub(r"```json\s*", "", text)
    text = re.sub(r"```\s*$", "", text)
    text = text.strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try to find JSON object in the text
    match = re.search(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass

    return None


def build_prompt(step: int, observation: Any, history: List[str], max_steps: int = 30) -> str:
    """Build user prompt from current observation and history."""
    parts = [f"[Step {step}/{max_steps}]"]

    if hasattr(observation, "tool_output") and observation.tool_output:
        output = observation.tool_output
        if len(output) > 2000:
            output = output[:2000] + "\n... (truncated)"
        parts.append(f"\nTool Output:\n{output}")

    if hasattr(observation, "message") and observation.message:
        parts.append(f"\nMessage: {observation.message}")

    hosts = []
    if hasattr(observation, "discovered_hosts") and observation.discovered_hosts:
        hosts = observation.discovered_hosts
        parts.append(f"\nDiscovered Hosts: {', '.join(hosts)}")

    findings = 0
    if hasattr(observation, "findings_submitted"):
        findings = observation.findings_submitted
        parts.append(f"Findings Submitted: {findings}")

    if hasattr(observation, "steps_remaining"):
        parts.append(f"Steps Remaining: {observation.steps_remaining}")

    if history:
        parts.append(f"\nRecent Actions:\n" + "\n".join(history[-8:]))

    # Phase guidance
    has_scanned = any("network_scan" in h for h in history)
    has_crawled = any("web_crawl" in h for h in history)
    has_tested = any(t in " ".join(history) for t in ["test_injection", "test_xss", "test_auth", "test_config"])

    if not has_scanned:
        parts.append("\n>> Phase 1: Run network_scan on the target CIDR now.")
    elif not has_crawled and hosts:
        parts.append(f"\n>> Phase 2: Run web_crawl on each host: {', '.join(hosts)}")
    elif has_crawled and not has_tested:
        parts.append("\n>> Phase 3: Test endpoints with test_injection, test_xss, test_auth, test_config, test_crypto, check_secrets, vulnerability_scan.")
    elif has_tested and findings == 0:
        parts.append("\n>> Phase 4: You MUST submit_finding for any anomalies detected. Review tool output and submit findings NOW.")
    elif step >= max_steps - 2:
        parts.append("\n>> Phase 5: Time is almost up. Run generate_report NOW.")

    parts.append("\nRespond with a single JSON action.")
    return "\n".join(parts)


def run_scenario(client: OpenAI, scenario_id: str, env_url: str) -> float:
    """Run the agent on one scenario and return the final score."""
    from security_audit_env import SecurityAuditEnv, SecurityAuditAction

    max_steps = SCENARIO_MAX_STEPS.get(scenario_id, 30)

    print(f"\n{'='*60}")
    print(f"Running scenario: {scenario_id} (max {max_steps} steps)")
    print(f"{'='*60}")
    _log("START", {"scenario": scenario_id, "max_steps": max_steps, "model": MODEL_NAME})

    with SecurityAuditEnv(base_url=env_url).sync() as env:
        result = env.reset(scenario_id=scenario_id)
        observation = result.observation
        history: List[str] = []
        final_score = 0.0

        for step in range(1, max_steps + 1):
            if result.done:
                print(f"  Episode complete at step {step - 1}.")
                break

            prompt = build_prompt(step, observation, history, max_steps=max_steps)
            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ]

            try:
                completion = client.chat.completions.create(
                    model=MODEL_NAME,
                    messages=messages,
                    temperature=TEMPERATURE,
                    max_tokens=MAX_TOKENS,
                    stream=False,
                )
                response_text = completion.choices[0].message.content or ""
            except Exception as exc:
                print(f"  Step {step}: LLM error — {exc}")
                response_text = '{"action_type": "list_tools"}'

            action_dict = parse_action(response_text)
            if not action_dict:
                print(f"  Step {step}: Could not parse action, using list_tools fallback")
                action_dict = {"action_type": "list_tools"}

            action_type = action_dict.get("action_type", "list_tools")
            tool_name = action_dict.get("tool_name")
            arguments = action_dict.get("arguments", {})

            print(f"  Step {step}: {action_type}" + (f" → {tool_name}" if tool_name else ""))

            try:
                action = SecurityAuditAction(
                    action_type=action_type,
                    tool_name=tool_name,
                    arguments=arguments,
                )
                result = env.step(action)
                observation = result.observation
            except Exception as exc:
                print(f"  Step {step}: Env error — {exc}")
                break

            reward = result.reward or 0.0
            history.append(f"Step {step}: {action_type}({tool_name or ''}) → reward {reward:+.2f}")
            print(f"    Reward: {reward:+.2f} | Done: {result.done}")
            _log("STEP", {
                "step": step, "action": action_type, "tool": tool_name,
                "reward": round(reward, 4), "done": result.done,
                "hosts": len(getattr(observation, "discovered_hosts", []) or []),
                "findings": getattr(observation, "findings_submitted", 0),
            })

            if result.done:
                grades = getattr(observation, "metadata", {}).get("grades", {})
                final_score = grades.get("final_score", reward)
                print(f"\n  FINAL SCORE: {final_score:.4f}")
                print(f"  Detection: {grades.get('detection_rate', 0):.2f}")
                print(f"  Coverage: {grades.get('coverage', 0):.2f}")
                print(f"  Severity Accuracy: {grades.get('severity_accuracy', 0):.2f}")
                _log("END", {"scenario": scenario_id, "score": final_score, "steps": step, "grades": grades})
                break
        else:
            try:
                action = SecurityAuditAction(action_type="generate_report")
                result = env.step(action)
                grades = getattr(result.observation, "metadata", {}).get("grades", {})
                final_score = grades.get("final_score", 0.0)
                print(f"\n  FINAL SCORE (forced report): {final_score:.4f}")
                _log("END", {"scenario": scenario_id, "score": final_score, "steps": max_steps, "grades": grades})
            except Exception:
                final_score = 0.0
                _log("END", {"scenario": scenario_id, "score": 0.0, "error": True})

    return final_score


def main():
    """Run baseline inference across all scenarios."""
    print("Security Audit Environment — Baseline Inference")
    print(f"API: {API_BASE_URL}")
    print(f"Model: {MODEL_NAME}")

    llm_client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)

    # Default to local server if no env URL provided
    env_url = os.getenv("ENV_URL", "http://localhost:8000")

    scores = {}
    for scenario_id in SCENARIOS:
        try:
            score = run_scenario(llm_client, scenario_id, env_url)
            scores[scenario_id] = score
        except Exception as exc:
            print(f"  ERROR on {scenario_id}: {exc}")
            scores[scenario_id] = 0.0

    print(f"\n{'='*60}")
    print("BASELINE SCORES")
    print(f"{'='*60}")
    for sid, score in scores.items():
        print(f"  {sid:10s}: {score:.4f}")
    avg = sum(scores.values()) / len(scores) if scores else 0.0
    print(f"  {'average':10s}: {avg:.4f}")
    print(f"{'='*60}")
    _log("SUMMARY", {"scores": scores, "average": round(avg, 4)})


if __name__ == "__main__":
    main()
