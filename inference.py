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

# --- ENV VARS ---
API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "meta-llama/Llama-3.3-70B-Instruct")
HF_TOKEN = os.getenv("HF_TOKEN")

if HF_TOKEN is None:
    raise ValueError("HF_TOKEN environment variable is required")

# --- CONFIG ---
SCENARIO_MAX_STEPS = {"easy": 25, "medium": 35, "hard": 45}
TEMPERATURE = 0.1
MAX_TOKENS = 1024
SCENARIOS = ["easy", "medium", "hard"]
ENV_NAME = "security_audit_env"

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

    text = response_text.strip()
    text = re.sub(r"```json\s*", "", text)
    text = re.sub(r"```\s*$", "", text)
    text = text.strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

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

    # --- MANDATORY STDOUT: [START] ---
    print(f"[START] task={scenario_id} env={ENV_NAME} model={MODEL_NAME}", flush=True)

    all_rewards: List[float] = []
    final_score = 0.0
    total_steps = 0
    success = False
    last_error = None

    try:
        with SecurityAuditEnv(base_url=env_url).sync() as env:
            result = env.reset(scenario_id=scenario_id)
            observation = result.observation
            history: List[str] = []

            for step in range(1, max_steps + 1):
                if result.done:
                    break

                prompt = build_prompt(step, observation, history, max_steps=max_steps)
                messages = [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ]

                last_error = None
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
                    last_error = str(exc)
                    response_text = '{"action_type": "list_tools"}'

                action_dict = parse_action(response_text)
                if not action_dict:
                    last_error = "Could not parse LLM response as JSON"
                    action_dict = {"action_type": "list_tools"}

                action_type = action_dict.get("action_type", "list_tools")
                tool_name = action_dict.get("tool_name")
                arguments = action_dict.get("arguments", {})

                action_str = action_type
                if tool_name:
                    action_str += f"({tool_name})"

                try:
                    action = SecurityAuditAction(
                        action_type=action_type,
                        tool_name=tool_name,
                        arguments=arguments,
                    )
                    result = env.step(action)
                    observation = result.observation
                    last_error = None
                except Exception as exc:
                    last_error = str(exc)
                    reward = 0.0
                    all_rewards.append(reward)
                    total_steps = step
                    # --- MANDATORY STDOUT: [STEP] ---
                    error_str = last_error.replace("\n", " ") if last_error else "null"
                    print(f"[STEP]  step={step} action={action_str} reward={reward:.2f} done=false error={error_str}", flush=True)
                    break

                reward = result.reward or 0.0
                all_rewards.append(reward)
                total_steps = step

                history.append(f"Step {step}: {action_str} → reward {reward:+.2f}")

                # --- MANDATORY STDOUT: [STEP] ---
                done_str = "true" if result.done else "false"
                error_str = last_error.replace("\n", " ") if last_error else "null"
                print(f"[STEP]  step={step} action={action_str} reward={reward:.2f} done={done_str} error={error_str}", flush=True)

                if result.done:
                    grades = getattr(observation, "metadata", {}) or {}
                    grades = grades.get("grades", {})
                    final_score = grades.get("final_score", reward)
                    success = final_score > 0
                    break
            else:
                # Didn't finish — force report generation
                try:
                    action = SecurityAuditAction(action_type="generate_report")
                    result = env.step(action)
                    reward = result.reward or 0.0
                    all_rewards.append(reward)
                    total_steps += 1

                    done_str = "true" if result.done else "false"
                    print(f"[STEP]  step={total_steps} action=generate_report reward={reward:.2f} done={done_str} error=null", flush=True)

                    grades = getattr(result.observation, "metadata", {}) or {}
                    grades = grades.get("grades", {})
                    final_score = grades.get("final_score", 0.0)
                    success = final_score > 0
                except Exception as exc:
                    final_score = 0.0
                    last_error = str(exc)
    except Exception as exc:
        last_error = str(exc)
    finally:
        # --- MANDATORY STDOUT: [END] (always emitted, even on exception) ---
        rewards_str = ",".join(f"{r:.2f}" for r in all_rewards)
        success_str = "true" if success else "false"
        print(f"[END]   success={success_str} steps={total_steps} rewards={rewards_str}", flush=True)

    return final_score


def main():
    """Run baseline inference across all scenarios."""
    print("Security Audit Environment — Baseline Inference")
    print(f"API: {API_BASE_URL}")
    print(f"Model: {MODEL_NAME}")

    llm_client = OpenAI(base_url=API_BASE_URL, api_key=HF_TOKEN)
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


if __name__ == "__main__":
    main()
