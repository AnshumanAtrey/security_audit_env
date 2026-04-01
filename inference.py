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
API_KEY = os.getenv("HF_TOKEN") or os.getenv("API_KEY") or os.getenv("OPENAI_API_KEY", "")
MODEL_NAME = os.getenv("MODEL_NAME", "meta-llama/Llama-3.3-70B-Instruct")

# --- CONFIG ---
SCENARIO_MAX_STEPS = {"easy": 25, "medium": 35, "hard": 45}
TEMPERATURE = 0.1
MAX_TOKENS = 1024
SCENARIOS = ["easy", "medium", "hard"]

# --- SYSTEM PROMPT ---
SYSTEM_PROMPT = textwrap.dedent("""\
You are a professional security auditor conducting a compliance assessment.
You interact with a security audit environment using structured JSON actions.

AVAILABLE ACTIONS:

1. List available tools:
   {"action_type": "list_tools"}

2. Use a security tool:
   {"action_type": "use_tool", "tool_name": "<tool>", "arguments": {"target": "<ip>", ...}}

   Tools: network_scan, service_fingerprint, web_crawl, vulnerability_scan,
          test_injection, test_xss, test_auth, test_config, test_crypto, check_secrets

3. Submit a finding:
   {"action_type": "submit_finding", "arguments": {
     "title": "...", "host": "10.0.x.x", "endpoint": "/path",
     "type": "SQL Injection", "severity": "Critical",
     "cvss_score": 9.8, "cwe": "CWE-89",
     "owasp": "A03:2021 - Injection",
     "evidence": "...", "remediation": "..."
   }}

4. Generate final report (ends the audit):
   {"action_type": "generate_report"}

YOUR METHODOLOGY:
1. Start by scanning the network to discover hosts
2. For each host, fingerprint services and crawl web endpoints
3. Test each endpoint/service for vulnerabilities
4. Submit a structured finding for each vulnerability found
5. When done, generate the final report

RESPOND WITH ONLY A SINGLE JSON ACTION. No explanation, no markdown, just the JSON object.
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
    parts = [f"Step {step} of {max_steps}"]

    if hasattr(observation, "message") and observation.message:
        parts.append(f"\n{observation.message}")

    if hasattr(observation, "tool_output") and observation.tool_output:
        output = observation.tool_output
        if len(output) > 3000:
            output = output[:3000] + "\n... (truncated)"
        parts.append(f"\nTool Output:\n{output}")

    if hasattr(observation, "discovered_hosts") and observation.discovered_hosts:
        parts.append(f"\nDiscovered Hosts: {', '.join(observation.discovered_hosts)}")

    if hasattr(observation, "findings_submitted"):
        parts.append(f"Findings Submitted: {observation.findings_submitted}")

    if hasattr(observation, "steps_remaining"):
        parts.append(f"Steps Remaining: {observation.steps_remaining}")

    if history:
        parts.append(f"\nRecent Actions:\n" + "\n".join(history[-5:]))

    parts.append("\nWhat is your next action? Respond with a single JSON object.")
    return "\n".join(parts)


def run_scenario(client: OpenAI, scenario_id: str, env_url: str) -> float:
    """Run the agent on one scenario and return the final score."""
    from security_audit_env import SecurityAuditEnv, SecurityAuditAction

    max_steps = SCENARIO_MAX_STEPS.get(scenario_id, 30)

    print(f"\n{'='*60}")
    print(f"Running scenario: {scenario_id} (max {max_steps} steps)")
    print(f"{'='*60}")

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

            if result.done:
                # Extract final score from metadata
                grades = getattr(observation, "metadata", {}).get("grades", {})
                final_score = grades.get("final_score", reward)
                print(f"\n  FINAL SCORE: {final_score:.4f}")
                print(f"  Detection: {grades.get('detection_rate', 0):.2f}")
                print(f"  Coverage: {grades.get('coverage', 0):.2f}")
                print(f"  Severity Accuracy: {grades.get('severity_accuracy', 0):.2f}")
                break
        else:
            # Didn't finish — force report generation
            try:
                action = SecurityAuditAction(action_type="generate_report")
                result = env.step(action)
                grades = getattr(result.observation, "metadata", {}).get("grades", {})
                final_score = grades.get("final_score", 0.0)
                print(f"\n  FINAL SCORE (forced report): {final_score:.4f}")
            except Exception:
                final_score = 0.0

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


if __name__ == "__main__":
    main()
