"""
REFERENCE ONLY — This is the official sample inference script from the hackathon dashboard.
It's for BrowserGym, NOT our Security Audit env. But the PATTERN is what we must follow.

KEY TAKEAWAYS FOR OUR inference.py:
1. API_BASE_URL defaults to "https://router.huggingface.co/v1" (HuggingFace Inference)
2. API_KEY = HF_TOKEN or API_KEY (support both)
3. MODEL_NAME from env var
4. OpenAI client with base_url=API_BASE_URL
5. Loop: reset → step → step → ... until done or max_steps
6. Build user prompt from observation + history
7. Parse LLM response into action
8. Fallback action if LLM fails
9. Track history of actions/results
10. Print reward/done/error at each step
"""

import os
import re
import textwrap
from typing import List, Optional, Dict

from openai import OpenAI

# --- ENV VARS (MANDATORY) ---
API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
API_KEY = os.getenv("HF_TOKEN") or os.getenv("API_KEY")
MODEL_NAME = os.getenv("MODEL_NAME")

# --- CONFIG ---
MAX_STEPS = 8
TEMPERATURE = 0.2
MAX_TOKENS = 200
FALLBACK_ACTION = "noop()"

# --- SYSTEM PROMPT (customize for your env) ---
SYSTEM_PROMPT = textwrap.dedent("""
    You control a web browser through BrowserGym.
    Reply with exactly one action string.
    ...
""").strip()


def build_user_prompt(step, observation, history):
    """Format the observation into a prompt for the LLM."""
    # ... customize for your env
    pass


def parse_model_action(response_text):
    """Extract action from LLM's text response."""
    # ... customize for your env
    pass


def main():
    client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)

    # Connect to your environment
    env = ...  # YourEnv(base_url="https://your-space.hf.space").sync()

    history = []

    try:
        result = env.reset()
        observation = result.observation

        for step in range(1, MAX_STEPS + 1):
            if result.done:
                break

            # Build prompt from observation
            user_prompt = build_user_prompt(step, observation, history)
            messages = [
                {"role": "system", "content": [{"type": "text", "text": SYSTEM_PROMPT}]},
                {"role": "user", "content": [{"type": "text", "text": user_prompt}]},
            ]

            # Call LLM
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
                print(f"Model request failed ({exc}). Using fallback.")
                response_text = FALLBACK_ACTION

            # Parse action from LLM output
            action_str = parse_model_action(response_text)
            print(f"Step {step}: model suggested -> {action_str}")

            # Step the environment
            result = env.step(action_str)  # adapt to your Action type
            observation = result.observation

            # Track
            reward = result.reward or 0.0
            history.append(f"Step {step}: {action_str} -> reward {reward:+.2f}")
            print(f"  Reward: {reward:+.2f} | Done: {result.done}")

            if result.done:
                print("Episode complete.")
                break
        else:
            print(f"Reached max steps ({MAX_STEPS}).")

    finally:
        env.close()


if __name__ == "__main__":
    main()
