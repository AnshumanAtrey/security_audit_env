# Winning Strategy — Meta OpenEnv Hackathon

Based on deep analysis of all 5 SF winning projects + OpenEnv core framework.

---

## What the SF Winners Actually Built

| Project | Complexity | Core Pattern | Grading | Reward |
|---------|-----------|-------------|---------|--------|
| **Calendar** | Massive — full Google Calendar API clone, 30+ MCP tools, SQLite DB | MCP tool-calling | SQL queries against actual DB state | Per-step (+0.5/-1.0 on tool success/fail) + final verifiers |
| **REPL** | High — sandboxed Python executor, recursive LLM architecture | Code execution + FINAL() answer | Rubric system: ExactMatch, FuzzyMatch, CodeExecution | Multi-layer: process (-0.05 for errors) + outcome (+1.0 for correct) |
| **CARLA** | High — autonomous driving simulator, 10 action types | Gym-style control actions | Scenario-specific (binary for trolley, continuous for navigation) | Exponential discounting trajectory rubric |
| **TB2** | Medium — terminal interaction with 8 action types | Terminal commands (exec/write/view) | Pytest test suite (binary pass/fail) | Binary: 1.0 if tests pass, 0.0 if not |
| **Reasoning Gym** | Low — wraps external library, ~200 lines | Single question → single answer | Library's built-in score_answer() | Direct passthrough of score (0.0-1.0) |

### Key Pattern: Calendar Env is the Gold Standard

Calendar likely scored highest because:
1. **Simulates a REAL production API** — not a toy, a full Google Calendar v3 clone
2. **MCP tool-calling** — agent discovers tools, calls them by name with arguments
3. **Real database state** — SQLite, not mock data. Agent's actions modify real records.
4. **SQL-based graders** — verification queries actual DB: "Does event X exist? Was calendar Y deleted?"
5. **Multi-tenant, concurrent** — production-quality architecture
6. **No heavy compute** — just SQLite + FastAPI. Runs on any hardware.

---

## The Exact Formula for 1st Place

### Step 1: Pass the Automated Gate (MANDATORY — fail = disqualified)

| Check | What They Run | How to Pass |
|-------|--------------|-------------|
| HF Space live | `curl https://your-space.hf.space/health` → 200 | Deploy early, test repeatedly |
| OpenEnv spec | `openenv validate --url <url>` | Use `create_app()` factory, proper `openenv.yaml` |
| Docker builds | `docker build` on your repo | Test locally, minimize dependencies |
| Baseline runs | Run `inference.py` → must produce scores | Test on vcpu=2, 8GB machine |
| 3+ tasks + graders | Enumerate tasks, run graders, verify 0.0-1.0 | Return floats, never fixed values |
| inference.py | Must use OpenAI client, `API_BASE_URL`, `MODEL_NAME`, `HF_TOKEN` | Follow exact variable names |
| Runtime | < 20 minutes | Limit steps, efficient code |
| Hardware | vcpu=2, memory=8GB | No heavy deps, no large models |

### Step 2: Score High on Agentic Evaluation

Nemotron 3 Super will play your environment. What matters:

1. **Clear action schema** — Nemotron reads your `/tasks` endpoint. If it can't understand what actions to take, it scores 0.
2. **Good system prompt in inference.py** — Guide the LLM clearly on what tools are available and what format to respond in.
3. **Graders must produce VARYING scores** — If Nemotron scores 0.0 on everything, judges see no signal. Design easy task so it scores at least 0.3-0.5.
4. **Score variance check** — Graders that always return the same score get flagged. Your tasks MUST produce different scores for different agent behaviors.

### Step 3: Win Human Review (Top Submissions Only)

Meta + HuggingFace engineers check:
1. **"Would I actually use this to train agents?"** — The #1 question
2. **"Is this a novel domain?"** — Have they seen this before in OpenEnv?
3. **"Is the code production quality?"** — Not hackathon spaghetti
4. **"Are the graders fair and robust?"** — No exploits, deterministic

---

## What Separates 1st Place from Top 10

| Aspect | Top 10 | 1st Place |
|--------|--------|-----------|
| Domain | Valid real-world task | Fills a GENUINE GAP in AI training |
| Simulation depth | Works but shallow | Faithful approximation of the real system |
| Grading | Binary pass/fail | Multi-dimensional with partial credit |
| Reward design | Sparse (end-of-episode) | Dense process + outcome signals |
| Code quality | Works | Production-ready, clean architecture |
| Documentation | Basic README | Research-paper-quality README with baseline scores |
| Difficulty curve | 3 tasks exist | Easy (solvable by LLM), Medium (challenging), Hard (frontier-difficulty) |
| Tool design | Free-text actions | MCP tool-calling with typed arguments |

---

## What Changes for Our VAPT Environment

### Change 1: Use MCP Tool-Calling Pattern

The Calendar env (top winner) uses MCP. Our pen testing tools map perfectly:

```python
# Instead of: VAPTAction(tool="nmap", target="10.0.1.10", parameters={...})
# Use MCP pattern:

class VAPTAction(Action):
    action_type: Literal["ListToolsAction", "ToolCallAction", "SubmitFinding"]
    tool_name: Optional[str] = None
    arguments: Optional[Dict[str, Any]] = None

# Agent flow:
# 1. step(ListToolsAction) → sees all available tools
# 2. step(ToolCallAction, tool_name="nmap", arguments={"target": "10.0.1.0/24"})
# 3. step(ToolCallAction, tool_name="nikto", arguments={"target": "10.0.1.10"})
# 4. step(SubmitFinding, arguments={"vuln_id": "...", "severity": "Critical", ...})
```

### Change 2: Structured State with Deterministic Verification

Like Calendar's SQL verifiers, our grader checks actual state:

```python
# Ground truth (hidden from agent):
ground_truth_vulns = {
    "SQLI-001": {"cvss": 9.8, "severity": "Critical", "host": "10.0.1.10"},
    "EXPOSED-DB-001": {"cvss": 9.1, "severity": "Critical", "host": "10.0.1.20"},
    ...
}

# Agent's submitted findings (via SubmitFinding actions):
agent_findings = state.submitted_findings

# Grader compares:
detection_score = len(found & actual) / len(actual)
```

### Change 3: Multi-Layer Reward (Rubric System)

Follow REPL env's rubric pattern:

```python
class VAPTRubric(Rubric):
    def forward(self, action, observation):
        # Process rewards (every step):
        if new_host_discovered:     return +0.05
        if new_port_discovered:     return +0.02
        if new_vuln_found:          return +0.10
        if access_escalated:        return +0.15
        if repeated_useless_action: return -0.02
        if invalid_tool_usage:      return -0.05

        # Outcome reward (final step):
        if observation.done:
            return grade_episode(ground_truth, agent_findings)
```

### Change 4: Proper inference.py

Must follow the EXACT pattern from the dashboard:

```python
import os
from openai import OpenAI

API_BASE_URL = os.environ["API_BASE_URL"]
MODEL_NAME = os.environ["MODEL_NAME"]
HF_TOKEN = os.environ["HF_TOKEN"]

client = OpenAI(base_url=API_BASE_URL, api_key=HF_TOKEN)
```

### Change 5: Lightweight — Must Run on vcpu=2, 8GB RAM

Our VAPT env is already lightweight (Python dicts + state tracking). But ensure:
- No large data files
- No heavy dependencies (no torch, no numpy arrays)
- No subprocess calls
- Inference script finishes in < 20 min (limit to ~30-50 steps)

---

## Critical Mistakes to Avoid

| Mistake | Why It Kills You | How to Avoid |
|---------|-----------------|-------------|
| Graders return fixed scores | DQ'd — "graders that always return the same score" | Test with random agents, verify varying scores |
| inference.py uses wrong env vars | DQ'd — must use `API_BASE_URL`, `MODEL_NAME`, `HF_TOKEN` | Copy exact names from dashboard |
| Docker doesn't build | DQ'd | Test `docker build && docker run` locally |
| HF Space doesn't respond to reset() | DQ'd | Test endpoint before submitting |
| Environment too heavy for 8GB | Fails automated eval | Profile memory usage |
| All tasks too hard | Nemotron scores 0 on everything, no signal | Make Task 1 easy enough for any LLM |
| No partial reward signal | Low "environment design" score | Reward every useful discovery |
| "Game-like" domain | Low "real-world utility" score | Frame as professional VAPT audit, not CTF |
| Spaghetti code | Low "code quality" score | Clean separation: models/client/server/tools |

---

## Final Build Plan

### Priority 1: AUTOMATED GATE (Days 1-3) — Must pass or nothing else matters

| Task | Time | Detail |
|------|------|--------|
| `openenv.yaml` | 30 min | 6-line file, exact format from reference projects |
| `models.py` | 2 hrs | VAPTAction, VAPTObservation, VAPTState — typed Pydantic |
| `server/app.py` | 30 min | `app = create_app(VAPTEnvironment, VAPTAction, VAPTObservation)` |
| `server/vapt_environment.py` | 1 day | reset/step/state with ONE working scenario |
| `client.py` | 2 hrs | EnvClient subclass with 3 methods |
| `Dockerfile` | 1 hr | Python 3.11-slim + requirements + uvicorn |
| `inference.py` | 3 hrs | OpenAI client, reads env vars, runs agent loop |
| Deploy to HF Spaces | 2 hrs | `openenv push` or manual Space creation |
| Run `openenv validate` | 1 hr | Fix any failures |

### Priority 2: SCORING (Days 3-5) — Maximize points

| Task | Time | Detail |
|------|------|--------|
| Scenario 1 (Easy) | 4 hrs | 2 hosts, 3 vulns, basic tools discover everything |
| Scenario 2 (Medium) | 4 hrs | 4 hosts, 6 vulns, requires pivoting |
| Scenario 3 (Hard) | 4 hrs | 8 hosts, 12 vulns, red herrings, time limit |
| Grader implementation | 4 hrs | Detection + coverage + severity + false positives |
| Reward function | 2 hrs | Process rewards + outcome rewards |
| Tool simulations | 6 hrs | nmap, nikto, sqlmap, hydra, searchsploit, exploit_cve |
| `/tasks`, `/grader`, `/baseline` endpoints | 2 hrs | Required custom endpoints |
| submit_finding + generate_report actions | 3 hrs | VAPT-specific differentiator |

### Priority 3: POLISH (Days 5-6) — Win human review

| Task | Time | Detail |
|------|------|--------|
| README.md | 2 hrs | Motivation, action/obs spaces, task descriptions, baseline scores |
| Test with actual LLM | 2 hrs | Run inference.py against GPT-4 / open model |
| Tune difficulty | 2 hrs | Make sure Easy scores 0.4+, Hard scores < 0.3 |
| Code cleanup | 2 hrs | Remove dead code, add type hints, proper imports |
| Final `openenv validate` | 30 min | One last check |
| Submit | 30 min | Via dashboard |

### Deadline: April 8th, 2026

---

## The Pitch (for Human Reviewers)

> **VAPTEnv: An AI Security Audit Training Environment**
>
> Simulates real-world Vulnerability Assessment & Penetration Testing (VAPT) engagements — the kind that costs $10k-$50k and takes 2-5 analysts 2 weeks.
>
> The agent must: discover network assets, identify vulnerabilities, assess severity (CVSS scoring), prove exploitation, and produce a structured audit report — exactly what a professional pen tester does.
>
> This fills a genuine gap: there is no existing OpenEnv environment for security assessment. VAPT is a $120B+ industry where AI augmentation would have immediate, measurable impact.
>
> Three tasks model realistic engagement scopes:
> - Easy: Startup web app security check (2 hosts, 3 known CVEs)
> - Medium: E-commerce PCI-DSS compliance audit (4 hosts, attack chaining required)
> - Hard: Enterprise SOC2 pre-audit (8 hosts, red herrings, time-limited engagement)
>
> Grading is multi-dimensional: detection rate, attack surface coverage, severity accuracy, false positive rate — weighted into a single 0.0-1.0 score.

---

## One-Line Summary

**Build a professional VAPT simulation using MCP tool-calling, with deterministic multi-dimensional graders, dense reward signals, and lightweight architecture that deploys on 2 vCPUs — following the exact Calendar Env pattern that won SF.**
