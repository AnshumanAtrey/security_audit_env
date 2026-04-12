# Tech Stack — What's Mandatory vs Optional

---

## What Each Sponsor Actually Provides

| Sponsor | Role | What They Give You |
|---------|------|--------------------|
| **Meta** | Primary Sponsor | The **OpenEnv framework** (openenv-core). The whole concept. Judging. Interview access. |
| **HuggingFace** | Ecosystem Partner | **HF Spaces** (deployment platform). Environment Hub. `HF_TOKEN` for auth. Model hosting. |
| **PyTorch** | Framework Partner | The ML training framework. Used for **Round 2 / RL training** — NOT for building the environment in Round 1. |
| **Scaler SST** | Powered By | Event organizer. Round 2 venue in Bangalore. |

---

## MANDATORY Tech (You MUST use these)

### 1. openenv-core (>= 0.2.2)

**What it is:** The core framework by Meta. This IS the hackathon.

**What it provides:**
```
Base classes:
  - Action (Pydantic BaseModel)        ← your action type extends this
  - Observation (Pydantic BaseModel)    ← your observation type extends this
  - State (Pydantic BaseModel)          ← your state type extends this
  - Environment (ABC)                   ← your env logic extends this
  - EnvClient (ABC)                     ← your client extends this

Server factory:
  - create_app() / create_fastapi_app() ← generates all endpoints automatically

CLI tools:
  - openenv validate                    ← validates your submission
  - openenv push                        ← deploys to HF Spaces

Rubric system:
  - Rubric, Sequential, WeightedSum     ← reward computation
  - TrajectoryRubric                    ← episode-level rewards

WebSocket server:
  - Handles /ws, /reset, /step, /state, /health, /schema, /docs
```

**Install:** `pip install openenv-core`

### 2. FastAPI (>= 0.104.0)

**What it is:** Web framework. openenv-core uses it internally.

**Why mandatory:** `create_app()` returns a FastAPI application. Your server IS a FastAPI app.

**You don't write FastAPI routes manually** — `create_app()` does it for you. But if you need custom endpoints (`/tasks`, `/grader`, `/baseline`), you add them to the FastAPI app.

### 3. Uvicorn (>= 0.24.0)

**What it is:** ASGI server that runs FastAPI.

**Why mandatory:** Your Dockerfile's CMD is `uvicorn server.app:app --host 0.0.0.0 --port 8000`

### 4. Pydantic (>= 2.0.0)

**What it is:** Data validation. Like Zod for Python.

**Why mandatory:** Action, Observation, State are all Pydantic BaseModels. Your typed models MUST extend them.

### 5. Docker

**What it is:** Containerization. You already know this.

**Why mandatory:** Problem statement says "Must include a working Dockerfile. docker build + docker run must work."

### 6. HuggingFace Spaces

**What it is:** Like Vercel but for ML apps. Hosts your container.

**Why mandatory:** "Deploys to a Hugging Face Space tagged with openenv." Your running environment lives here.

**Deploy:** Either `openenv push --repo-id yourname/your-env` or manually create a Space.

### 7. OpenAI Python Client

**What it is:** The `openai` pip package.

**Why mandatory:** Problem statement says "Participants must use OpenAI Client for all LLM calls."

**Important:** You're NOT calling OpenAI's API. You're using the OpenAI CLIENT LIBRARY to call whatever model is at `API_BASE_URL`. It's an OpenAI-compatible endpoint (could be HuggingFace, could be anything).

```python
from openai import OpenAI

client = OpenAI(
    base_url=os.environ["API_BASE_URL"],  # NOT openai.com — it's the judges' endpoint
    api_key=os.environ["HF_TOKEN"],        # NOT OPENAI_API_KEY
)

completion = client.chat.completions.create(
    model=os.environ["MODEL_NAME"],  # e.g., "nvidia/Nemotron-3-Super"
    messages=[...],
)
```

### 8. Python >= 3.10

**Why:** openenv-core requires it. Use 3.11 (same as reference projects).

---

## NOT Mandatory (Despite Being Sponsors)

### PyTorch — NOT NEEDED for Round 1

PyTorch is the "Framework Partner" because it's used for **RL training** (Round 2, Module 5 of course, GRPO with TRL).

But Round 1 is about **building the environment** — the thing the AI plays in. The environment is a FastAPI server. No neural networks, no training, no GPU.

**None of the 5 SF winning environments import PyTorch:**
- Calendar env: No PyTorch
- REPL env: No PyTorch
- TB2 env: No PyTorch
- Reasoning Gym: No PyTorch
- CARLA env: Uses it optionally, not required

**DO NOT add PyTorch to your requirements.** It will blow your 8GB RAM limit.

### Transformers / TRL — NOT NEEDED

Same reason. These are for training. Your env doesn't train anything.

### LangChain — NOT NEEDED

Calendar env uses it for multi-provider LLM support in their client. But the problem statement says use OpenAI client. Don't add LangChain complexity.

---

## RECOMMENDED Tech (Used by Winners, Good to Use)

### SQLAlchemy + SQLite — STRONGLY RECOMMENDED

**Used by:** Calendar env (the likely top winner)

**Why:** Gives you real database state. Graders can run SQL queries to verify agent's work. Way more professional than Python dicts.

For our security audit env:
```python
# Tables:
# hosts, ports, services, vulnerabilities (ground truth — static)
# agent_discoveries, agent_findings (agent's work — grows during episode)
# Grader: SELECT COUNT(*) FROM vulnerabilities v
#          JOIN agent_findings f ON v.id = f.finding_vuln_id
```

### websockets — RECOMMENDED

openenv-core uses it internally. May need to add explicitly.

### httpx — OPTIONAL

Better HTTP client than requests. Used by Calendar env.

### pytest — OPTIONAL

Useful for testing your env locally before submission. TB2 uses it for grading.

---

## Your Exact requirements.txt

```
# Core (MANDATORY)
openenv-core>=0.2.2
fastapi>=0.110.0
uvicorn[standard]>=0.27.0
pydantic>=2.5.0
websockets

# Database (RECOMMENDED — like Calendar env winner)
sqlalchemy>=2.0.0

# Inference script (MANDATORY)
openai>=1.0.0

# Utilities
python-dotenv>=1.0.0
requests>=2.31.0
```

**Total size: < 50MB installed. Runs easily on vcpu=2, 8GB.**

Compare to what you'd have with PyTorch: 2GB+ installed, would crash on 8GB.

---

## Your Exact openenv.yaml

```yaml
spec_version: 1
name: security_audit_env
type: space
runtime: fastapi
app: server.app:app
port: 8000
```

That's it. 6 lines. Same format as every SF winner.

---

## Your Exact Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl gcc && rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code
COPY . .

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000

CMD ["uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "8000"]
```

---

## Your Exact inference.py Header

```python
#!/usr/bin/env python3
"""Security Audit Environment — Baseline Inference Script"""

import os
from openai import OpenAI

# MANDATORY env vars — exact names from dashboard
API_BASE_URL = os.environ["API_BASE_URL"]
MODEL_NAME = os.environ["MODEL_NAME"]
HF_TOKEN = os.environ["HF_TOKEN"]

# OpenAI client pointing at the judges' endpoint (NOT openai.com)
client = OpenAI(base_url=API_BASE_URL, api_key=HF_TOKEN)

# Your environment client
from security_audit_env import SecurityAuditEnv, SecurityAuditAction

SYSTEM_PROMPT = """You are a professional security auditor..."""

MAX_STEPS = 30  # Must finish in < 20 minutes
TEMPERATURE = 0.0  # Reproducible scores
MAX_TOKENS = 1024
```

---

## Architecture Diagram — What Connects to What

```
┌─────────────────────────────────────────────────┐
│              HuggingFace Spaces                  │
│  ┌───────────────────────────────────────────┐  │
│  │     Your Docker Container                  │  │
│  │                                            │  │
│  │  ┌──────────────┐    ┌─────────────────┐  │  │
│  │  │ FastAPI App   │    │  SQLite DB      │  │  │
│  │  │ (openenv-core)│◄──►│  (network state)│  │  │
│  │  │               │    └─────────────────┘  │  │
│  │  │ Endpoints:    │                         │  │
│  │  │  /reset       │    ┌─────────────────┐  │  │
│  │  │  /step        │    │ SecurityAudit   │  │  │
│  │  │  /state       │◄──►│ Environment     │  │  │
│  │  │  /health      │    │ (your logic)    │  │  │
│  │  │  /ws          │    └─────────────────┘  │  │
│  │  │  /tasks       │                         │  │
│  │  │  /grader      │                         │  │
│  │  │  /baseline    │                         │  │
│  │  └──────────────┘                          │  │
│  └───────────────────────────────────────────┘  │
│                     ▲                            │
└─────────────────────│────────────────────────────┘
                      │ WebSocket / HTTP
                      │
┌─────────────────────│────────────────────────────┐
│  inference.py       │                            │
│  ┌──────────────────▼───────────────┐            │
│  │  OpenAI Client                    │            │
│  │  (calls your env via WebSocket)   │            │
│  └──────────────────┬───────────────┘            │
│                     │                            │
│  ┌──────────────────▼───────────────┐            │
│  │  LLM (Nemotron / GPT / etc)      │            │
│  │  at API_BASE_URL                  │            │
│  │  (judges provide this)            │            │
│  └──────────────────────────────────┘            │
└──────────────────────────────────────────────────┘
```

---

## Quick Start: Scaffold with `openenv init`

```bash
pip install openenv-core
openenv init security_audit_env
```

This generates the entire project structure automatically:
```
security_audit_env/
├── __init__.py          # Package exports
├── models.py            # Action, Observation, State (edit these)
├── client.py            # EnvClient (edit these)
├── openenv.yaml         # Manifest (already configured)
├── pyproject.toml       # Dependencies (add yours)
├── inference.py         # Baseline script (WRITE THIS — mandatory for hackathon)
├── README.md            # Documentation
└── server/
    ├── __init__.py
    ├── environment.py   # Your env logic — reset/step/state (MAIN FILE)
    ├── app.py           # FastAPI app (already wired)
    ├── requirements.txt # Server deps
    └── Dockerfile       # Container spec
```

Then customize: `models.py` → `server/environment.py` → `client.py` → `inference.py`

Deploy: `openenv push --repo-id yourname/security-audit-env`

Validate: `openenv validate .` (local) or `openenv validate --url https://your-space.hf.space` (remote)

---

## Summary: What You're Actually Building

```
You build:
  1. A FastAPI server (using openenv-core) ← the "environment"
  2. A SQLite database ← the simulated network state
  3. A Dockerfile ← containerization
  4. An inference.py ← baseline agent using OpenAI client
  5. Deploy to HF Spaces ← hosting

You DO NOT build:
  ✗ Any ML model
  ✗ Any PyTorch code
  ✗ Any training pipeline
  ✗ Any neural network
  ✗ Any GPU code

Your tech stack is essentially:
  Python + FastAPI + SQLite + Docker + HuggingFace Spaces
  (Plus openenv-core for the framework glue)

This is a full-stack web project. You already know 90% of this.
```
