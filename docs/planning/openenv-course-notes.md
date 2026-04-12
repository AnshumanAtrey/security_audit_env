# OpenEnv Course — Complete Study Notes

**Source:** https://github.com/raun/openenv-course/tree/main
**Scraped:** 2026-03-24

> Building RL Environments with OpenEnv — A hands-on course for ML engineers, researchers, and hobbyists who want to use and build RL environments for LLM training.

---

## Course Overview

- **5 modules**, ~45-60 min each
- Format: Markdown README + Jupyter Notebook (Google Colab) per module
- **Prerequisites:** Basic Python, Hugging Face ecosystem familiarity, **no RL experience required**

| # | Module | What You'll Learn |
|---|--------|-------------------|
| 1 | Why OpenEnv? | The RL loop, why Gym falls short, OpenEnv architecture |
| 2 | Using Existing Environments | Environment Hub, type-safe models, policies, competition |
| 3 | Deploying Environments | Local dev, Docker, HF Spaces, `openenv push` |
| 4 | Building Your Own Environment | The 3-component pattern, scaffold → deploy |
| 5 | Training with OpenEnv + TRL | GRPO, reward functions, Wordle training |

---

## Quick Start

```bash
# Install OpenEnv core
pip install openenv-core

# Clone the OpenEnv repo to get typed environment clients
git clone https://github.com/meta-pytorch/OpenEnv.git
```

```python
import sys, os
repo = os.path.abspath('OpenEnv')
sys.path.insert(0, repo)
sys.path.insert(0, os.path.join(repo, 'src'))

# Echo environment — uses MCP tool-calling interface
from envs.echo_env import EchoEnv
with EchoEnv(base_url="https://openenv-echo-env.hf.space").sync() as env:
    env.reset()
    response = env.call_tool("echo_message", message="Hello, OpenEnv!")
    print(response)  # Hello, OpenEnv!

# OpenSpiel environments — use standard reset/step interface
from envs.openspiel_env import OpenSpielEnv
from envs.openspiel_env.models import OpenSpielAction
with OpenSpielEnv(base_url="https://openenv-openspiel-catch.hf.space").sync() as env:
    result = env.reset()
    result = env.step(OpenSpielAction(action_id=1, game_name="catch"))
    print(result.observation.legal_actions)
```

**Every standard OpenEnv environment uses the same 3-method interface:** `reset()`, `step()`, `state()`.

---

## Module 1: Why OpenEnv?

### The RL Loop
**Observe → Act → Reward → Repeat** — the basic cycle where agents interact with environments, receive feedback, and improve.

### Why Not Gymnasium?

| Problem | Gymnasium | OpenEnv |
|---------|-----------|---------|
| Type Safety | Cryptic array indexing (`obs[0][3]`) | Typed Pydantic models with autocomplete |
| Isolation | Same-process, crashes together | Containerized microservices |
| Deployment | Not reproducible across machines | Versioned Docker images |
| Scaling | Single-process only | Cloud-scalable, multi-container |
| Language | Python-only | Language-agnostic HTTP/WebSocket API |
| Debugging | Hard to inspect state | Type-safe, inspectable |

### OpenEnv Core Principle
> "RL environments should be **microservices**" — environments deserve containerized isolation, like separating databases from application servers.

### Architecture

```
Training Code  ←——WebSocket/HTTP——→  Containerized Environment Server
(any language)                        (Docker, FastAPI, versioned)
```

### The 3-Method Interface
Every environment implements:
- `reset()` — initialize/restart episode
- `step(action)` — send action, receive observation + reward
- `state()` — inspect current environment state

### The 3-Component Structure (per environment)

```
my_env/
├── models.py      ← Type contracts (Action, Observation, State)
├── client.py      ← What training code imports
└── server/
    ├── environment.py  ← Game logic (FastAPI)
    ├── app.py          ← Server wiring
    └── Dockerfile      ← Container definition
```

- **Server-side:** Abstract base classes, FastAPI
- **Client-side:** Async methods with sync wrappers for notebooks
- **MCP-based environments:** Use tool-calling patterns

---

## Module 2: Using Existing Environments

### The Environment Hub
Environments are hosted on **Hugging Face Spaces**. Each Space provides three components:

| Component | Function | Access |
|-----------|----------|--------|
| Server | Running environment endpoint | `https://<username>-<space-name>.hf.space` |
| Repository | Installable Python package | `pip install git+https://huggingface.co/spaces/<space>` |
| Registry | Docker container image | `docker pull registry.hf.space/<space>:latest` |

> You don't need to build environments to use them. Install the client, point it at a server, and go.

### Type-Safe Models
Environments define typed Pydantic models for actions, observations, and state:

```python
class OpenSpielAction(Action):
    action_id: int
    game_name: str = "catch"
    game_params: Dict[str, Any] = Field(default_factory=dict)

class OpenSpielObservation(Observation):
    info_state: List[float]
    legal_actions: List[int]
    game_phase: str = "playing"
    current_player_id: int = 0
    opponent_last_action: Optional[int] = None
```

No more guessing what `obs[0][3]` means.

### Available OpenSpiel Games

| Game | Type | Description |
|------|------|-------------|
| Catch | Single-player | Catch falling ball |
| Cliff Walking | Single-player | Navigate grid |
| 2048 | Single-player | Tile puzzle |
| Blackjack | Single-player | Card game |
| Tic-Tac-Toe | Multi-player | Classic 3x3 |
| Kuhn Poker | Multi-player | Imperfect information |

### Writing Policies — Example (Catch)

| Policy | Success Rate | Logic |
|--------|-------------|-------|
| Random | ~20% | `random.choice(obs.legal_actions)` |
| Stay | ~20% | Always returns `1` (STAY) |
| Smart Heuristic | **100%** | Finds ball & paddle position, moves toward ball |
| Epsilon-Greedy | ~85% | Mixes random exploration with smart policy |

**Key insight:** All four policies operate with the **identical** `OpenSpielObservation` type.

### Switching Games — Same Interface
```python
# Catch
with OpenSpielEnv(base_url="https://openenv-openspiel-catch.hf.space").sync() as env:
    result = env.reset()

# Tic-Tac-Toe — same client, different URL
with OpenSpielEnv(base_url="https://openenv-openspiel-tictactoe.hf.space").sync() as env:
    result = env.reset()
```

Policy code stays the same; only game strategy changes.

---

## Module 3: Deploying Environments

### Three Access Methods (from a single HF Space)
1. **Web server:** `https://<username>-<space-name>.hf.space`
2. **Pip package:** `pip install git+https://huggingface.co/spaces/<space>`
3. **Docker image:** `docker pull registry.hf.space/<space>:latest`

### Local Development
```bash
# Clone and run
git clone https://huggingface.co/spaces/<space>
cd <space>
uv sync && uv run server

# Or with uvicorn (auto-reload)
uvicorn server.app:app --reload
```

### Docker Deployment
```bash
# Pull prebuilt
docker pull registry.hf.space/<space>:latest

# Or build from source
docker build -t my-env ./server

# Run with config
docker run -p 8000:8000 \
  -e WORKERS=4 \
  -e MAX_CONCURRENT_ENVS=100 \
  my-env
```

### Deploy to HF Spaces
```bash
openenv push --repo-id user/my-env
```
Automatically provides: API docs, web UI, health check endpoints.

### Configuration via `openenv.yaml`

| Variable | Default | Description |
|----------|---------|-------------|
| `WORKERS` | 4 | Uvicorn worker processes |
| `PORT` | 8000 | Server port |
| `HOST` | 0.0.0.0 | Bind address |
| `MAX_CONCURRENT_ENVS` | 100 | Max WebSocket sessions per worker |

### HF Spaces Hardware Tiers

| Tier | Specs | Cost |
|------|-------|------|
| CPU Basic (free) | 2 vCPUs, 16GB RAM | Free (~128 concurrent sessions) |
| CPU Upgrade | 8 vCPUs, 32GB RAM | $0.03/hour |

### Deployment Workflow
`Initialize → Implement logic → Test locally → Deploy → Install client`

---

## Module 4: Building Your Own Environment

### The 3-Component Pattern

```
my_env/
├── models.py              ← Types: Action, Observation, State
├── client.py              ← HTTP/WebSocket client (what users import)
├── server/
│   ├── environment.py     ← Game logic (reset, step, state)
│   ├── app.py             ← FastAPI server
│   └── Dockerfile         ← Container definition
├── openenv.yaml           ← Manifest
└── pyproject.toml         ← Package metadata
```

> ~100 lines of meaningful code for a complete custom environment.

### Step 1: Define Types (`models.py`)

```python
from openenv.core.env_server import Action, Observation, State

class WordGameAction(Action):
    guess: str  # Player's guessed letter

class WordGameObservation(Observation):
    # Inherits: done, reward
    masked_word: str
    guessed_letters: list
    attempts_remaining: int
    message: str

class WordGameState(State):
    # Inherits: episode_id, step_count
    target_word: str
    max_attempts: int
```

### Step 2: Implement Logic (`server/environment.py`)

```python
class WordGameEnvironment:
    SUPPORTS_CONCURRENT_SESSIONS = True
    MAX_ATTEMPTS = 10
    WORDS = ["python", "neural", "tensor", "matrix", "vector",
             "kernel", "lambda", "signal", "binary", "cipher"]

    def reset(self):
        # Select random word, clear state, return initial observation
        ...

    def step(self, action):
        # Process guess, update state, check win/loss
        # reward: 1.0 for win, 0.0 otherwise
        ...

    def _mask(self):
        # Reveal guessed letters, hide others with underscores
        ...
```

### Step 3: Create Client (`client.py`)

```python
class WordGameEnv(EnvClient):
    def _step_payload(self, action: WordGameAction) -> dict:
        return {"guess": action.guess}

    def _parse_result(self, payload) -> WordGameObservation:
        # Reconstruct observation from server response
        ...

    def _parse_state(self, payload) -> WordGameState:
        # Reconstruct state from server response
        ...
```

`EnvClient` base class handles all WebSocket communication automatically.

### Step 4: Wire FastAPI (`server/app.py`)

```python
app = create_fastapi_app(WordGameEnvironment)
```

This single line auto-generates endpoints: `/ws`, `/reset`, `/step`, `/state`, `/health`, `/web`, `/docs`.

### Step 5: Dockerize (`server/Dockerfile`)

Standard Python 3.11-slim container running uvicorn on port 8000.

### The Fast Path — Scaffolding

```bash
openenv init word_game      # Generates full directory structure
# Customize: models.py, server/environment.py, client.py
uv run server               # Test locally
openenv push --repo-id user/word-game  # Deploy
```

---

## Module 5: Training with OpenEnv + TRL

### What is GRPO?
**Group Relative Policy Optimization** — RL for LLM fine-tuning:
1. Generate **multiple completions** per prompt
2. Score them via reward functions
3. Use **relative ranking** within groups to optimize the policy
4. **No separate value model** needed (unlike PPO)

### TRL + OpenEnv Integration

```
GRPOTrainer
  → calls rollout_func with prompts
    → generates completions via model
      → each completion becomes an environment action
        → environment returns observations + rewards
          → TRL applies rewards to optimize model
```

```python
trainer = GRPOTrainer(
    model=model_name,
    reward_funcs=[reward_correct, reward_greens, reward_yellows],
    rollout_func=rollout_func,
    train_dataset=dataset,
    args=grpo_config,
)
trainer.train()
```

### Wordle Training Example

**Environment:** TextArena Wordle on HF Spaces
- Input: `[WORD]` (5-letter words in brackets)
- Feedback: `G` (green/correct), `Y` (yellow/misplaced), `X` (gray/absent)
- 6 attempts per game
- Reward: 1.0 for correct, 0.0 otherwise

```python
from envs.textarena_env import TextArenaEnv
env = TextArenaEnv(base_url="https://burtenshaw-textarena.hf.space")
```

### Reward Functions

| Reward | What it measures | Range |
|--------|-----------------|-------|
| `reward_correct` | Game win (solved word) | 0.0–1.0 |
| `reward_greens` | Correct letter positions | 0.0–1.0 |
| `reward_yellows` | Misplaced letter detection | 0.0–1.0 |
| `reward_repetition` | Penalizes duplicate guesses | 0.0–1.0 |

**Greens and yellows provide learning gradient even without victories.** Repetition penalty discourages repeating the same guess.

### Rollout Function (Simplified)

```python
def rollout_once(trainer, env, tokenizer, prompt, system_prompt, max_turns):
    result = env.reset()
    observation = result.observation

    for turn in range(max_turns):
        if result.done:
            break
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": format_game_state(observation)},
        ]
        rollout = generate_rollout_completions(trainer, [messages])
        guess = extract_guess(rollout["text"])
        result = env.step(TextArenaAction(message=guess))
        observation = result.observation

    return {
        "prompt_ids": ..., "completion_ids": ..., "logprobs": ...,
        "correct_reward": ..., "green_reward": ...,
    }
```

### GRPO Config

```python
grpo_config = GRPOConfig(
    num_train_epochs=1,
    learning_rate=5e-6,
    gradient_accumulation_steps=64,
    per_device_train_batch_size=1,
    num_generations=2,
    max_completion_length=8,        # Wordle = short responses
    max_prompt_length=1400,
    use_vllm=True,
    vllm_mode="colocate",           # Generation + training on same GPU
    vllm_gpu_memory_utilization=0.1,
    gradient_checkpointing=True,
    report_to="trackio",
)
```

### Hardware Requirements
- **GPU:** A100 40GB (Colab Pro or equivalent)
- **Training time:** ~90 minutes
- **Peak memory:** ~37GB

### What the Model Learns
After training:
- Strong opening moves (CRANE, SLATE)
- Feedback-driven candidate narrowing
- Strategic letter position confirmation
- Still struggles with repetitive guesses (common RL challenge)

### Improvement Ideas
- More training epochs
- Stronger repetition penalties
- Larger models (Qwen3-8B+)
- **Swap Wordle for any other environment** (coding, math, your Module 4 build)

> "OpenEnv makes the environment a plug-in. The training pipeline stays the same."

---

## Scaling OpenEnv (Bonus)

### WebSocket vs HTTP
OpenEnv uses WebSocket (`/ws`) for persistent sessions:
- `step()` = lightweight frame (~0.1ms overhead) over existing connection
- HTTP would require TCP handshake (~10-50ms) per call
- One container handles many isolated sessions (each WS connection = own environment instance)

### Single Container Scaling

| Variable | Default | Description |
|----------|---------|-------------|
| `WORKERS` | 4 | Uvicorn worker processes |
| `MAX_CONCURRENT_ENVS` | 100 | Max WebSocket sessions per worker |

With 8 workers → ~2,048 concurrent sessions for simple text environments.

### Multi-Container Scaling (Envoy Load Balancer)

| Setup | Containers | Sessions/container | Total |
|-------|-----------|-------------------|-------|
| Single | 1 | 100 | 100 |
| 4× containers | 4 | 100 | 400 |
| 8× containers | 8 | 100 | 800 |

### Benchmarks

| Infrastructure | Max Concurrent (WS) | Cores | Sessions/Core |
|---------------|---------------------|-------|---------------|
| HF Spaces (free) | 128 | 2 | 64 |
| Local Uvicorn | 2,048 | 8 | 256 |
| Local Docker | 2,048 | 8 | 256 |
| SLURM multi-node | 16,384 | 96 | 171 |

### Recommendations
- **Dev / moderate (<2K):** Single Uvicorn or Docker. Best efficiency (256 sessions/core).
- **Demos / published:** HF Spaces free tier, reliable up to 128 concurrent.
- **Large-scale training (>2K):** Multi-node with Envoy. See `tutorial/03-scaling.md`.

---

## Dependencies (`requirements.txt`)

| Package | Purpose |
|---------|---------|
| `openenv-core>=0.2.2` | Core framework |
| `fastapi` | Server-side API |
| `uvicorn` | ASGI server |
| `fastmcp` | MCP tool-calling |
| `pydantic` | Type-safe models |
| `trl` | GRPO trainer (Module 5) |
| `transformers` | Model loading |
| `datasets` | Training data |
| `accelerate` | Multi-GPU training |
| `trackio` | Experiment tracking |
| `huggingface-hub` | Model/Space management |
| `vllm` *(optional)* | Fast inference (CUDA/Linux) |
| `bitsandbytes` *(optional)* | Quantization |

```bash
pip install -r requirements.txt
```

GPU (A100 40GB) only required for Module 5 (GRPO training).

---

## Key Links

- [OpenEnv GitHub](https://github.com/meta-pytorch/OpenEnv)
- [Environment Hub Collection](https://huggingface.co/collections/openenv) (HF Spaces)
- [TRL Documentation](https://huggingface.co/docs/trl)
- [Scaling Experiments](https://github.com/burtenshaw/openenv-scaling)
