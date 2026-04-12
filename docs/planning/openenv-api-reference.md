# OpenEnv API Reference (v0.2.3) — Quick Reference for Building

---

## Base Classes (from `openenv.core.env_server`)

### Action
```python
from openenv.core.env_server import Action

class Action(BaseModel):
    model_config = ConfigDict(extra="forbid")
    metadata: Dict[str, Any] = Field(default_factory=dict)
```

### Observation
```python
from openenv.core.env_server import Observation

class Observation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    done: bool = Field(default=False)
    reward: bool | int | float | None = Field(default=None)
    metadata: Dict[str, Any] = Field(default_factory=dict)
```

### State
```python
from openenv.core.env_server import State

class State(BaseModel):
    model_config = ConfigDict(extra="allow")  # NOTE: allows extra fields
    episode_id: Optional[str] = Field(default=None)
    step_count: int = Field(default=0, ge=0)
```

---

## Environment Base Class

```python
from openenv.core.env_server.interfaces import Environment

class Environment(ABC, Generic[ActT, ObsT, StateT]):
    SUPPORTS_CONCURRENT_SESSIONS: bool = False
    rubric: Optional[Rubric] = None

    def __init__(self, transform=None, rubric=None): ...

    # --- YOU MUST IMPLEMENT THESE ---
    @abstractmethod
    def reset(self, seed=None, episode_id=None, **kwargs) -> ObsT: ...

    @abstractmethod
    def step(self, action: ActT, timeout_s=None, **kwargs) -> ObsT: ...

    @property
    @abstractmethod
    def state(self) -> StateT: ...

    # --- OPTIONAL OVERRIDES ---
    def get_metadata(self) -> EnvironmentMetadata: ...
    def close(self): ...

    # --- BUILT-IN HELPERS ---
    def _apply_transform(self, observation): ...
    def _apply_rubric(self, action, observation) -> float: ...
    def _reset_rubric(self): ...
```

---

## EnvClient Base Class

```python
from openenv.core.env_client import EnvClient

class EnvClient(ABC, Generic[ActT, ObsT, StateT]):
    def __init__(self, base_url, connect_timeout_s=10.0,
                 message_timeout_s=60.0, max_message_size_mb=100.0,
                 provider=None, mode=None): ...

    # --- YOU MUST IMPLEMENT THESE ---
    @abstractmethod
    def _step_payload(self, action: ActT) -> Dict[str, Any]: ...

    @abstractmethod
    def _parse_result(self, payload: Dict[str, Any]) -> StepResult[ObsT]: ...

    @abstractmethod
    def _parse_state(self, payload: Dict[str, Any]) -> StateT: ...

    # --- PROVIDED (don't override) ---
    async def reset(**kwargs) -> StepResult[ObsT]: ...
    async def step(action, **kwargs) -> StepResult[ObsT]: ...
    async def state() -> StateT: ...
    def sync() -> SyncEnvClient: ...  # synchronous wrapper

    # --- FACTORY METHODS ---
    @classmethod
    async def from_docker_image(cls, image, provider=None, **kwargs): ...
    @classmethod
    async def from_env(cls, repo_id, use_docker=True, ...): ...
```

---

## StepResult

```python
from openenv.core.client_types import StepResult

@dataclass
class StepResult(Generic[ObsT]):
    observation: ObsT
    reward: Optional[float] = None
    done: bool = False
```

---

## Server Factory

```python
from openenv.core.env_server import create_app

app = create_app(
    env=MyEnvironment,              # Environment CLASS (not instance)
    action_cls=MyAction,            # Action subclass
    observation_cls=MyObservation,  # Observation subclass
    env_name="my_env",             # optional
    max_concurrent_envs=1,         # optional
)
```

**Auto-generated endpoints:**
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/reset` | POST | Initialize new episode |
| `/step` | POST | Execute action |
| `/state` | GET | Get current state |
| `/health` | GET | Health check |
| `/metadata` | GET | Environment info |
| `/schema` | GET | JSON schemas |
| `/ws` | WS | WebSocket sessions |
| `/mcp` | POST | MCP JSON-RPC |
| `/docs` | GET | Swagger UI |

---

## Rubric Base Class

```python
from openenv.core.rubrics.base import Rubric

class Rubric(ABC):
    last_score: float

    @abstractmethod
    def forward(self, action, observation) -> float: ...

    def reset(self): ...
    def state_dict(self) -> dict: ...
    def load_state_dict(self, state_dict): ...
```

---

## openenv.yaml Format

```yaml
spec_version: 1
name: my_env
type: space
runtime: fastapi
app: server.app:app
port: 8000
```

---

## CLI Commands

```bash
openenv init my_env                              # scaffold project
openenv validate                                  # validate locally
openenv validate --url https://space.hf.space    # validate remote
openenv push --repo-id user/my-env               # deploy to HF Spaces
```

---

## Project Structure (from openenv init)

```
my_env/
├── __init__.py          # exports
├── models.py            # Action, Observation, State
├── client.py            # EnvClient subclass
├── openenv.yaml         # manifest
├── pyproject.toml       # deps
├── inference.py         # baseline (hackathon requirement)
├── README.md
└── server/
    ├── __init__.py
    ├── environment.py   # Environment subclass
    ├── app.py           # create_app()
    ├── requirements.txt
    └── Dockerfile
```

---

## Dependencies (openenv-core 0.2.3)

```
# Core
fastapi>=0.104.0
pydantic>=2.0.0
uvicorn>=0.24.0
requests>=2.25.0
websockets>=15.0.1
httpx>=0.28.1

# CLI
typer>=0.9.0
rich>=13.0.0
pyyaml>=6.0
huggingface_hub>=0.20.0
openai>=2.7.2
tomli>=2.3.0
tomli-w>=1.2.0

# MCP + UI
fastmcp>=3.0.0
gradio>=4.0.0
```

Python >= 3.10 required.

---

## Sync Usage Pattern (for inference.py)

```python
from my_env import MyEnv, MyAction

with MyEnv(base_url="https://your-space.hf.space").sync() as env:
    result = env.reset()
    observation = result.observation

    result = env.step(MyAction(field="value"))
    print(result.observation)
    print(result.reward)
    print(result.done)

    state = env.state()
    print(state.episode_id, state.step_count)
```
