"""
Test configuration — mocks openenv so tests run without the full framework installed.
"""

import sys
import types
import unittest.mock as mock

from pydantic import BaseModel
from typing import Any, Dict, Optional


# Build a proper mock hierarchy for openenv so sub-module imports resolve
_openenv = types.ModuleType("openenv")
_core = types.ModuleType("openenv.core")
_env_server = types.ModuleType("openenv.core.env_server")
_interfaces = types.ModuleType("openenv.core.env_server.interfaces")
_types_mod = types.ModuleType("openenv.core.env_server.types")
_http = types.ModuleType("openenv.core.env_server.http_server")
_client_types = types.ModuleType("openenv.core.client_types")

_openenv.core = _core
_core.env_server = _env_server
_core.EnvClient = mock.MagicMock()
_core.client_types = _client_types
_env_server.interfaces = _interfaces
_env_server.types = _types_mod
_env_server.http_server = _http


class _MockAction(BaseModel):
    pass


class _MockObservation(BaseModel):
    done: bool = False
    reward: float = 0.0
    truncated: bool = False
    metadata: Optional[Dict[str, Any]] = None


class _MockState(BaseModel):
    episode_id: Optional[str] = None
    step_count: int = 0


_types_mod.Action = _MockAction
_types_mod.Observation = _MockObservation
_types_mod.State = _MockState
_interfaces.Environment = type("Environment", (), {
    "__init__": lambda self: None,
    "_reset_rubric": lambda self: None,
})
_http.create_app = mock.MagicMock()
_client_types.StepResult = mock.MagicMock()

for name, mod in [
    ("openenv", _openenv),
    ("openenv.core", _core),
    ("openenv.core.env_server", _env_server),
    ("openenv.core.env_server.interfaces", _interfaces),
    ("openenv.core.env_server.types", _types_mod),
    ("openenv.core.env_server.http_server", _http),
    ("openenv.core.client_types", _client_types),
]:
    sys.modules[name] = mod
