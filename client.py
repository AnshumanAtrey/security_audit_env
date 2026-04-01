# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""Security Audit Environment Client."""

from typing import Any, Dict

from openenv.core import EnvClient
from openenv.core.client_types import StepResult

from .models import SecurityAuditAction, SecurityAuditObservation, SecurityAuditState


class SecurityAuditEnv(
    EnvClient[SecurityAuditAction, SecurityAuditObservation, SecurityAuditState]
):
    """
    Client for the Security Audit Environment.

    Example:
        >>> with SecurityAuditEnv(base_url="http://localhost:8000").sync() as env:
        ...     result = env.reset(scenario_id="easy")
        ...     print(result.observation.message)
        ...
        ...     result = env.step(SecurityAuditAction(
        ...         action_type="list_tools"
        ...     ))
        ...     print(result.observation.tool_output)
    """

    def _step_payload(self, action: SecurityAuditAction) -> Dict[str, Any]:
        return action.model_dump(exclude_none=True)

    def _parse_result(self, payload: Dict[str, Any]) -> StepResult[SecurityAuditObservation]:
        obs_data = payload.get("observation", {})
        observation = SecurityAuditObservation(
            tool_output=obs_data.get("tool_output", ""),
            available_tools=obs_data.get("available_tools"),
            discovered_hosts=obs_data.get("discovered_hosts", []),
            discovered_services=obs_data.get("discovered_services", {}),
            findings_submitted=obs_data.get("findings_submitted", 0),
            steps_remaining=obs_data.get("steps_remaining", 0),
            message=obs_data.get("message", ""),
            done=payload.get("done", False),
            reward=payload.get("reward"),
            metadata=obs_data.get("metadata", {}),
        )
        return StepResult(
            observation=observation,
            reward=payload.get("reward"),
            done=payload.get("done", False),
        )

    def _parse_state(self, payload: Dict[str, Any]) -> SecurityAuditState:
        return SecurityAuditState(
            episode_id=payload.get("episode_id"),
            step_count=payload.get("step_count", 0),
            scenario_id=payload.get("scenario_id", ""),
            scenario_name=payload.get("scenario_name", ""),
            target_network=payload.get("target_network", ""),
            max_steps=payload.get("max_steps", 50),
            discovered_hosts=payload.get("discovered_hosts", []),
            discovered_ports=payload.get("discovered_ports", {}),
            discovered_services=payload.get("discovered_services", {}),
            submitted_findings=payload.get("submitted_findings", []),
            total_reward=payload.get("total_reward", 0.0),
        )
