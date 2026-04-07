# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""
Data models for the Security Audit Environment.

Simulates real-world VAPT (Vulnerability Assessment & Penetration Testing)
engagements where an AI agent audits infrastructure for security compliance.
"""

from typing import Any, Dict, List, Literal, Optional

from openenv.core.env_server.types import Action, Observation, State
from pydantic import Field


class SecurityAuditAction(Action):
    """Action for the Security Audit environment.

    The agent interacts via tool calls — discover hosts, scan services,
    test for vulnerabilities, submit findings, and generate reports.
    """

    action_type: Literal[
        "list_tools",
        "use_tool",
        "submit_finding",
        "generate_report",
    ] = Field(..., description="Type of action to take")

    tool_name: Optional[str] = Field(
        default=None,
        description="Tool to invoke (required when action_type='use_tool')",
    )

    arguments: Dict[str, Any] = Field(
        default_factory=dict,
        description="Tool-specific arguments",
    )


class SecurityAuditObservation(Observation):
    """Observation returned after each step.

    Contains tool output, current discovery state, and audit progress.
    """

    tool_output: str = Field(
        default="",
        description="Text output from the executed tool",
    )

    available_tools: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="List of available tools (populated by list_tools action)",
    )

    discovered_hosts: List[str] = Field(
        default_factory=list,
        description="Hosts discovered so far",
    )

    discovered_services: Dict[str, List[str]] = Field(
        default_factory=dict,
        description="Services discovered per host (host → [service descriptions])",
    )

    findings_submitted: int = Field(
        default=0,
        description="Number of findings submitted so far",
    )

    steps_remaining: int = Field(
        default=0,
        description="Steps remaining before episode ends",
    )

    message: str = Field(
        default="",
        description="Human-readable status message",
    )

    truncated: bool = Field(
        default=False,
        description="True if episode ended due to step limit (truncation), "
                    "False if agent called generate_report (termination). "
                    "Important for RL value function estimation.",
    )

    current_phase: str = Field(
        default="reconnaissance",
        description="Current audit phase: reconnaissance, enumeration, exploitation, or reporting",
    )


class SecurityAuditState(State):
    """Full episode state for the security audit.

    Extends base State (episode_id, step_count) with audit-specific tracking.
    """

    scenario_id: str = Field(default="", description="Current scenario identifier")
    scenario_name: str = Field(default="", description="Human-readable scenario name")
    target_network: str = Field(default="", description="Target network CIDR")
    max_steps: int = Field(default=50, description="Maximum steps allowed")
    discovered_hosts: List[str] = Field(default_factory=list)
    discovered_ports: Dict[str, List[int]] = Field(default_factory=dict)
    discovered_services: Dict[str, List[str]] = Field(default_factory=dict)
    submitted_findings: List[Dict[str, Any]] = Field(default_factory=list)
    total_reward: float = Field(default=0.0)
