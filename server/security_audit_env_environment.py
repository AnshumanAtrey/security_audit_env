# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""
Security Audit Environment Implementation.

Simulates real-world VAPT engagements where an AI agent audits
infrastructure for security vulnerabilities and compliance gaps.
"""

from copy import deepcopy
from uuid import uuid4

from openenv.core.env_server.interfaces import Environment

try:
    from ..models import SecurityAuditAction, SecurityAuditObservation, SecurityAuditState
except ImportError:
    from models import SecurityAuditAction, SecurityAuditObservation, SecurityAuditState

try:
    from .scenarios import get_scenario, list_scenarios
    from .tools import TOOL_DEFINITIONS, execute_tool
    from .grader import grade_episode
except ImportError:
    from server.scenarios import get_scenario, list_scenarios
    from server.tools import TOOL_DEFINITIONS, execute_tool
    from server.grader import grade_episode


class SecurityAuditEnvironment(Environment):
    """
    AI Security Audit Training Environment.

    Simulates real-world Vulnerability Assessment & Penetration Testing (VAPT)
    engagements. The agent discovers hosts, scans services, identifies
    vulnerabilities, and submits structured findings — just like a
    professional security auditor.

    Three scenarios with increasing difficulty:
    - Easy: Startup web app (2 hosts, 3 vulns)
    - Medium: E-commerce platform (4 hosts, 6 vulns)
    - Hard: Enterprise SOC2 audit (6 hosts, 10 vulns + honeypots)
    """

    SUPPORTS_CONCURRENT_SESSIONS: bool = True

    def __init__(self):
        super().__init__()
        self._state = SecurityAuditState()
        self._scenario = None
        self._discovered_hosts: list = []
        self._discovered_ports: dict = {}
        self._discovered_services: dict = {}
        self._submitted_findings: list = []
        self._action_history: list = []
        self._discovered_vulns: set = set()
        self._episode_reward: float = 0.0

    def reset(self, seed=None, episode_id=None, **kwargs) -> SecurityAuditObservation:
        """Reset the environment for a new audit engagement.

        kwargs:
            scenario_id: "easy", "medium", or "hard" (default: "easy")
        """
        scenario_id = kwargs.get("scenario_id", "easy")
        self._scenario = deepcopy(get_scenario(scenario_id))

        self._discovered_hosts = []
        self._discovered_ports = {}
        self._discovered_services = {}
        self._submitted_findings = []
        self._action_history = []
        self._discovered_vulns = set()
        self._episode_reward = 0.0

        eid = episode_id or str(uuid4())
        self._state = SecurityAuditState(
            episode_id=eid,
            step_count=0,
            scenario_id=scenario_id,
            scenario_name=self._scenario["name"],
            target_network=self._scenario["target_network"],
            max_steps=self._scenario["max_steps"],
        )

        self._reset_rubric()

        return SecurityAuditObservation(
            tool_output="",
            message=self._scenario["briefing"],
            discovered_hosts=[],
            discovered_services={},
            findings_submitted=0,
            steps_remaining=self._scenario["max_steps"],
            done=False,
            reward=0.0,
        )

    def step(self, action: SecurityAuditAction, **kwargs) -> SecurityAuditObservation:
        """Execute one step in the security audit.

        The agent can:
        - list_tools: See available audit tools
        - use_tool: Run a security tool
        - submit_finding: Document a vulnerability
        - generate_report: End the audit and get final score
        """
        self._state.step_count += 1
        steps_remaining = self._state.max_steps - self._state.step_count

        # Track action
        self._action_history.append({
            "step": self._state.step_count,
            "action_type": action.action_type,
            "tool_name": action.tool_name,
            "arguments": action.arguments,
        })

        # Check step limit
        if steps_remaining <= 0:
            return self._finish_episode("Step limit reached. Audit terminated.")

        # Dispatch action
        if action.action_type == "list_tools":
            return self._handle_list_tools(steps_remaining)

        elif action.action_type == "use_tool":
            return self._handle_use_tool(action, steps_remaining)

        elif action.action_type == "submit_finding":
            return self._handle_submit_finding(action, steps_remaining)

        elif action.action_type == "generate_report":
            return self._finish_episode("Audit report generated.")

        else:
            return SecurityAuditObservation(
                tool_output=f"Unknown action_type: {action.action_type}",
                message="Use list_tools, use_tool, submit_finding, or generate_report.",
                discovered_hosts=self._discovered_hosts,
                discovered_services=self._discovered_services,
                findings_submitted=len(self._submitted_findings),
                steps_remaining=steps_remaining,
                done=False,
                reward=-0.05,
            )

    @property
    def state(self) -> SecurityAuditState:
        self._state.discovered_hosts = list(self._discovered_hosts)
        self._state.discovered_ports = dict(self._discovered_ports)
        self._state.discovered_services = dict(self._discovered_services)
        self._state.submitted_findings = list(self._submitted_findings)
        self._state.total_reward = self._episode_reward
        return self._state

    # --- Action Handlers ---

    def _handle_list_tools(self, steps_remaining: int) -> SecurityAuditObservation:
        tools_text = "Available security audit tools:\n\n"
        for tool in TOOL_DEFINITIONS:
            params = ", ".join(f"{k}: {v}" for k, v in tool["parameters"].items())
            tools_text += f"  {tool['name']}\n"
            tools_text += f"    Description: {tool['description']}\n"
            tools_text += f"    Parameters: {params}\n\n"

        return SecurityAuditObservation(
            tool_output=tools_text,
            available_tools=TOOL_DEFINITIONS,
            message="Use 'use_tool' action with tool_name and arguments to run a tool.",
            discovered_hosts=self._discovered_hosts,
            discovered_services=self._discovered_services,
            findings_submitted=len(self._submitted_findings),
            steps_remaining=steps_remaining,
            done=False,
            reward=0.0,
        )

    def _handle_use_tool(
        self, action: SecurityAuditAction, steps_remaining: int
    ) -> SecurityAuditObservation:
        if not action.tool_name:
            return SecurityAuditObservation(
                tool_output="Error: tool_name is required for use_tool action.",
                message="Specify which tool to use.",
                discovered_hosts=self._discovered_hosts,
                discovered_services=self._discovered_services,
                findings_submitted=len(self._submitted_findings),
                steps_remaining=steps_remaining,
                done=False,
                reward=-0.02,
            )

        # Check for honeypot interaction
        target = action.arguments.get("host", action.arguments.get("target", ""))
        honeypots = self._scenario.get("honeypots", [])
        honeypot_penalty = 0.0
        if target in honeypots:
            honeypot_penalty = -0.10

        output, new_hosts, new_ports, tool_reward = execute_tool(
            action.tool_name,
            action.arguments,
            self._scenario,
            self._discovered_hosts,
            self._discovered_ports,
            self._discovered_vulns,
        )

        # Update discovered state
        for h in new_hosts:
            if h not in self._discovered_hosts:
                self._discovered_hosts.append(h)

        for h, ports in new_ports.items():
            if h not in self._discovered_ports:
                self._discovered_ports[h] = []
            for p in ports:
                if p not in self._discovered_ports[h]:
                    self._discovered_ports[h].append(p)

        # Update discovered services from ports data
        for h in self._discovered_hosts:
            host_ports = self._scenario.get("ports", {}).get(h, [])
            known_ports = self._discovered_ports.get(h, [])
            services = []
            for p in host_ports:
                if p["port"] in known_ports:
                    services.append(f"{p['service']}/{p['port']}")
            if services:
                self._discovered_services[h] = services

        reward = tool_reward + honeypot_penalty
        self._episode_reward += reward

        message = ""
        if honeypot_penalty < 0:
            message = "WARNING: Activity detected on a monitoring system. This may be a honeypot."

        return SecurityAuditObservation(
            tool_output=output,
            message=message,
            discovered_hosts=self._discovered_hosts,
            discovered_services=self._discovered_services,
            findings_submitted=len(self._submitted_findings),
            steps_remaining=steps_remaining,
            done=False,
            reward=reward,
        )

    def _handle_submit_finding(
        self, action: SecurityAuditAction, steps_remaining: int
    ) -> SecurityAuditObservation:
        finding = action.arguments

        required = ["title", "host", "severity"]
        missing = [k for k in required if k not in finding]
        if missing:
            return SecurityAuditObservation(
                tool_output=f"Error: Missing required fields: {', '.join(missing)}",
                message="Finding must include at least: title, host, severity. "
                        "Recommended: cvss_score, cwe, owasp, endpoint, evidence, remediation.",
                discovered_hosts=self._discovered_hosts,
                discovered_services=self._discovered_services,
                findings_submitted=len(self._submitted_findings),
                steps_remaining=steps_remaining,
                done=False,
                reward=-0.02,
            )

        self._submitted_findings.append(finding)

        # Quick check if it matches a real vulnerability
        reward = 0.0
        gt_vulns = self._scenario.get("vulnerabilities", [])
        for v in gt_vulns:
            if v["host"] == finding.get("host"):
                v_type = v["type"].lower()
                f_title = finding.get("title", "").lower()
                f_type = finding.get("type", "").lower()
                f_cwe = str(finding.get("cwe", "")).lower()

                if (v_type in f_title or v_type in f_type
                        or f_title in v_type
                        or (v["cwe"].lower() in f_cwe)):
                    reward = 0.12
                    self._discovered_vulns.add(v["id"])
                    break

        if reward == 0.0:
            reward = 0.02  # small reward for any finding submission

        self._episode_reward += reward

        return SecurityAuditObservation(
            tool_output=f"Finding #{len(self._submitted_findings)} recorded: {finding.get('title', 'Untitled')}",
            message=f"Finding submitted. Total findings: {len(self._submitted_findings)}.",
            discovered_hosts=self._discovered_hosts,
            discovered_services=self._discovered_services,
            findings_submitted=len(self._submitted_findings),
            steps_remaining=steps_remaining,
            done=False,
            reward=reward,
        )

    def _finish_episode(self, message: str) -> SecurityAuditObservation:
        """End the audit and compute final grade."""
        grades = grade_episode(
            self._scenario,
            self._submitted_findings,
            self._discovered_hosts,
            self._discovered_ports,
        )

        final_score = grades["final_score"]
        self._episode_reward += final_score

        report_lines = [
            "=" * 60,
            "SECURITY AUDIT REPORT",
            "=" * 60,
            f"Scenario: {self._scenario['name']}",
            f"Company: {self._scenario['company']}",
            f"Compliance: {self._scenario['compliance_context']}",
            "",
            "RESULTS:",
            f"  Final Score: {final_score:.2f} / 1.00",
            f"  Detection Rate: {grades['detection_rate']:.2f} ({grades['true_positives']}/{grades['total_vulnerabilities']} vulnerabilities found)",
            f"  Coverage: {grades['coverage']:.2f} ({grades['hosts_examined']}/{grades['total_hosts']} hosts examined)",
            f"  Severity Accuracy: {grades['severity_accuracy']:.2f}",
            f"  Classification Accuracy: {grades['classification_accuracy']:.2f}",
            f"  False Positives: {grades['false_positives']} (penalty: -{grades['fp_penalty']:.2f})",
            f"  Honeypot Penalty: -{grades['honeypot_penalty']:.2f}",
            "",
            f"Steps Used: {self._state.step_count}",
            f"Findings Submitted: {len(self._submitted_findings)}",
            "=" * 60,
        ]

        return SecurityAuditObservation(
            tool_output="\n".join(report_lines),
            message=message,
            discovered_hosts=self._discovered_hosts,
            discovered_services=self._discovered_services,
            findings_submitted=len(self._submitted_findings),
            steps_remaining=0,
            done=True,
            reward=final_score,
            metadata={"grades": grades},
        )
