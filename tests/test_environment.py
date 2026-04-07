"""Tests for the Security Audit Environment."""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from server.security_audit_env_environment import SecurityAuditEnvironment
from models import SecurityAuditAction, SecurityAuditObservation


class TestReset:
    def test_clean_state(self):
        env = SecurityAuditEnvironment()
        obs = env.reset(scenario_id="easy")
        assert obs.done is False and obs.reward == 0.0 and obs.discovered_hosts == []
        assert obs.steps_remaining == 30 and "QuickLaunch" in obs.message

    def test_clears_previous(self):
        env = SecurityAuditEnvironment()
        env.reset(scenario_id="easy")
        env.step(SecurityAuditAction(action_type="use_tool", tool_name="network_scan", arguments={"target": "10.0.1.0/24"}))
        obs = env.reset(scenario_id="easy")
        assert obs.discovered_hosts == [] and env._episode_reward == 0.0

    def test_all_scenarios(self):
        env = SecurityAuditEnvironment()
        for sid, steps in [("easy", 30), ("medium", 50), ("hard", 60)]:
            obs = env.reset(scenario_id=sid)
            assert obs.steps_remaining == steps and obs.done is False


class TestActions:
    def test_list_tools(self):
        env = SecurityAuditEnvironment(); env.reset(scenario_id="easy")
        obs = env.step(SecurityAuditAction(action_type="list_tools"))
        assert obs.available_tools is not None and len(obs.available_tools) == 10 and obs.reward == 0.0

    def test_network_scan(self):
        env = SecurityAuditEnvironment(); env.reset(scenario_id="easy")
        obs = env.step(SecurityAuditAction(action_type="use_tool", tool_name="network_scan", arguments={"target": "10.0.1.0/24"}))
        assert len(obs.discovered_hosts) == 2 and obs.reward > 0

    def test_missing_tool_name(self):
        env = SecurityAuditEnvironment(); env.reset(scenario_id="easy")
        obs = env.step(SecurityAuditAction(action_type="use_tool"))
        assert "Error" in obs.tool_output and obs.reward == -0.02

    def test_submit_finding(self):
        env = SecurityAuditEnvironment(); env.reset(scenario_id="easy")
        obs = env.step(SecurityAuditAction(action_type="submit_finding", arguments={"title": "SQL Injection in /api/login", "host": "10.0.1.10", "type": "SQL Injection", "severity": "Critical", "cwe": "CWE-89"}))
        assert obs.findings_submitted == 1 and obs.reward > 0

    def test_submit_missing_fields(self):
        env = SecurityAuditEnvironment(); env.reset(scenario_id="easy")
        obs = env.step(SecurityAuditAction(action_type="submit_finding", arguments={"title": "Test"}))
        assert obs.reward == -0.02 and "Missing" in obs.tool_output

    def test_generate_report(self):
        env = SecurityAuditEnvironment(); env.reset(scenario_id="easy")
        obs = env.step(SecurityAuditAction(action_type="generate_report"))
        assert obs.done is True and "SECURITY AUDIT REPORT" in obs.tool_output and obs.metadata and "grades" in obs.metadata


class TestRewards:
    def test_vary_by_action(self):
        env = SecurityAuditEnvironment(); env.reset(scenario_id="easy")
        obs1 = env.step(SecurityAuditAction(action_type="list_tools"))
        obs2 = env.step(SecurityAuditAction(action_type="use_tool", tool_name="network_scan", arguments={"target": "10.0.1.0/24"}))
        assert obs1.reward == 0.0 and obs2.reward > 0.0

    def test_difficulty_scaling(self):
        rewards = {}
        for sid in ["easy", "medium"]:
            env = SecurityAuditEnvironment(); env.reset(scenario_id=sid)
            obs = env.step(SecurityAuditAction(action_type="use_tool", tool_name="network_scan", arguments={"target": f"10.0.{1 if sid=='easy' else 2}.0/24"}))
            rewards[sid] = obs.reward
        assert rewards["medium"] > rewards["easy"]

    def test_redundant_penalty(self):
        env = SecurityAuditEnvironment(); env.reset(scenario_id="easy")
        obs1 = env.step(SecurityAuditAction(action_type="use_tool", tool_name="web_crawl", arguments={"host": "10.0.1.10"}))
        obs2 = env.step(SecurityAuditAction(action_type="use_tool", tool_name="web_crawl", arguments={"host": "10.0.1.10"}))
        assert obs2.reward < obs1.reward


class TestEpisodeBoundaries:
    def test_step_limit(self):
        env = SecurityAuditEnvironment(); env.reset(scenario_id="easy")
        obs = None
        for _ in range(31):
            obs = env.step(SecurityAuditAction(action_type="list_tools"))
            if obs.done: break
        assert obs.done is True

    def test_generate_report_ends(self):
        env = SecurityAuditEnvironment(); env.reset(scenario_id="easy")
        obs = env.step(SecurityAuditAction(action_type="generate_report"))
        assert obs.done is True and obs.steps_remaining == 0


class TestProgressiveDiscovery:
    def test_hidden_hosts_initially(self):
        env = SecurityAuditEnvironment(); env.reset(scenario_id="medium")
        obs = env.step(SecurityAuditAction(action_type="use_tool", tool_name="network_scan", arguments={"target": "10.0.2.0/24"}))
        assert "10.0.2.10" in obs.discovered_hosts and "10.0.2.30" not in obs.discovered_hosts

    def test_unlock_after_finding(self):
        env = SecurityAuditEnvironment(); env.reset(scenario_id="medium")
        env.step(SecurityAuditAction(action_type="use_tool", tool_name="network_scan", arguments={"target": "10.0.2.0/24"}))
        env.step(SecurityAuditAction(action_type="submit_finding", arguments={"title": "SSRF", "host": "10.0.2.10", "endpoint": "/api/upload/image", "type": "Server-Side Request Forgery (SSRF)", "severity": "High", "cwe": "CWE-918"}))
        obs = env.step(SecurityAuditAction(action_type="use_tool", tool_name="network_scan", arguments={"target": "10.0.2.0/24"}))
        assert "10.0.2.30" in obs.discovered_hosts


class TestHoneypot:
    def test_penalty(self):
        env = SecurityAuditEnvironment(); env.reset(scenario_id="hard")
        env.step(SecurityAuditAction(action_type="use_tool", tool_name="network_scan", arguments={"target": "10.0.3.0/24"}))
        obs = env.step(SecurityAuditAction(action_type="use_tool", tool_name="web_crawl", arguments={"host": "10.0.3.99"}))
        assert obs.reward < 0


class TestTruncation:
    def test_report_not_truncated(self):
        env = SecurityAuditEnvironment(); env.reset(scenario_id="easy")
        obs = env.step(SecurityAuditAction(action_type="generate_report"))
        assert obs.done is True and obs.truncated is False

    def test_step_limit_truncated(self):
        env = SecurityAuditEnvironment(); env.reset(scenario_id="easy")
        obs = None
        for _ in range(31):
            obs = env.step(SecurityAuditAction(action_type="list_tools"))
            if obs.done: break
        assert obs.done is True and obs.truncated is True


class TestPhaseTracking:
    def test_recon(self):
        env = SecurityAuditEnvironment(); env.reset(scenario_id="easy")
        assert env.step(SecurityAuditAction(action_type="list_tools")).current_phase == "reconnaissance"

    def test_enumeration(self):
        env = SecurityAuditEnvironment(); env.reset(scenario_id="easy")
        assert env.step(SecurityAuditAction(action_type="use_tool", tool_name="network_scan", arguments={"target": "10.0.1.0/24"})).current_phase == "enumeration"

    def test_exploitation(self):
        env = SecurityAuditEnvironment(); env.reset(scenario_id="easy")
        env.step(SecurityAuditAction(action_type="use_tool", tool_name="network_scan", arguments={"target": "10.0.1.0/24"}))
        assert env.step(SecurityAuditAction(action_type="submit_finding", arguments={"title": "T", "host": "10.0.1.10", "severity": "H"})).current_phase == "exploitation"

    def test_reporting(self):
        env = SecurityAuditEnvironment(); env.reset(scenario_id="easy")
        assert env.step(SecurityAuditAction(action_type="generate_report")).current_phase == "reporting"


class TestSeed:
    def test_deterministic(self):
        e1 = SecurityAuditEnvironment(); o1 = e1.reset(seed=42, scenario_id="easy")
        e2 = SecurityAuditEnvironment(); o2 = e2.reset(seed=42, scenario_id="easy")
        assert o1.message == o2.message

    def test_no_seed(self):
        env = SecurityAuditEnvironment()
        assert env.reset(scenario_id="easy").steps_remaining == 30


class TestFindingRewardCap:
    def test_diminishing(self):
        env = SecurityAuditEnvironment(); env.reset(scenario_id="easy")
        rewards = []
        for i in range(6):
            obs = env.step(SecurityAuditAction(action_type="submit_finding", arguments={"title": f"Fake {i}", "host": "10.0.1.99", "severity": "Low"}))
            rewards.append(obs.reward)
        assert rewards[0] == 0.02 and rewards[5] == 0.0


class TestBaseline:
    def test_easy_scores_high(self):
        env = SecurityAuditEnvironment(); env.reset(scenario_id="easy")
        env.step(SecurityAuditAction(action_type="use_tool", tool_name="network_scan", arguments={"target": "10.0.1.0/24"}))
        for title, host, ep, typ, sev, cvss, cwe, owasp in [
            ("SQL Injection", "10.0.1.10", "/api/login", "SQL Injection", "Critical", 9.8, "CWE-89", "A03:2021 - Injection"),
            ("Broken Auth", "10.0.1.10", "/admin", "Broken Authentication", "High", 8.1, "CWE-798", "A07:2021 - Identification and Authentication Failures"),
            ("Misconfig", "10.0.1.20", None, "Security Misconfiguration", "Critical", 9.1, "CWE-200", "A05:2021 - Security Misconfiguration"),
        ]:
            args = {"title": title, "host": host, "type": typ, "severity": sev, "cvss_score": cvss, "cwe": cwe, "owasp": owasp, "evidence": "Detailed evidence for " + title, "remediation": "Detailed remediation for " + title}
            if ep: args["endpoint"] = ep
            env.step(SecurityAuditAction(action_type="submit_finding", arguments=args))
        obs = env.step(SecurityAuditAction(action_type="generate_report"))
        g = obs.metadata["grades"]
        assert g["detection_rate"] == 1.0 and g["true_positives"] == 3 and g["final_score"] >= 0.90
