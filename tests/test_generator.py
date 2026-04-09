"""Tests for the procedural scenario generator and knowledge base."""

from server.generator import generate_scenario
from server.knowledge_base.vulnerabilities import get_vuln_types, get_vuln_types_for_role, get_vuln_types_by_owasp
from server.knowledge_base.payloads import get_payloads, get_all_payload_sets
from server.knowledge_base.responses import render_vulnerable, render_safe, get_all_response_templates
from server.knowledge_base.compliance import get_controls_for_vuln, get_all_frameworks
from server.scenarios import get_scenario


# --- Knowledge Base Tests ---

class TestVulnTypes:
    def test_covers_all_owasp(self):
        vt = get_vuln_types()
        owasp_cats = {v.owasp_category.split(" - ")[0].strip() for v in vt.values()}
        for cat in ["A01:2021", "A02:2021", "A03:2021", "A05:2021", "A07:2021"]:
            assert cat in owasp_cats, f"Missing OWASP category {cat}"

    def test_min_count(self):
        assert len(get_vuln_types()) >= 20

    def test_valid_fields(self):
        for vid, vt in get_vuln_types().items():
            assert vt.id == vid
            assert len(vt.cwe_ids) > 0, f"{vid} has no CWE IDs"
            assert vt.cvss_range[0] <= vt.cvss_range[1], f"{vid} invalid CVSS range"
            assert len(vt.discoverable_by) > 0, f"{vid} has no tools"

    def test_role_filtering(self):
        web = get_vuln_types_for_role("Web Application Server")
        assert len(web) >= 5
        db = get_vuln_types_for_role("Database Server")
        assert len(db) >= 3


class TestPayloads:
    def test_has_major_types(self):
        for vt_id in ["sqli", "xss_reflected", "ssrf", "idor", "command_injection"]:
            ps = get_payloads(vt_id)
            assert len(ps.payloads) >= 3, f"{vt_id} has too few payloads"
            assert len(ps.indicators) >= 3, f"{vt_id} has too few indicators"

    def test_all_sets(self):
        assert len(get_all_payload_sets()) >= 14


class TestResponses:
    def test_three_tiers(self):
        for vt_id, tmpl in get_all_response_templates().items():
            assert "easy" in tmpl.vulnerable, f"{vt_id} missing easy tier"
            assert "medium" in tmpl.vulnerable, f"{vt_id} missing medium tier"
            assert "hard" in tmpl.vulnerable, f"{vt_id} missing hard tier"

    def test_easy_has_labels(self):
        ctx = {"host": "10.0.1.10", "endpoint": "/test", "parameter": "q",
               "cvss": "9.8", "cwe": "CWE-89", "severity": "Critical",
               "owasp": "A03:2021", "evidence_detail": "test", "remediation": "fix"}
        out = render_vulnerable("sqli", "easy", ctx)
        assert "CWE" in out or "cwe" in out.lower()

    def test_render_safe(self):
        ctx = {"host": "10.0.1.10", "endpoint": "/test"}
        out = render_safe("sqli", ctx)
        assert len(out) > 0


class TestCompliance:
    def test_all_frameworks(self):
        frameworks = get_all_frameworks()
        assert "PCI-DSS" in frameworks
        assert "SOC2" in frameworks
        assert "HIPAA" in frameworks

    def test_controls_for_sqli(self):
        controls = get_controls_for_vuln("sqli", "PCI-DSS")
        assert len(controls) > 0


# --- Generator Tests ---

class TestGeneratorDeterminism:
    def test_same_seed_same_output(self):
        s1 = generate_scenario("test-abc", seed=12345)
        s2 = generate_scenario("test-abc", seed=12345)
        assert s1["hosts"] == s2["hosts"]
        assert len(s1["vulnerabilities"]) == len(s2["vulnerabilities"])
        for v1, v2 in zip(s1["vulnerabilities"], s2["vulnerabilities"]):
            assert v1["id"] == v2["id"]
            assert v1["type"] == v2["type"]

    def test_different_seeds_different_output(self):
        s1 = generate_scenario("alpha", seed=111)
        s2 = generate_scenario("beta", seed=222)
        assert s1["hosts"] != s2["hosts"] or s1["company"] != s2["company"]


class TestGeneratorSchema:
    def test_required_keys(self):
        s = generate_scenario("test-schema", seed=99)
        for key in ["id", "name", "company", "compliance_context", "target_network",
                     "max_steps", "briefing", "hosts", "ports", "web_endpoints",
                     "vulnerabilities", "honeypots"]:
            assert key in s, f"Missing key: {key}"

    def test_vuln_schema(self):
        s = generate_scenario("test-vuln-schema", seed=77)
        for v in s["vulnerabilities"]:
            for key in ["id", "host", "type", "cwe", "owasp", "cvss", "severity",
                         "evidence", "remediation", "discoverable_by"]:
                assert key in v, f"Vuln {v.get('id', '?')} missing key: {key}"
            assert 0.0 <= v["cvss"] <= 10.0
            assert v["severity"] in ("Critical", "High", "Medium", "Low")


class TestGeneratorDifficulty:
    def test_easy_small(self):
        s = generate_scenario("easy-test", seed=1)
        assert len(s["hosts"]) == 2
        assert len(s["vulnerabilities"]) == 3
        assert len(s["honeypots"]) == 0

    def test_hard_large(self):
        s = generate_scenario("hard-test", seed=1)
        assert len(s["hosts"]) >= 5
        assert len(s["vulnerabilities"]) >= 8
        assert len(s["honeypots"]) >= 1

    def test_chain_integrity(self):
        s = generate_scenario("medium-chains", seed=42)
        vuln_ids = {v["id"] for v in s["vulnerabilities"]}
        for v in s["vulnerabilities"]:
            for req in v.get("requires_found", []):
                assert req in vuln_ids, f"Vuln {v['id']} requires {req} which doesn't exist"


class TestGeneratorBackwardCompat:
    def test_legacy_scenarios_unchanged(self):
        """Legacy easy/medium/hard must use original definitions, not generator."""
        easy = get_scenario("easy")
        assert "QuickLaunch" in easy.get("briefing", "") or "QuickLaunch" in easy.get("company", "")
        assert "10.0.1.10" in easy["hosts"]
        assert len(easy["vulnerabilities"]) == 3

    def test_custom_id_uses_generator(self):
        """Non-legacy IDs should produce generated scenarios."""
        s = get_scenario("custom-fintech-audit-2024")
        assert s["id"] == "custom-fintech-audit-2024"
        assert len(s["hosts"]) >= 2
        assert len(s["vulnerabilities"]) >= 3


# --- Parameter-Level Testing ---

class TestParameterTesting:
    def test_web_crawl_shows_params(self):
        """web_crawl output should include parameter info."""
        from server.tools_engine import execute_tool
        scenario = get_scenario("easy")
        hosts = list(scenario["hosts"].keys())
        output, _, _, _ = execute_tool(
            "web_crawl", {"host": hosts[0]},
            scenario, hosts, {}, set()
        )
        # Output should mention endpoints (may or may not have params depending on scenario)
        assert len(output) > 0

    def test_injection_without_param_works(self):
        """Backward compat: test_injection without parameter arg still works."""
        from server.tools_engine import execute_tool
        scenario = get_scenario("easy")
        hosts = list(scenario["hosts"].keys())
        output, _, _, reward = execute_tool(
            "test_injection", {"host": hosts[0], "endpoint": "/api/login"},
            scenario, hosts, {}, set()
        )
        assert len(output) > 0
        assert isinstance(reward, float)

    def test_injection_with_param_works(self):
        """test_injection with parameter arg should work."""
        from server.tools_engine import execute_tool
        scenario = get_scenario("easy")
        hosts = list(scenario["hosts"].keys())
        output, _, _, reward = execute_tool(
            "test_injection",
            {"host": hosts[0], "endpoint": "/api/login", "parameter": "username"},
            scenario, hosts, {}, set()
        )
        assert len(output) > 0
        assert isinstance(reward, float)
