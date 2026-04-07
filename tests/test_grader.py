"""Tests for the Security Audit grader."""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from server.grader import grade_episode, match_single_finding, _match_findings, _detect_framework
from server.scenarios import get_scenario


def _perfect_easy_findings():
    return [
        {"title": "SQL Injection in /api/login", "host": "10.0.1.10", "endpoint": "/api/login",
         "type": "SQL Injection", "severity": "Critical", "cvss_score": 9.8, "cwe": "CWE-89",
         "owasp": "A03:2021 - Injection",
         "evidence": "Parameter username vulnerable to OR 1=1 bypass, MySQL error exposed in response body.",
         "remediation": "Use parameterized queries or prepared statements for all database operations."},
        {"title": "Default credentials on admin panel", "host": "10.0.1.10", "endpoint": "/admin",
         "type": "Broken Authentication", "severity": "High", "cvss_score": 8.1, "cwe": "CWE-798",
         "owasp": "A07:2021 - Identification and Authentication Failures",
         "evidence": "Admin panel accessible with admin:admin123, no account lockout after multiple failures.",
         "remediation": "Change default credentials immediately. Implement account lockout and MFA."},
        {"title": "MySQL publicly accessible", "host": "10.0.1.20",
         "type": "Security Misconfiguration", "severity": "Critical", "cvss_score": 9.1, "cwe": "CWE-200",
         "owasp": "A05:2021 - Security Misconfiguration",
         "evidence": "MySQL port 3306 accessible from public internet, remote root login enabled, no firewall rules.",
         "remediation": "Restrict MySQL access to application server IPs only using firewall rules."},
    ]


class TestDeterminism:
    def test_same_inputs_same_outputs(self):
        s = get_scenario("easy"); f = _perfect_easy_findings()
        g1 = grade_episode(s, f, ["10.0.1.10", "10.0.1.20"], {"10.0.1.10": [22,80,443], "10.0.1.20": [22,3306]})
        g2 = grade_episode(s, f, ["10.0.1.10", "10.0.1.20"], {"10.0.1.10": [22,80,443], "10.0.1.20": [22,3306]})
        assert g1 == g2

    def test_all_scenarios(self):
        for sid in ["easy", "medium", "hard"]:
            s = get_scenario(sid)
            assert grade_episode(s, [], [], {}) == grade_episode(s, [], [], {})


class TestScoreBounds:
    def test_final_score_bounded(self):
        for sid in ["easy", "medium", "hard"]:
            g = grade_episode(get_scenario(sid), [], [], {})
            assert 0.0 <= g["final_score"] <= 1.0

    def test_component_scores_bounded(self):
        s = get_scenario("easy"); f = _perfect_easy_findings()
        g = grade_episode(s, f, ["10.0.1.10", "10.0.1.20"], {"10.0.1.10": [22,80,443], "10.0.1.20": [22,3306]})
        for k in ["detection_rate", "coverage", "severity_accuracy", "classification_accuracy",
                   "report_quality", "exploitation_proof", "compliance_coverage", "pivoting_score"]:
            assert 0.0 <= g[k] <= 1.0, f"{k} out of bounds: {g[k]}"


class TestPerfectScore:
    def test_easy_perfect(self):
        s = get_scenario("easy"); f = _perfect_easy_findings()
        g = grade_episode(s, f, ["10.0.1.10", "10.0.1.20"], {"10.0.1.10": [22,80,443], "10.0.1.20": [22,3306]})
        assert g["detection_rate"] == 1.0
        assert g["coverage"] == 1.0
        assert g["true_positives"] == 3
        assert g["false_positives"] == 0
        assert g["final_score"] >= 0.90


class TestEmptySubmission:
    def test_no_findings_no_hosts(self):
        g = grade_episode(get_scenario("easy"), [], [], {})
        assert g["final_score"] >= 0.0 and g["detection_rate"] == 0.0

    def test_no_findings_all_hosts(self):
        g = grade_episode(get_scenario("easy"), [], ["10.0.1.10", "10.0.1.20"], {})
        assert g["coverage"] == 1.0 and g["detection_rate"] == 0.0


class TestPenalties:
    def test_fp_escalating(self):
        s = get_scenario("easy")
        g1 = grade_episode(s, [{"title": "F", "host": "10.0.1.10", "type": "X", "severity": "Low"}], ["10.0.1.10"], {})
        g3 = grade_episode(s, [{"title": "F", "host": "10.0.1.10", "type": "X", "severity": "Low"}]*3, ["10.0.1.10"], {})
        assert abs(g1["fp_penalty"] - 0.03) < 0.001
        assert g3["fp_penalty"] > g1["fp_penalty"] * 3

    def test_honeypot(self):
        g = grade_episode(get_scenario("hard"), [], ["10.0.3.99"], {})
        assert g["honeypot_penalty"] == 0.15

    def test_coverage_multiplier(self):
        g = grade_episode(get_scenario("hard"), [], ["10.0.3.10"], {})
        assert g["coverage"] < 0.5 and g["coverage_multiplier"] < 1.0


class TestMatching:
    def test_by_cwe(self):
        assert match_single_finding({"host": "10.0.1.10", "type": "X", "cwe": "CWE-89"}, get_scenario("easy")["vulnerabilities"], set()) == "VULN-E001"

    def test_by_word_overlap(self):
        assert match_single_finding({"host": "10.0.1.10", "type": "SQL Injection vulnerability"}, get_scenario("easy")["vulnerabilities"], set()) == "VULN-E001"

    def test_by_endpoint(self):
        assert match_single_finding({"host": "10.0.1.10", "endpoint": "/api/login", "type": "Unknown"}, get_scenario("easy")["vulnerabilities"], set()) == "VULN-E001"

    def test_no_match_wrong_host(self):
        assert match_single_finding({"host": "10.0.1.99", "type": "SQL Injection", "cwe": "CWE-89"}, get_scenario("easy")["vulnerabilities"], set()) is None

    def test_no_double_match(self):
        assert match_single_finding({"host": "10.0.1.10", "type": "SQL Injection", "cwe": "CWE-89"}, get_scenario("easy")["vulnerabilities"], {"VULN-E001"}) is None

    def test_batch(self):
        assert len(_match_findings(get_scenario("easy")["vulnerabilities"], _perfect_easy_findings())) == 3


class TestCompliance:
    def test_pci(self): assert _detect_framework(get_scenario("medium")) == "PCI-DSS"
    def test_soc2(self): assert _detect_framework(get_scenario("hard")) == "SOC2"
    def test_generic(self): assert _detect_framework(get_scenario("easy")) == "Generic"
    def test_coverage_with_findings(self):
        g = grade_episode(get_scenario("easy"), _perfect_easy_findings(), ["10.0.1.10", "10.0.1.20"], {"10.0.1.10": [22,80,443], "10.0.1.20": [22,3306]})
        assert g["compliance_coverage"] > 0.0


class TestOWASP:
    def test_perfect(self):
        g = grade_episode(get_scenario("easy"), _perfect_easy_findings(), ["10.0.1.10", "10.0.1.20"], {"10.0.1.10": [22,80,443], "10.0.1.20": [22,3306]})
        assert g["owasp_accuracy"] == 1.0

    def test_missing(self):
        g = grade_episode(get_scenario("easy"), [{"title": "SQLi", "host": "10.0.1.10", "type": "SQL Injection", "severity": "Critical", "cvss_score": 9.8, "cwe": "CWE-89"}], ["10.0.1.10"], {})
        assert g["owasp_accuracy"] == 0.0


class TestReportQuality:
    def test_narrative(self):
        good = [{"title": "SQLi", "host": "10.0.1.10", "type": "SQL Injection", "severity": "Critical", "cvss_score": 9.8, "cwe": "CWE-89", "owasp": "A03:2021 - Injection", "evidence": "The username parameter is vulnerable to SQL injection via OR 1=1 payload", "remediation": "Use parameterized queries for all database operations in the login endpoint"}]
        bad = [{"title": "SQLi", "host": "10.0.1.10", "type": "SQL Injection", "severity": "Critical", "cvss_score": 9.8, "cwe": "CWE-89", "owasp": "A03:2021 - Injection", "evidence": "yes", "remediation": "fix"}]
        s = get_scenario("easy")
        assert grade_episode(s, good, ["10.0.1.10"], {})["narrative_quality"] > grade_episode(s, bad, ["10.0.1.10"], {})["narrative_quality"]


class TestEfficiency:
    def test_calculated(self):
        assert abs(grade_episode(get_scenario("easy"), [], [], {}, steps_used=15)["efficiency"] - 0.5) < 0.01

    def test_zero(self):
        assert grade_episode(get_scenario("easy"), [], [], {}, steps_used=0)["efficiency"] == 0.0


class TestPivoting:
    def test_easy_no_gateways(self):
        g = grade_episode(get_scenario("easy"), [], [], {})
        assert g["pivoting_score"] == 1.0  # no gateway vulns = default 1.0

    def test_medium_gateway(self):
        s = get_scenario("medium")
        # Submit only the SSRF (gateway vuln)
        f = [{"title": "SSRF", "host": "10.0.2.10", "endpoint": "/api/upload/image", "type": "Server-Side Request Forgery (SSRF)", "severity": "High", "cwe": "CWE-918"}]
        g = grade_episode(s, f, ["10.0.2.10"], {})
        assert g["pivoting_score"] == 1.0  # found the gateway


class TestExploitationProof:
    def test_proportional(self):
        s = get_scenario("easy")
        g = grade_episode(s, [_perfect_easy_findings()[0]], ["10.0.1.10"], {})
        assert abs(g["exploitation_proof"] - 1.0/3.0) < 0.01
