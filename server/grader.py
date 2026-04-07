"""
Security Audit Grader — Multi-dimensional scoring.

Scores agent performance across detection, coverage, severity accuracy,
classification accuracy, with penalties for false positives and honeypots.
Includes pivoting score, compliance-framework mapping, and report narrative quality.
"""

import re
from typing import Any, Dict, List, Optional, Set


# ---------------------------------------------------------------------------
# Compliance framework mappings — OWASP category → framework-specific controls
# ---------------------------------------------------------------------------
COMPLIANCE_MAPPINGS: Dict[str, Dict[str, List[str]]] = {
    "PCI-DSS": {
        "A01:2021": ["PCI-DSS 6.5.8 — Improper Access Control"],
        "A02:2021": ["PCI-DSS 4.1 — Strong Cryptography", "PCI-DSS 6.5.3 — Insecure Cryptographic Storage"],
        "A03:2021": ["PCI-DSS 6.5.1 — Injection Flaws"],
        "A04:2021": ["PCI-DSS 6.5.5 — Improper Error Handling"],
        "A05:2021": ["PCI-DSS 2.2 — Configuration Standards", "PCI-DSS 6.5.10 — Broken Auth/Session"],
        "A06:2021": ["PCI-DSS 6.2 — Security Patches"],
        "A07:2021": ["PCI-DSS 8.2 — User Authentication", "PCI-DSS 2.1 — Default Passwords"],
        "A08:2021": ["PCI-DSS 6.3.1 — Known Vulnerabilities"],
        "A09:2021": ["PCI-DSS 10.2 — Audit Trails"],
        "A10:2021": ["PCI-DSS 6.5.9 — SSRF"],
    },
    "SOC2": {
        "A01:2021": ["CC6.1 — Logical Access Security", "CC6.3 — Role-Based Access"],
        "A02:2021": ["CC6.7 — Restrict Data Transmission", "C1.1 — Confidentiality Commitments"],
        "A03:2021": ["CC6.1 — Logical Access Security", "CC6.6 — System Boundaries"],
        "A04:2021": ["CC8.1 — Change Management", "PI1.1 — Processing Integrity"],
        "A05:2021": ["CC6.6 — System Boundaries", "CC7.1 — Detect Changes"],
        "A06:2021": ["CC7.1 — Detect Changes", "CC8.1 — Change Management"],
        "A07:2021": ["CC6.1 — Logical Access Security", "CC6.2 — Prior to Access"],
        "A08:2021": ["CC7.1 — Detect Changes", "CC8.1 — Change Management"],
        "A09:2021": ["CC4.1 — Monitoring Activities", "CC7.2 — System Monitoring"],
        "A10:2021": ["CC6.6 — System Boundaries", "CC6.1 — Logical Access Security"],
    },
    "Generic": {
        "A01:2021": ["Access Control"],
        "A02:2021": ["Data Protection", "Encryption"],
        "A03:2021": ["Input Validation", "Secure Coding"],
        "A04:2021": ["Secure Design"],
        "A05:2021": ["Configuration Management"],
        "A06:2021": ["Patch Management"],
        "A07:2021": ["Authentication", "Credential Management"],
        "A08:2021": ["Software Composition Analysis"],
        "A09:2021": ["Logging and Monitoring"],
        "A10:2021": ["Network Security"],
    },
}

_FRAMEWORK_KEYWORDS = {
    "PCI-DSS": "PCI-DSS",
    "pci": "PCI-DSS",
    "SOC2": "SOC2",
    "SOC 2": "SOC2",
    "soc2": "SOC2",
}


def _detect_framework(scenario: Dict[str, Any]) -> str:
    """Detect compliance framework from scenario metadata."""
    ctx = scenario.get("compliance_context", "")
    for keyword, framework in _FRAMEWORK_KEYWORDS.items():
        if keyword.lower() in ctx.lower():
            return framework
    return "Generic"


def _owasp_matches(gt_owasp: str, submitted_owasp: str) -> bool:
    """Check if OWASP category matches (by category code, e.g. A03:2021)."""
    if not gt_owasp or not submitted_owasp:
        return False
    gt_cat = _extract_owasp_category(gt_owasp)
    sub_cat = _extract_owasp_category(submitted_owasp)
    return bool(gt_cat and gt_cat == sub_cat)


def _extract_owasp_category(owasp_str: str) -> str:
    """Extract OWASP category code like 'A03:2021' from full string."""
    match = re.search(r"A\d{2}:\d{4}", owasp_str)
    return match.group(0) if match else ""


def grade_episode(
    scenario: Dict[str, Any],
    submitted_findings: List[Dict[str, Any]],
    discovered_hosts: List[str],
    discovered_ports: Dict[str, List[int]],
    steps_used: int = 0,
) -> Dict[str, Any]:
    """Grade a completed audit episode. Returns component scores and final score (0.0-1.0)."""
    ground_truth = scenario.get("vulnerabilities", [])
    all_hosts = scenario.get("hosts", {})
    honeypots = scenario.get("honeypots", [])
    max_steps = scenario.get("max_steps", 50)

    # 1. Match findings to ground truth
    matched = _match_findings(ground_truth, submitted_findings)
    true_positives = len(matched)
    detection_rate = true_positives / len(ground_truth) if ground_truth else 0.0

    # 2. Coverage — what % of non-honeypot hosts did agent examine?
    total_hosts = len([h for h in all_hosts if h not in honeypots])
    examined_hosts = len([h for h in discovered_hosts if h not in honeypots])
    coverage = examined_hosts / total_hosts if total_hosts > 0 else 0.0

    # 3. Severity accuracy — CVSS scoring precision (stricter: ±4.0 tolerance)
    cvss_errors = []
    for gt_vuln, finding in matched:
        gt_cvss = gt_vuln.get("cvss", 0)
        submitted_cvss = finding.get("cvss_score", finding.get("cvss", 0))
        try:
            cvss_errors.append(abs(float(gt_cvss) - float(submitted_cvss)))
        except (ValueError, TypeError):
            cvss_errors.append(4.0)

    avg_cvss_error = sum(cvss_errors) / len(cvss_errors) if cvss_errors else 4.0
    severity_accuracy = max(0.0, 1.0 - avg_cvss_error / 4.0)

    # 4. Classification accuracy — CWE + OWASP matching
    correct_cwe = 0
    cwe_provided = 0
    correct_owasp = 0
    owasp_provided = 0
    for gt_vuln, finding in matched:
        gt_cwe = gt_vuln.get("cwe", "").strip()
        submitted_cwe = str(finding.get("cwe", "")).strip()
        if submitted_cwe:
            cwe_provided += 1
        if gt_cwe and gt_cwe.lower() == submitted_cwe.lower():
            correct_cwe += 1

        gt_owasp = gt_vuln.get("owasp", "").strip()
        submitted_owasp = str(finding.get("owasp", "")).strip()
        if submitted_owasp:
            owasp_provided += 1
        if gt_owasp and _owasp_matches(gt_owasp, submitted_owasp):
            correct_owasp += 1

    cwe_accuracy = correct_cwe / len(matched) if matched else 0.0
    owasp_accuracy = correct_owasp / len(matched) if matched else 0.0

    # CWE completeness penalty — halve classification if CWEs not provided
    cwe_completeness = cwe_provided / len(matched) if matched else 0.0

    # Blend CWE (70%) and OWASP (30%) for classification
    raw_classification = 0.7 * cwe_accuracy + 0.3 * owasp_accuracy
    classification_accuracy = raw_classification * (0.5 + 0.5 * cwe_completeness)

    # 5. False positive penalty — escalating per additional FP
    unmatched_findings = max(0, len(submitted_findings) - true_positives)
    fp_penalty = 0.0
    for i in range(unmatched_findings):
        fp_penalty += 0.03 + 0.01 * min(i, 5)  # 0.03, 0.04, 0.05, 0.06, 0.07, 0.08, 0.08...

    # 6. Honeypot penalty
    honeypot_touches = len([h for h in discovered_hosts if h in honeypots])
    honeypot_penalty = honeypot_touches * 0.15

    # 7. Report quality — field completeness + evidence narrative quality
    quality_fields = ["title", "host", "type", "severity", "cvss_score", "cwe", "owasp", "evidence", "remediation"]
    field_scores = []
    narrative_scores = []
    for _, finding in matched:
        present = sum(1 for f in quality_fields if finding.get(f))
        field_scores.append(present / len(quality_fields))

        evidence = str(finding.get("evidence", ""))
        remediation = str(finding.get("remediation", ""))
        evidence_quality = min(1.0, len(evidence) / 30.0) if evidence else 0.0
        remediation_quality = min(1.0, len(remediation) / 30.0) if remediation else 0.0
        narrative_scores.append((evidence_quality + remediation_quality) / 2.0)

    field_completeness = sum(field_scores) / len(field_scores) if field_scores else 0.0
    narrative_quality = sum(narrative_scores) / len(narrative_scores) if narrative_scores else 0.0
    report_quality = 0.6 * field_completeness + 0.4 * narrative_quality

    # 8. Pivoting score — did the agent find gateway vulns that unlock hidden hosts?
    # Rewards agents that recognize a vulnerability is a gateway to deeper access,
    # not just another checkbox — a uniquely VAPT concept.
    matched_vuln_ids = set()
    for gt_vuln, _ in matched:
        matched_vuln_ids.add(gt_vuln["id"])

    gateway_vulns = []
    for host_info in all_hosts.values():
        for req_id in host_info.get("hidden_until", []):
            if req_id not in [g["id"] for g in gateway_vulns]:
                for v in ground_truth:
                    if v["id"] == req_id:
                        gateway_vulns.append(v)
                        break

    gateway_found = sum(1 for v in gateway_vulns if v["id"] in matched_vuln_ids)
    pivoting_score = gateway_found / len(gateway_vulns) if gateway_vulns else 1.0

    # 9. Exploitation proof — proportional to findings (not binary)
    exploitation_proof = true_positives / len(ground_truth) if ground_truth else 0.0

    # 10. Compliance coverage
    framework = _detect_framework(scenario)
    compliance_controls_expected = set()
    compliance_controls_covered = set()
    framework_map = COMPLIANCE_MAPPINGS.get(framework, COMPLIANCE_MAPPINGS["Generic"])
    for gt_vuln in ground_truth:
        owasp_cat = _extract_owasp_category(gt_vuln.get("owasp", ""))
        controls = framework_map.get(owasp_cat, [])
        compliance_controls_expected.update(controls)
    for gt_vuln, _finding in matched:
        owasp_cat = _extract_owasp_category(gt_vuln.get("owasp", ""))
        controls = framework_map.get(owasp_cat, [])
        compliance_controls_covered.update(controls)
    compliance_coverage = (
        len(compliance_controls_covered) / len(compliance_controls_expected)
        if compliance_controls_expected else 0.0
    )

    # 11. Coverage multiplier — penalize agents that barely explored
    coverage_multiplier = 1.0
    if coverage < 0.5:
        coverage_multiplier = 0.7 + 0.6 * coverage

    # 12. Efficiency — informational metric
    efficiency = 1.0 - (steps_used / max_steps) if max_steps > 0 and steps_used > 0 else 0.0

    # Final weighted score
    # Weights: detection 30%, severity 20%, classification 15%, coverage 5%,
    # report 10%, pivoting 5%, exploitation 5%, compliance 5%, FP/honeypot penalties
    raw_score = (
        0.30 * detection_rate
        + 0.05 * coverage
        + 0.20 * severity_accuracy
        + 0.15 * classification_accuracy
        + 0.10 * report_quality
        + 0.05 * pivoting_score
        + 0.05 * exploitation_proof
        + 0.05 * compliance_coverage
        + 0.05 * (1.0 if true_positives > 0 else 0.0)
    ) * coverage_multiplier - fp_penalty - honeypot_penalty

    final_score = max(0.0, min(1.0, raw_score))

    return {
        "final_score": round(final_score, 4),
        "detection_rate": round(detection_rate, 4),
        "coverage": round(coverage, 4),
        "severity_accuracy": round(severity_accuracy, 4),
        "classification_accuracy": round(classification_accuracy, 4),
        "cwe_accuracy": round(cwe_accuracy, 4),
        "owasp_accuracy": round(owasp_accuracy, 4),
        "cwe_completeness": round(cwe_completeness, 4),
        "pivoting_score": round(pivoting_score, 4),
        "exploitation_proof": round(exploitation_proof, 4),
        "coverage_multiplier": round(coverage_multiplier, 4),
        "true_positives": true_positives,
        "total_vulnerabilities": len(ground_truth),
        "false_positives": unmatched_findings,
        "fp_penalty": round(fp_penalty, 4),
        "honeypot_penalty": round(honeypot_penalty, 4),
        "report_quality": round(report_quality, 4),
        "field_completeness": round(field_completeness, 4),
        "narrative_quality": round(narrative_quality, 4),
        "hosts_examined": examined_hosts,
        "total_hosts": total_hosts,
        # Informational metrics
        "compliance_framework": framework,
        "compliance_coverage": round(compliance_coverage, 4),
        "compliance_controls_covered": len(compliance_controls_covered),
        "compliance_controls_expected": len(compliance_controls_expected),
        "efficiency": round(efficiency, 4),
    }


def match_single_finding(
    finding: Dict[str, Any],
    ground_truth: List[Dict[str, Any]],
    already_matched: Set[str],
) -> Optional[str]:
    """Match a single submitted finding against ground truth.

    Returns the matched vulnerability ID, or None if no match.
    Uses the same matching logic as _match_findings for consistency.
    """
    f_host = finding.get("host", "")
    f_type = finding.get("type", finding.get("title", "")).lower()
    f_endpoint = finding.get("endpoint", "")
    f_cwe = str(finding.get("cwe", "")).lower()

    for gt in ground_truth:
        gt_id = gt.get("id", "")
        if gt_id in already_matched:
            continue

        gt_host = gt.get("host", "")
        gt_type = gt.get("type", "").lower()
        gt_endpoint = gt.get("endpoint", "")
        gt_cwe = gt.get("cwe", "").lower()

        if f_host != gt_host:
            continue

        gt_words = set(w.lower() for w in gt_type.replace("-", " ").split() if len(w) > 3)
        f_words = set(w.lower() for w in f_type.replace("-", " ").split() if len(w) > 3)
        word_overlap = len(gt_words & f_words) / len(gt_words) if gt_words else 0
        type_match = word_overlap > 0.5

        cwe_match = bool(gt_cwe and gt_cwe == f_cwe)
        endpoint_match = bool(f_endpoint and gt_endpoint and f_endpoint == gt_endpoint)

        if type_match or cwe_match or endpoint_match:
            return gt_id

    return None


def _match_findings(
    ground_truth: List[Dict[str, Any]],
    submitted: List[Dict[str, Any]],
) -> List[tuple]:
    """Match submitted findings to ground truth vulnerabilities.

    Uses word overlap matching on host + type/CWE/endpoint.
    """
    matched = []
    used_gt = set()

    for i, finding in enumerate(submitted):
        f_host = finding.get("host", "")
        f_type = finding.get("type", finding.get("title", "")).lower()
        f_endpoint = finding.get("endpoint", "")
        f_cwe = str(finding.get("cwe", "")).lower()

        for j, gt in enumerate(ground_truth):
            if j in used_gt:
                continue

            gt_host = gt.get("host", "")
            gt_type = gt.get("type", "").lower()
            gt_endpoint = gt.get("endpoint", "")
            gt_cwe = gt.get("cwe", "").lower()

            if f_host != gt_host:
                continue

            gt_words = set(w.lower() for w in gt_type.replace("-", " ").split() if len(w) > 3)
            f_words = set(w.lower() for w in f_type.replace("-", " ").split() if len(w) > 3)
            word_overlap = len(gt_words & f_words) / len(gt_words) if gt_words else 0
            type_match = word_overlap > 0.5

            cwe_match = gt_cwe and gt_cwe == f_cwe
            endpoint_match = (
                f_endpoint and gt_endpoint
                and f_endpoint == gt_endpoint
            )

            if type_match or cwe_match or endpoint_match:
                matched.append((gt, finding))
                used_gt.add(j)
                break

    return matched
