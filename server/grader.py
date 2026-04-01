"""
Security Audit Grader — Multi-dimensional scoring.

Scores agent performance across detection, coverage, severity accuracy,
classification accuracy, with penalties for false positives and honeypots.
"""

from typing import Any, Dict, List


def grade_episode(
    scenario: Dict[str, Any],
    submitted_findings: List[Dict[str, Any]],
    discovered_hosts: List[str],
    discovered_ports: Dict[str, List[int]],
) -> Dict[str, Any]:
    """Grade a completed audit episode. Returns component scores and final score (0.0-1.0)."""
    ground_truth = scenario.get("vulnerabilities", [])
    all_hosts = scenario.get("hosts", {})
    honeypots = scenario.get("honeypots", [])

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

    # 4. Classification accuracy — correct CWE mapping (exact match)
    correct_cwe = 0
    cwe_provided = 0
    for gt_vuln, finding in matched:
        gt_cwe = gt_vuln.get("cwe", "").strip()
        submitted_cwe = str(finding.get("cwe", "")).strip()
        if submitted_cwe:
            cwe_provided += 1
        if gt_cwe and gt_cwe.lower() == submitted_cwe.lower():
            correct_cwe += 1
    classification_accuracy = correct_cwe / len(matched) if matched else 0.0

    # CWE completeness penalty — halve classification if CWEs not provided
    cwe_completeness = cwe_provided / len(matched) if matched else 0.0
    classification_accuracy = classification_accuracy * (0.5 + 0.5 * cwe_completeness)

    # 5. False positive penalty — uncapped, 0.05 per false positive
    unmatched_findings = max(0, len(submitted_findings) - true_positives)
    fp_penalty = unmatched_findings * 0.05

    # 6. Honeypot penalty
    honeypot_touches = len([h for h in discovered_hosts if h in honeypots])
    honeypot_penalty = honeypot_touches * 0.15

    # 7. Report quality — bonus for complete findings (all fields present)
    quality_fields = ["title", "host", "type", "severity", "cvss_score", "cwe", "owasp", "evidence", "remediation"]
    field_scores = []
    for _, finding in matched:
        present = sum(1 for f in quality_fields if finding.get(f))
        field_scores.append(present / len(quality_fields))
    report_quality = sum(field_scores) / len(field_scores) if field_scores else 0.0

    # 8. Coverage multiplier — penalize agents that barely explored
    coverage_multiplier = 1.0
    if coverage < 0.5:
        coverage_multiplier = 0.7 + 0.6 * coverage

    # Final weighted score
    raw_score = (
        0.30 * detection_rate
        + 0.15 * coverage
        + 0.20 * severity_accuracy
        + 0.15 * classification_accuracy
        + 0.10 * report_quality
        + 0.10 * (1.0 if true_positives > 0 else 0.0)
    ) * coverage_multiplier - fp_penalty - honeypot_penalty

    final_score = max(0.0, min(1.0, raw_score))

    return {
        "final_score": round(final_score, 4),
        "detection_rate": round(detection_rate, 4),
        "coverage": round(coverage, 4),
        "severity_accuracy": round(severity_accuracy, 4),
        "classification_accuracy": round(classification_accuracy, 4),
        "cwe_completeness": round(cwe_completeness, 4),
        "coverage_multiplier": round(coverage_multiplier, 4),
        "true_positives": true_positives,
        "total_vulnerabilities": len(ground_truth),
        "false_positives": unmatched_findings,
        "fp_penalty": round(fp_penalty, 4),
        "honeypot_penalty": round(honeypot_penalty, 4),
        "report_quality": round(report_quality, 4),
        "hosts_examined": examined_hosts,
        "total_hosts": total_hosts,
    }


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

            # Type matching — require >50% significant word overlap
            gt_words = set(w.lower() for w in gt_type.replace("-", " ").split() if len(w) > 3)
            f_words = set(w.lower() for w in f_type.replace("-", " ").split() if len(w) > 3)
            word_overlap = len(gt_words & f_words) / len(gt_words) if gt_words else 0
            type_match = word_overlap > 0.5

            # CWE matching — exact CWE ID
            cwe_match = gt_cwe and gt_cwe == f_cwe

            # Endpoint matching — both must be defined and equal
            endpoint_match = (
                f_endpoint and gt_endpoint
                and f_endpoint == gt_endpoint
            )

            if type_match or cwe_match or endpoint_match:
                matched.append((gt, finding))
                used_gt.add(j)
                break

    return matched
