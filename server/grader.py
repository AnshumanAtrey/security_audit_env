"""
Security Audit Grader — Multi-dimensional scoring.

Scores agent performance across:
- Detection rate (found vs actual vulnerabilities)
- Coverage (attack surface examined)
- Severity accuracy (CVSS scoring precision)
- Classification accuracy (correct CWE/OWASP mapping)
- False positive penalty
"""

from typing import Any, Dict, List


def grade_episode(
    scenario: Dict[str, Any],
    submitted_findings: List[Dict[str, Any]],
    discovered_hosts: List[str],
    discovered_ports: Dict[str, List[int]],
) -> Dict[str, Any]:
    """Grade a completed audit episode.

    Returns a dict with component scores and final score (0.0-1.0).
    """
    ground_truth = scenario.get("vulnerabilities", [])
    all_hosts = scenario.get("hosts", {})
    all_ports = scenario.get("ports", {})
    honeypots = scenario.get("honeypots", [])

    gt_ids = {v["id"] for v in ground_truth}
    submitted_ids = set()
    for f in submitted_findings:
        vid = f.get("vuln_id", f.get("finding_id", ""))
        if vid:
            submitted_ids.add(vid)

    # 1. Detection rate — what % of real vulns did agent find?
    matched = _match_findings(ground_truth, submitted_findings)
    true_positives = len(matched)
    detection_rate = true_positives / len(ground_truth) if ground_truth else 0.0

    # 2. Coverage — what % of hosts did agent examine?
    total_hosts = len([h for h in all_hosts if h not in honeypots])
    examined_hosts = len([h for h in discovered_hosts if h not in honeypots])
    coverage = examined_hosts / total_hosts if total_hosts > 0 else 0.0

    # 3. Severity accuracy — CVSS scoring precision
    cvss_errors = []
    for gt_vuln, finding in matched:
        gt_cvss = gt_vuln.get("cvss", 0)
        submitted_cvss = finding.get("cvss_score", finding.get("cvss", 0))
        try:
            cvss_errors.append(abs(float(gt_cvss) - float(submitted_cvss)))
        except (ValueError, TypeError):
            cvss_errors.append(5.0)

    avg_cvss_error = sum(cvss_errors) / len(cvss_errors) if cvss_errors else 5.0
    severity_accuracy = max(0.0, 1.0 - avg_cvss_error / 10.0)

    # 4. Classification accuracy — correct CWE mapping
    correct_cwe = 0
    for gt_vuln, finding in matched:
        gt_cwe = gt_vuln.get("cwe", "").lower()
        submitted_cwe = str(finding.get("cwe", "")).lower()
        if gt_cwe and gt_cwe in submitted_cwe:
            correct_cwe += 1
    classification_accuracy = correct_cwe / len(matched) if matched else 0.0

    # 5. False positive penalty
    unmatched_findings = len(submitted_findings) - true_positives
    fp_penalty = min(0.3, unmatched_findings * 0.05)

    # 6. Honeypot penalty
    honeypot_touches = len([h for h in discovered_hosts if h in honeypots])
    honeypot_penalty = honeypot_touches * 0.10

    # Final weighted score
    raw_score = (
        0.35 * detection_rate
        + 0.20 * coverage
        + 0.20 * severity_accuracy
        + 0.15 * classification_accuracy
        + 0.10 * (1.0 if true_positives > 0 else 0.0)  # exploitation proof
    ) - fp_penalty - honeypot_penalty

    final_score = max(0.0, min(1.0, raw_score))

    return {
        "final_score": round(final_score, 4),
        "detection_rate": round(detection_rate, 4),
        "coverage": round(coverage, 4),
        "severity_accuracy": round(severity_accuracy, 4),
        "classification_accuracy": round(classification_accuracy, 4),
        "true_positives": true_positives,
        "total_vulnerabilities": len(ground_truth),
        "false_positives": unmatched_findings,
        "fp_penalty": round(fp_penalty, 4),
        "honeypot_penalty": round(honeypot_penalty, 4),
        "hosts_examined": examined_hosts,
        "total_hosts": total_hosts,
    }


def _match_findings(
    ground_truth: List[Dict[str, Any]],
    submitted: List[Dict[str, Any]],
) -> List[tuple]:
    """Match submitted findings to ground truth vulnerabilities.

    Uses fuzzy matching on host + type/endpoint to pair findings.
    Returns list of (gt_vuln, finding) tuples.
    """
    matched = []
    used_gt = set()
    used_sub = set()

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

            # Match by host + (type OR cwe OR endpoint)
            if f_host == gt_host:
                type_match = (
                    gt_type in f_type
                    or f_type in gt_type
                    or any(word in f_type for word in gt_type.split() if len(word) > 3)
                )
                cwe_match = gt_cwe and gt_cwe in f_cwe
                endpoint_match = f_endpoint and gt_endpoint and f_endpoint == gt_endpoint

                if type_match or cwe_match or endpoint_match:
                    matched.append((gt, finding))
                    used_gt.add(j)
                    used_sub.add(i)
                    break

    return matched
