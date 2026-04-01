---
title: Security Audit Environment Server
emoji: "🔒"
colorFrom: blue
colorTo: purple
sdk: docker
app_port: 8000
---

# SecurityAuditEnv -- AI Security Compliance Audit Training

**Live Environment:** https://huggingface.co/spaces/anshumanatrey/security-audit-env

An OpenEnv environment that simulates real-world Vulnerability Assessment & Penetration Testing (VAPT) engagements. AI agents audit simulated corporate infrastructure -- discovering hosts, scanning services, identifying vulnerabilities, and producing structured compliance reports.

## Why This Matters

Every company needs annual security audits (SOC2, GDPR, PCI-DSS). Each audit costs $10k-$50k and takes 2-5 analysts 2 weeks. This environment trains AI agents to perform the same assessments, creating a standardized benchmark for security AI capabilities.

## Quick Start

```bash
pip install openenv-core
cd security_audit_env
PYTHONPATH=. uvicorn server.app:app --host 0.0.0.0 --port 8000
```

```python
from security_audit_env import SecurityAuditEnv, SecurityAuditAction

with SecurityAuditEnv(base_url="http://localhost:8000").sync() as env:
    result = env.reset(scenario_id="easy")
    print(result.observation.message)

    result = env.step(SecurityAuditAction(action_type="list_tools"))
    result = env.step(SecurityAuditAction(
        action_type="use_tool",
        tool_name="network_scan",
        arguments={"target": "10.0.1.0/24"}
    ))
    print(result.observation.discovered_hosts)

    result = env.step(SecurityAuditAction(
        action_type="submit_finding",
        arguments={
            "title": "SQL Injection in /api/login",
            "host": "10.0.1.10",
            "type": "SQL Injection",
            "severity": "Critical",
            "cvss_score": 9.8,
            "cwe": "CWE-89",
            "owasp": "A03:2021 - Injection",
        }
    ))

    result = env.step(SecurityAuditAction(action_type="generate_report"))
    print(result.observation.tool_output)
```

## Action Space

| Action | Description |
|--------|-------------|
| `list_tools` | See all available security audit tools |
| `use_tool` | Run a security tool (requires tool_name + arguments) |
| `submit_finding` | Document a discovered vulnerability |
| `generate_report` | End the audit and get the final score |

### Available Tools

| Tool | Description | Parameters |
|------|-------------|------------|
| `network_scan` | Discover hosts and open ports | target: IP/CIDR |
| `service_fingerprint` | Get service version details | host, port (opt) |
| `web_crawl` | Discover web endpoints | host |
| `vulnerability_scan` | Check for known CVEs | host |
| `test_injection` | Test for SQLi, SSRF, SSTI | host, endpoint |
| `test_xss` | Test for XSS | host, endpoint |
| `test_auth` | Test auth, default creds, IDOR | host, endpoint (opt) |
| `test_config` | Check for misconfigurations | host |
| `test_crypto` | Analyze TLS/SSL | host |
| `check_secrets` | Scan for exposed secrets | host, endpoint (opt) |

## Observation Space

| Field | Type | Description |
|-------|------|-------------|
| tool_output | str | Text output from the executed tool |
| available_tools | List[Dict] | Tool list (from list_tools) |
| discovered_hosts | List[str] | IPs found so far |
| discovered_services | Dict | Services per host |
| findings_submitted | int | Number of findings filed |
| steps_remaining | int | Steps left |
| message | str | Status message |
| done | bool | Episode finished? |
| reward | float | Step reward |

## Tasks (3 Scenarios)

### Easy: Startup Web App Audit
2 hosts, 3 vulnerabilities (SQLi, default credentials, exposed database). **Labeled tool output** — tools report vulnerability type, CWE, CVSS, and remediation. Max 30 steps.

### Medium: E-commerce Platform Audit
4 hosts (2 initially hidden behind firewall), 6 vulnerabilities (SSRF, IDOR, hardcoded secrets, unauthenticated Jenkins, weak credentials, outdated TLS). **Evidence-based output** — tools show anomalous behavior and raw evidence but do NOT label the vulnerability type, CWE, or severity. Agent must classify from evidence. SSRF discovery reveals internal hosts. Attack chaining required. Max 50 steps.

### Hard: Enterprise SOC2 Pre-Audit
6 hosts (3 initially hidden on internal network), 10 vulnerabilities (stored XSS, BOLA, race condition, SSTI, file upload, weak creds, missing encryption, email misconfiguration, vulnerable component, missing rate limiting). **Raw tool output** — tools return HTTP responses, timing data, error messages, and protocol traces. No labels, no hints. Agent must infer vulnerability type, severity, CWE, and impact from raw evidence. Includes honeypot decoy. Progressive network discovery. Max 60 steps.

## Tool Output Difficulty Tiers

The same tools produce different output detail depending on scenario difficulty:

| Difficulty | Tool Output Style | Agent Must... |
|------------|-------------------|---------------|
| Easy | `[CRITICAL] SQL Injection DETECTED, CWE: CWE-89, CVSS: 9.8` | Read and submit the labeled finding |
| Medium | `[!] Anomalous response — server fetched internal URL via image_url parameter` | Classify the vulnerability type and assess severity |
| Hard | `Parameter: image_url=http://10.0.2.30:8080 → HTTP 200, body: Jenkins HTML` | Infer SSRF from raw HTTP behavior, determine CWE-918, estimate CVSS |

This three-tier system ensures easy validates environment mechanics, medium tests classification ability, and hard genuinely challenges frontier model reasoning.

## Baseline Scores

Scores from a deterministic rule-based agent (no LLM) that scans, crawls endpoints, tests each individually, and attempts to parse tool output for labeled detections:

| Scenario | Detection | Coverage | Final Score | Why |
|----------|-----------|----------|-------------|-----|
| Easy | 1.00 | 1.00 | **1.00** | Labeled output — parser matches perfectly |
| Medium | 0.00 | 0.50 | **0.07** | Evidence-based output — parser can't classify, only gets coverage |
| Hard | 0.00 | 0.40 | **0.00** | Raw output + honeypot penalty exceeds coverage score |

The deterministic baseline fails on medium/hard because raw tool output requires reasoning to classify vulnerabilities. An LLM agent that can infer "server fetched internal URL → SSRF" or "payload {{7*7}} returned 49 → SSTI" would significantly outperform this baseline.

## Scoring

Multi-dimensional grading (0.0-1.0):

| Component | Weight |
|-----------|--------|
| Detection Rate | 30% |
| Coverage | 15% |
| Severity Accuracy (CVSS) | 20% |
| Classification (CWE/OWASP) | 15% |
| Report Quality | 10% |
| Exploitation Proof | 10% |
| False Positive Penalty | -5% each |
| Honeypot Penalty | -15% each |
| Coverage < 50% | multiplier penalty |

## Reward Function

Dense per-step rewards: +0.05 per host discovered, +0.08 per vulnerability found, +0.12 per correct finding submitted, -0.10 for honeypot interaction, plus final report score (0.0-1.0).

## Setup

```bash
# Docker
docker build -t security-audit-env -f server/Dockerfile .
docker run -p 8000:8000 security-audit-env

# HuggingFace Spaces
openenv push --repo-id your-username/security-audit-env

# Baseline inference
export API_BASE_URL="https://router.huggingface.co/v1"
export MODEL_NAME="meta-llama/Llama-3.3-70B-Instruct"
export HF_TOKEN="your-token"
export ENV_URL="http://localhost:8000"
python inference.py
```
