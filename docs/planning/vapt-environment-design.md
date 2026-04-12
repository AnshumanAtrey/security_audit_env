# VAPT Environment — Design Document

**Team:** AI Mafias (Anshuman Atrey, Sahil Shah, Vijay Kota)
**Hackathon:** Meta PyTorch OpenEnv Hackathon x SST
**Concept:** AI-powered VAPT (Vulnerability Assessment & Penetration Testing) simulation

---

## The Core Idea

Not a CTF game. A **simulated VAPT engagement platform** — the kind companies pay $10k–$50k for and takes 2-5 analysts 2 weeks to complete.

The AI does what a real red team does:

```
Real VAPT Workflow (what AI must replicate):

1. RECON          → map the attack surface (hosts, ports, services, tech stack)
2. ENUMERATION    → fingerprint every service, find version numbers
3. VULN SCAN      → match versions against CVE databases, find misconfigs
4. EXPLOITATION   → prove the vulnerability is real (PoC)
5. POST-EXPLOIT   → escalate privileges, move laterally, access sensitive data
6. REPORTING      → document each finding with CVSS score + remediation
```

The last step — **reporting** — is what separates this from CTF and makes it a real VAPT simulation. The AI's job isn't just "get root." It's "produce a professional security audit report."

---

## Real-World Problem Being Solved

| Customer | Current Reality | With This Environment |
|----------|----------------|-----------------------|
| Enterprise internal security team | 2 analysts, 2 weeks, manual process | AI runs overnight, analysts review output |
| SOC2 / ISO 27001 compliance teams | Annual pen test, $30k+ vendor cost | Continuous automated VAPT |
| VAPT service providers | Scale limited by headcount | AI handles 80% of work, humans review |
| Startups needing GDPR compliance | Can't afford proper pen test | Affordable AI-driven audit |

**Real-world utility argument for judges: 28–30/30**

---

## Architecture

```
vapt-env/
├── models.py                    ← Action, Observation, State (Pydantic)
├── client.py                    ← EnvClient subclass
├── server/
│   ├── environment.py           ← Main env logic (reset/step/state)
│   ├── network/
│   │   ├── topology.py          ← Simulated hosts, ports, services
│   │   ├── services.py          ← What each service returns when probed
│   │   ├── vulnerabilities.py   ← Vuln definitions + CVSS scores
│   │   └── scenarios/
│   │       ├── scenario_1.py    ← Easy: Startup web app (2 hosts, 3 vulns)
│   │       ├── scenario_2.py    ← Medium: E-commerce platform (4 hosts, 6 vulns)
│   │       └── scenario_3.py    ← Hard: Enterprise pre-SOC2 (8 hosts, 12 vulns)
│   ├── tools/
│   │   ├── recon.py             ← nmap, whatweb, dnsenum
│   │   ├── scanners.py          ← nikto, nuclei, searchsploit, sslyze
│   │   ├── exploits.py          ← sqlmap, hydra, exploit_cve, burp_test
│   │   ├── post_exploit.py      ← linpeas, lateral_move
│   │   └── reporting.py         ← submit_finding, generate_report
│   ├── grader.py                ← Score calculation logic
│   ├── app.py                   ← FastAPI wiring (one line)
│   └── Dockerfile
├── baseline/
│   └── agent.py                 ← OpenAI API agent that plays the env
├── openenv.yaml
├── requirements.txt
└── README.md
```

---

## Action Space

```python
class VAPTAction(Action):
    tool: Literal[
        # Recon
        "nmap",           # port + service scan
        "whatweb",        # tech fingerprinting
        "dnsenum",        # DNS enumeration

        # Vulnerability scanning
        "nikto",          # web vuln scanner
        "nuclei",         # template-based scanner
        "searchsploit",   # CVE lookup for version
        "sslyze",         # TLS/SSL misconfig check

        # Exploitation
        "sqlmap",         # SQL injection
        "hydra",          # credential brute force
        "exploit_cve",    # run specific CVE exploit
        "burp_test",      # manual web app testing

        # Post-exploitation
        "linpeas",        # privilege escalation enumeration
        "lateral_move",   # pivot to another host

        # VAPT-specific (the differentiator)
        "submit_finding",   # agent documents a vulnerability
        "generate_report"   # produce final VAPT report
    ]
    target: str       # IP address or hostname
    parameters: dict  # tool-specific params
```

---

## Observation Space

```python
class VAPTObservation(Observation):
    tool_output: str                       # Realistic tool output text
    discovered_hosts: List[str]            # IPs found so far
    open_ports: Dict[str, List[int]]       # host → [22, 80, 443, 3306]
    service_versions: Dict[str, str]       # "10.0.1.10:80" → "Apache 2.2.8"
    vulnerabilities_found: List[dict]      # submitted findings so far
    access_level: Dict[str, str]           # host → "none"|"user"|"root"
    attack_surface_coverage: float         # % of services examined (0.0-1.0)
    time_budget_remaining: int             # simulated engagement hours left
    message: str                           # human-readable context
    done: bool
    reward: float
```

---

## State Space

```python
class VAPTState(State):
    episode_id: str
    step_count: int
    scenario_id: int                       # 1, 2, or 3
    target_company: str
    engagement_type: str                   # "Web App VAPT", "Full Infra VAPT"
    compliance_context: str               # "SOC2", "GDPR", "PCI-DSS"
    discovered_hosts: List[str]
    open_ports: Dict[str, List[int]]
    service_versions: Dict[str, str]
    current_access: Dict[str, str]
    submitted_findings: List[dict]
    false_positives_submitted: int
    time_budget_used: int
```

---

## The Key Differentiator: `submit_finding`

This is what makes it VAPT, not CTF. The AI documents vulnerabilities like a real analyst:

```python
# Agent submits a finding:
action = VAPTAction(
    tool="submit_finding",
    target="10.0.1.10",
    parameters={
        "vuln_id": "SQLI-001",
        "title": "SQL Injection in /api/login",
        "severity": "Critical",
        "cvss_score": 9.8,
        "proof_of_concept": "' OR 1=1-- bypasses authentication",
        "impact": "Full database access, authentication bypass",
        "remediation": "Use parameterized queries / prepared statements"
    }
)
```

Grader checks:
- Did agent find the right vulnerability?
- Did they correctly assess severity (Critical vs High vs Medium)?
- Is the CVSS score close to ground truth?
- Did they provide a real PoC?
- Did they suggest remediation?

---

## The 3 Tasks

### Task 1 — Easy: "Startup Web App Audit"
- **Scenario:** 2 hosts, 3 vulnerabilities
- **Context:** Pre-launch security check for a SaaS startup
- **Hosts:** Web app server + database server
- **Vulnerabilities:**
  - SQL Injection in login endpoint (CVSS 9.8 — Critical)
  - Default admin credentials (CVSS 8.1 — High)
  - MySQL exposed to public internet (CVSS 9.1 — Critical)
- **Discovery:** All findable with nmap + nikto + sqlmap
- **Target:** Find all 3, correctly rate severity, submit structured findings

### Task 2 — Medium: "E-commerce Platform VAPT"
- **Scenario:** 4 hosts, 6 vulnerabilities, one requires chaining
- **Context:** PCI-DSS compliance audit for payment processor
- **Hosts:** Web frontend, API server, Jenkins CI/CD, internal DB
- **Vulnerabilities:**
  - SSRF in product image upload → internal network access
  - Broken authentication on API
  - Exposed API keys in JavaScript source
  - Unauthenticated Jenkins console (RCE)
  - Weak SSH passwords on DB server
  - Outdated SSL/TLS configuration
- **Chaining required:** SSRF → discover Jenkins → unauthenticated RCE
- **Target:** Find 5+/6, lateral movement required for full coverage

### Task 3 — Hard: "Enterprise Pre-SOC2 Audit"
- **Scenario:** 8 hosts, 12 vulnerabilities, Active Directory environment
- **Context:** SOC2 Type II pre-audit for enterprise SaaS company
- **Hosts:** Web app, API gateway, AD controller, file server, DB cluster, devops server, mail server, workstation
- **Features:**
  - Red herrings (honeypot services that penalize if touched)
  - Time-limited (40-hour simulated engagement budget)
  - AD/LDAP vulnerabilities (Kerberoasting, password spray)
  - Cloud misconfiguration (exposed S3 bucket equivalent)
  - Multi-step attack chains required
- **Target:** Cover full attack surface, correctly prioritize critical findings, produce executive report

---

## Simulated Network (Internal Representation)

The network is a Python dict — no real networking needed:

```python
SCENARIO_2 = {
    "company": "AcmePay Ltd",
    "engagement": "Full-scope Web + Infrastructure VAPT",
    "compliance_context": "PCI-DSS pre-audit",

    "hosts": {
        "10.0.1.10": {
            "hostname": "web-app-prod",
            "role": "Customer-facing web application",
            "stack": "Node.js + Express 4.17.1",
            "ports": {443: "HTTPS", 22: "SSH"},
            "vulnerabilities": [
                {
                    "id": "SQLI-001",
                    "type": "SQL Injection",
                    "location": "/api/login",
                    "cvss": 9.8, "severity": "Critical",
                    "found_by": ["sqlmap", "manual_burp"],
                    "impact": "Full DB dump, auth bypass"
                },
                {
                    "id": "BROKEN-AUTH-001",
                    "type": "Broken Authentication",
                    "location": "/admin",
                    "cvss": 8.1, "severity": "High",
                    "found_by": ["hydra", "manual"],
                    "credentials": {"admin": "admin123"}
                }
            ]
        },
        "10.0.1.20": {
            "hostname": "db-internal",
            "role": "MySQL Database",
            "ports": {3306: "MySQL (exposed externally!)", 22: "SSH"},
            "vulnerabilities": [
                {
                    "id": "EXPOSED-DB-001",
                    "type": "Exposed Database Service",
                    "cvss": 9.1, "severity": "Critical",
                    "found_by": ["nmap"],
                    "impact": "Direct DB access bypassing app layer"
                }
            ]
        },
        "10.0.1.30": {
            "hostname": "devops-jenkins",
            "role": "CI/CD Server",
            "ports": {8080: "Jenkins 2.235.1 (unauthenticated!)", 22: "SSH"},
            "vulnerabilities": [
                {
                    "id": "UNAUTH-JENKINS-001",
                    "type": "Unauthenticated Jenkins Access",
                    "cvss": 9.9, "severity": "Critical",
                    "found_by": ["nmap", "nikto", "gobuster"],
                    "impact": "RCE via Groovy script console, access to all secrets"
                }
            ]
        }
    },

    "ground_truth": {
        "total_vulns": 6,
        "critical": 3, "high": 2, "medium": 1, "low": 0
    }
}
```

When agent runs `nmap`, your code reads this dict and returns realistic text:

```
Starting Nmap 7.80
Nmap scan report for 10.0.1.10 (web-app-prod)
PORT    STATE  SERVICE  VERSION
22/tcp  open   ssh      OpenSSH 8.2p1
443/tcp open   ssl/http Express 4.17.1

Nmap scan report for 10.0.1.20 (db-internal)
PORT     STATE  SERVICE  VERSION
22/tcp   open   ssh      OpenSSH 7.6
3306/tcp open   mysql    MySQL 5.7.28
```

---

## Grader Formula

```python
def grade_episode(ground_truth, agent_findings, agent_actions):

    # 1. Detection rate — did agent find the vulns?
    found_ids    = set(f["vuln_id"] for f in agent_findings)
    actual_ids   = set(v["id"] for v in ground_truth["vulnerabilities"])
    detection    = len(found_ids & actual_ids) / len(actual_ids)

    # 2. Coverage — did agent examine the full attack surface?
    services_tested = count_unique_targets(agent_actions)
    total_services  = count_all_services(ground_truth)
    coverage        = services_tested / total_services

    # 3. Severity accuracy — did agent correctly rate CVSS?
    diffs = []
    for f in agent_findings:
        if f["vuln_id"] in actual_ids:
            true_cvss = get_true_cvss(ground_truth, f["vuln_id"])
            diffs.append(abs(true_cvss - f["cvss_score"]))
    severity_accuracy = 1.0 - (mean(diffs) / 10) if diffs else 0.0

    # 4. False positive penalty
    fp_count  = len(found_ids - actual_ids)
    fp_penalty = fp_count * 0.05

    # 5. Exploitation proof bonus
    exploited     = count_exploited(agent_actions, actual_ids)
    exploit_score = exploited / len(actual_ids)

    final = (
        0.40 * detection +
        0.25 * coverage +
        0.25 * severity_accuracy +
        0.10 * exploit_score
    ) - fp_penalty

    return max(0.0, min(1.0, final))
```

---

## Reward Function (Partial Progress Throughout)

```python
def step_reward(prev_state, curr_state, action, result):
    reward = 0.0

    # New host discovered
    new_hosts = set(curr_state.discovered_hosts) - set(prev_state.discovered_hosts)
    reward += len(new_hosts) * 0.05

    # New port/service discovered
    new_ports = count_new_ports(prev_state, curr_state)
    reward += new_ports * 0.02

    # New vulnerability found (via submit_finding)
    new_findings = len(curr_state.submitted_findings) - len(prev_state.submitted_findings)
    reward += new_findings * 0.10

    # New access level gained
    new_access = hosts_with_higher_access(prev_state, curr_state)
    reward += len(new_access) * 0.15

    # Correct CVSS severity bonus
    if action.tool == "submit_finding":
        reward += severity_accuracy_bonus(action.parameters, ground_truth)

    # Penalties
    if result == "invalid_tool_usage":
        reward -= 0.05
    if is_repeated_action(action, history):
        reward -= 0.02
    if action.target in honeypot_ips:
        reward -= 0.10   # touched honeypot

    return round(max(-0.5, min(0.5, reward)), 4)
```

---

## Required Endpoints

| Endpoint | Purpose |
|----------|---------|
| `POST /reset` | Start new engagement session |
| `POST /step` | Run a tool action, get observation |
| `GET /state` | Get current session state |
| `GET /tasks` | List all 3 tasks + action schema |
| `POST /grader` | Return final score after episode |
| `POST /baseline` | Run baseline OpenAI agent, return scores for all 3 tasks |

---

## Baseline Agent Logic

```python
# baseline/agent.py
# OpenAI agent that plays the VAPT environment

SYSTEM_PROMPT = """
You are a professional penetration tester conducting a VAPT engagement.

Available tools: nmap, whatweb, nikto, searchsploit, nuclei, sslyze,
                 sqlmap, hydra, exploit_cve, burp_test, linpeas,
                 lateral_move, submit_finding, generate_report

Your methodology:
1. Start with nmap to discover hosts and open ports
2. Fingerprint each service (version, technology)
3. Search for known CVEs using searchsploit
4. Exploit vulnerabilities to prove impact
5. Submit each finding with title, severity, CVSS score, PoC, remediation
6. Generate final report when done

Always respond with JSON:
{"tool": "...", "target": "...", "parameters": {...}}
"""
```

---

## Scoring Projection

| Criterion | Weight | Expected Score | Reason |
|-----------|--------|---------------|--------|
| Real-world utility | 30% | 28–30 | Solves a $30k/engagement real problem |
| Task & grader quality | 25% | 22–25 | Deterministic graders, clear difficulty curve |
| Environment design | 20% | 17–20 | Rich reward signal, clean state, realistic obs |
| Code quality | 15% | 13–15 | Standard OpenEnv spec, typed models |
| Creativity & novelty | 10% | 9–10 | Nobody else will build VAPT |
| **Total** | **100%** | **89–100** | |

---

## Why This Beats Everyone

1. **Reporting angle is unique** — every other team builds CTF-style "get the flag." We build an actual audit tool with structured findings.
2. **Rewards intelligence, not brute force** — random tool spamming gets penalized (false positives, coverage gaps). Systematic methodology wins.
3. **Judges immediately see the value** — Meta/HF engineers know what SOC2 costs. They'll see this as a real product.
4. **Nemotron will struggle with Hard task** — realistic, shows good difficulty calibration.
5. **Full-stack background is perfect** — the simulation is JSON + state machine + API. Exactly what we build every day.

---

## Build Order

| Day | Task |
|-----|------|
| Day 1 | `models.py` — all Pydantic types (Action, Observation, State) |
| Day 1 | `scenario_1.py` — easy network dict + ground truth |
| Day 2 | `tools/recon.py` — nmap simulation reads network dict, returns text |
| Day 2 | `tools/exploits.py` — sqlmap, hydra, exploit_cve simulations |
| Day 3 | `environment.py` — reset/step/state wired up, reward function |
| Day 3 | `grader.py` — detection rate, coverage, severity accuracy |
| Day 4 | `scenario_2.py` + `scenario_3.py` — medium + hard networks |
| Day 4 | `/tasks`, `/grader`, `/baseline` endpoints |
| Day 5 | Docker + deploy to HF Spaces |
| Day 5 | `baseline/agent.py` — OpenAI agent plays the env |
| Day 6 | Test with `openenv validate`, fix issues, submit |
