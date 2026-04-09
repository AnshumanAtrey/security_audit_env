# VAPT Methodology, Testing Checklists, and Compliance Framework Mappings

> Comprehensive reference for building a realistic security audit benchmark.
> Compiled from PTES, OWASP WSTG, NIST SP 800-115, PCI-DSS 4.0, SOC2, HIPAA, and ISO 27001.

---

## Table of Contents

1. [VAPT Methodology / Phases](#1-vapt-methodology--phases)
2. [OWASP Web Security Testing Guide Checklist](#2-owasp-web-security-testing-guide-checklist)
3. [Compliance Framework Mappings](#3-compliance-framework-mappings)
4. [Pentest Report Structure](#4-pentest-report-structure)
5. [Cross-Reference: Vulnerability Types to Compliance](#5-cross-reference-vulnerability-types-to-compliance)

---

## 1. VAPT Methodology / Phases

### 1.1 PTES (Penetration Testing Execution Standard) - 7 Phases

The PTES is the internationally accepted framework for planning, executing, and reporting penetration tests. Created in 2009 by a group of security professionals.

#### Phase 1: Pre-Engagement Interactions

**Activities:**
- Define scope of engagement (IP ranges, domains, applications, exclusions)
- Obtain written authorization and legal agreements (Rules of Engagement)
- Establish testing windows, emergency contacts, escalation procedures
- Define communication channels and status reporting cadence
- Agree on testing methodology and tools to be used
- Set success criteria and objectives
- Identify sensitive systems and no-test zones

**Deliverables:** Scope document, Rules of Engagement (RoE), signed authorization, emergency contacts list

**Decision Logic:** Scope boundaries determine what intelligence gathering focuses on.

#### Phase 2: Intelligence Gathering (OSINT)

**Activities:**
- **Passive Reconnaissance:** Collect public information without touching target systems
  - DNS enumeration, WHOIS lookups, certificate transparency logs
  - Google Dorks for sensitive file discovery
  - Social media profiling of employees
  - Job posting analysis for technology stack identification
  - Data breach repository checks (HaveIBeenPwned)
  - Shodan/Censys for exposed services
- **Active Reconnaissance:** Direct interaction with target
  - Port scanning and service enumeration
  - Banner grabbing
  - Web application crawling
  - Technology fingerprinting (Wappalyzer, WhatWeb)

**Tools:** theHarvester, Maltego, Recon-ng, Amass, Nmap, Shodan, Google Dorks, SpiderFoot

**Deliverables:** Target profile, technology map, identified attack surface, potential credential sets

**Flow to Next Phase:** Intelligence informs threat modeling by mapping the attack surface and identifying likely entry points.

#### Phase 3: Threat Modeling

**Activities:**
- Analyze gathered intelligence to map probable attack paths
- Identify high-value assets and data stores
- Map business processes and their dependencies
- Identify threat actors relevant to the target (APTs, insiders, opportunistic)
- Prioritize attack vectors based on:
  - Likelihood of exploitation
  - Business impact if compromised
  - Alignment with real-world threat actor TTPs (MITRE ATT&CK)
- Create attack trees showing multi-step exploitation paths

**Deliverables:** Threat model document, prioritized attack vector list, attack trees

**Decision Logic:** Focus testing on realistic business risks rather than random vulnerability scanning. Prioritized vectors guide which vulnerabilities to look for in Phase 4.

#### Phase 4: Vulnerability Analysis

**Activities:**
- **Automated Scanning:**
  - Network vulnerability scanning (Nessus, OpenVAS, Qualys)
  - Web application scanning (Burp Suite, OWASP ZAP, Nikto)
  - SSL/TLS configuration testing (testssl.sh, SSLyze)
  - Configuration compliance scanning
- **Manual Validation:**
  - Verify automated findings to eliminate false positives
  - Test for logic flaws that scanners cannot detect
  - Review source code if available (white-box)
  - Test authentication and authorization mechanisms
  - Analyze custom application functionality
- **Correlation:**
  - Map vulnerabilities to threat model attack paths
  - Identify vulnerability chains that combine for greater impact
  - Prioritize validated vulnerabilities for exploitation

**Tools:** Nessus, OpenVAS, Burp Suite Professional, OWASP ZAP, Nikto, SQLMap, testssl.sh

**Deliverables:** Validated vulnerability list with severity ratings, false positive analysis

**Flow to Next Phase:** Only validated vulnerabilities become exploitation targets. Vulnerability chains inform multi-step attack scenarios.

#### Phase 5: Exploitation

**Activities:**
- Actively exploit validated vulnerabilities to prove they are real
- Gain initial foothold through proven attack vectors
- Common exploitation techniques:
  - SQL injection for data extraction or authentication bypass
  - Remote code execution via unpatched services
  - Password attacks (brute force, credential stuffing, password spraying)
  - Client-side attacks (phishing, XSS exploitation)
  - File upload bypasses
  - Deserialization attacks
  - Server-Side Request Forgery (SSRF)

**Tools:** Metasploit Framework, custom scripts, Cobalt Strike, SQLMap, Burp Suite

**Deliverables:** Proof of exploitation, initial access documentation, captured evidence (screenshots, logs)

**Decision Logic:** Only exploit vulnerabilities that passed manual validation. Avoid destructive actions. Document every step for reproducibility.

**Flow to Next Phase:** Successful compromises provide pivot points for post-exploitation.

#### Phase 6: Post-Exploitation

**Activities:**
- **Privilege Escalation:**
  - Local privilege escalation on compromised systems
  - Kernel exploits, misconfigurations, SUID/SGID binaries
  - Service account abuse
- **Lateral Movement:**
  - Use compromised systems as pivot points
  - Pass-the-hash, pass-the-ticket attacks
  - Network pivoting through compromised hosts
  - Exploiting trust relationships between systems
- **Data Exfiltration (Simulated):**
  - Identify sensitive data accessible from compromised positions
  - Demonstrate data exfiltration paths
  - Document scope of potential data breach
- **Persistence (if in scope):**
  - Demonstrate how attackers maintain access
  - Backdoor installation (documented, then removed)
- **Business Impact Analysis:**
  - Quantify the real-world impact of compromises
  - Answer "So what?" for each finding

**Tools:** Mimikatz, BloodHound, CrackMapExec, Chisel, proxychains, custom scripts

**Deliverables:** Impact assessment, lateral movement map, data access documentation

**Flow to Next Phase:** Documented impact informs remediation priority and executive summary.

#### Phase 7: Reporting

**Activities:**
- Compile all findings into a structured report
- Write Executive Summary (non-technical, 1-2 pages)
- Write Technical Report (detailed, reproducible findings)
- Assign risk ratings (CVSS 3.1 scoring)
- Provide remediation recommendations (short, medium, long-term)
- Map findings to compliance requirements
- Conduct debrief presentation with stakeholders

**Deliverables:** Final penetration test report (Executive + Technical), finding details with evidence, remediation roadmap

---

### 1.2 NIST SP 800-115 Framework - 4 Phases

NIST Special Publication 800-115 provides a four-phase framework for information security testing:

#### Phase 1: Planning
- Develop formal test plan with stakeholder sign-off
- Define Rules of Engagement
- Identify testing objectives and success criteria
- Coordinate with system owners and IT teams
- Establish legal and regulatory compliance requirements

#### Phase 2: Discovery
- **Review Techniques:** Documentation review, log review, ruleset review, system configuration review, network sniffing
- **Target Identification and Analysis:** Network discovery, port and service identification, vulnerability scanning, wireless scanning
- Active scanning with manual validation emphasis

#### Phase 3: Attack
- **Target Vulnerability Validation:** Password cracking, social engineering, penetration testing
- Controlled exploitation within strict safety constraints
- Focus on confirming vulnerabilities, not causing damage

#### Phase 4: Reporting
- Document all findings with evidence
- Bifurcated reports for executive and technical audiences
- Remediation recommendations
- Lessons learned and process improvement

### 1.3 Assessment Method Types (NIST SP 800-115)

| Method | Description | Examples |
|--------|-------------|----------|
| **Testing** | Hands-on validation of security controls | Penetration testing, password cracking, social engineering |
| **Examination** | Review of documentation, settings, and configurations | Policy review, log analysis, configuration audit |
| **Interviewing** | Discussions with personnel about security practices | Staff interviews about incident response, access control |

### 1.4 How Real Pentesters Decide What to Test Next

**Decision Framework:**

1. **Attack Surface Mapping First:** Start with the broadest view, then narrow down
2. **Low-Hanging Fruit:** Check for default credentials, known CVEs, misconfigurations
3. **Follow the Data:** Trace where sensitive data flows and focus testing there
4. **Threat-Informed:** Use MITRE ATT&CK to emulate real threat actor TTPs
5. **Chain Building:** Look for vulnerability combinations (e.g., SSRF + cloud metadata = credential theft)
6. **Business Logic:** Test application-specific workflows for logic flaws
7. **Iterative Deepening:** Each finding unlocks new testing avenues (compromised creds enable internal testing)

**Modern Approach (2025):**
A mature testing provider must be a "polymethodologist," blending:
- Lifecycle management from PTES or NIST
- Technical depth from OWASP WSTG
- Threat intelligence from MITRE ATT&CK

---

## 2. OWASP Web Security Testing Guide Checklist

### 2.1 Overview

The OWASP Web Security Testing Guide (WSTG) v4.2 is a comprehensive, open-source guide for testing web application security. Test cases use the identifier format: `WSTG-<CATEGORY>-<NUMBER>`.

**Total Test Categories:** 12
**Total Unique Test Cases:** 91 primary tests (+ 10 SQL injection subtypes + 2 code injection subtypes = 103 total including subtypes)

### 2.2 Complete Test Case Catalog

---

#### WSTG-INFO: Information Gathering (10 tests)

| ID | Test Name | What the Tester Looks For |
|----|-----------|--------------------------|
| WSTG-INFO-01 | Conduct Search Engine Discovery Reconnaissance | Sensitive information indexed by search engines, cached pages, exposed documents |
| WSTG-INFO-02 | Fingerprint Web Server | Web server type, version, known vulnerabilities for that version |
| WSTG-INFO-03 | Review Webserver Metafiles for Information Leakage | robots.txt, sitemap.xml, security.txt, humans.txt revealing hidden paths |
| WSTG-INFO-04 | Enumerate Applications on Webserver | Virtual hosts, subdomains, applications on non-standard ports |
| WSTG-INFO-05 | Review Webpage Content for Information Leakage | Comments in HTML/JS, API keys, internal IPs, developer notes |
| WSTG-INFO-06 | Identify Application Entry Points | HTTP methods, parameters, headers, cookies used by the application |
| WSTG-INFO-07 | Map Execution Paths Through Application | Application workflows, state machines, decision points |
| WSTG-INFO-08 | Fingerprint Web Application Framework | Framework type (Django, Rails, Spring), version, default files |
| WSTG-INFO-09 | Fingerprint Web Application | Custom application identification, technology stack mapping |
| WSTG-INFO-10 | Map Application Architecture | Infrastructure topology, load balancers, WAFs, CDNs, microservices |

---

#### WSTG-CONF: Configuration and Deployment Management Testing (11 tests)

| ID | Test Name | What the Tester Looks For |
|----|-----------|--------------------------|
| WSTG-CONF-01 | Test Network Infrastructure Configuration | Default configurations, unnecessary services, network device weaknesses |
| WSTG-CONF-02 | Test Application Platform Configuration | Default settings, unnecessary features enabled, debug modes |
| WSTG-CONF-03 | Test File Extensions Handling for Sensitive Information | Server behavior with different file extensions, source code disclosure |
| WSTG-CONF-04 | Review Old Backup and Unreferenced Files for Sensitive Information | .bak, .old, .tmp files, source code backups, configuration files |
| WSTG-CONF-05 | Enumerate Infrastructure and Application Admin Interfaces | Exposed admin panels, management consoles, default admin URLs |
| WSTG-CONF-06 | Test HTTP Methods | Dangerous HTTP methods enabled (PUT, DELETE, TRACE, CONNECT) |
| WSTG-CONF-07 | Test HTTP Strict Transport Security | HSTS header presence, correct configuration, preload status |
| WSTG-CONF-08 | Test RIA Cross Domain Policy | Flash/Silverlight cross-domain policies, overly permissive settings |
| WSTG-CONF-09 | Test File Permission | World-readable sensitive files, incorrect directory permissions |
| WSTG-CONF-10 | Test for Subdomain Takeover | Dangling DNS records, unclaimed cloud resources, expired services |
| WSTG-CONF-11 | Test Cloud Storage | Publicly accessible S3 buckets, Azure blobs, GCP storage buckets |

---

#### WSTG-IDNT: Identity Management Testing (5 tests)

| ID | Test Name | What the Tester Looks For |
|----|-----------|--------------------------|
| WSTG-IDNT-01 | Test Role Definitions | Role hierarchy, separation of duties, role assignment flaws |
| WSTG-IDNT-02 | Test User Registration Process | Self-registration abuse, identity verification weaknesses |
| WSTG-IDNT-03 | Test Account Provisioning Process | Account creation workflow flaws, authorization checks |
| WSTG-IDNT-04 | Testing for Account Enumeration and Guessable User Account | Username enumeration via login errors, registration, password reset |
| WSTG-IDNT-05 | Testing for Weak or Unenforced Username Policy | Predictable usernames, weak naming conventions, enumerable patterns |

---

#### WSTG-ATHN: Authentication Testing (10 tests)

| ID | Test Name | What the Tester Looks For |
|----|-----------|--------------------------|
| WSTG-ATHN-01 | Testing for Credentials Transported over an Encrypted Channel | Login forms over HTTP, credentials in URL parameters, mixed content |
| WSTG-ATHN-02 | Testing for Default Credentials | Default admin accounts, vendor-supplied passwords, known defaults |
| WSTG-ATHN-03 | Testing for Weak Lock Out Mechanism | Account lockout thresholds, lockout duration, lockout bypass |
| WSTG-ATHN-04 | Testing for Bypassing Authentication Schema | Direct page access, parameter manipulation, forced browsing |
| WSTG-ATHN-05 | Testing for Vulnerable Remember Password | Persistent authentication tokens, "remember me" implementation flaws |
| WSTG-ATHN-06 | Testing for Browser Cache Weaknesses | Credentials cached in browser, autocomplete enabled on sensitive fields |
| WSTG-ATHN-07 | Testing for Weak Password Policy | Minimum length, complexity requirements, common password blocking |
| WSTG-ATHN-08 | Testing for Weak Security Question/Answer | Guessable questions, publicly available answers, insufficient entropy |
| WSTG-ATHN-09 | Testing for Weak Password Change or Reset Functionality | Password reset token predictability, reset flow bypasses |
| WSTG-ATHN-10 | Testing for Weaker Authentication in Alternative Channel | Mobile app, API, or alternative interface with weaker auth |

---

#### WSTG-ATHZ: Authorization Testing (4 tests)

| ID | Test Name | What the Tester Looks For |
|----|-----------|--------------------------|
| WSTG-ATHZ-01 | Testing Directory Traversal File Include | Path traversal (../), file inclusion via parameter manipulation |
| WSTG-ATHZ-02 | Testing for Bypassing Authorization Schema | Horizontal and vertical privilege escalation, forced browsing |
| WSTG-ATHZ-03 | Testing for Privilege Escalation | Low-privilege user accessing admin functions, role escalation |
| WSTG-ATHZ-04 | Testing for Insecure Direct Object References (IDOR) | Predictable resource IDs, accessing other users' data via ID manipulation |

---

#### WSTG-SESS: Session Management Testing (9 tests)

| ID | Test Name | What the Tester Looks For |
|----|-----------|--------------------------|
| WSTG-SESS-01 | Testing for Session Management Schema | Session token generation quality, entropy, predictability |
| WSTG-SESS-02 | Testing for Cookies Attributes | Secure, HttpOnly, SameSite flags; cookie scope; domain/path settings |
| WSTG-SESS-03 | Testing for Session Fixation | Ability to set/fix session tokens before authentication |
| WSTG-SESS-04 | Testing for Exposed Session Variables | Session IDs in URLs, logs, referrer headers, error messages |
| WSTG-SESS-05 | Testing for Cross Site Request Forgery (CSRF) | Anti-CSRF token absence, token validation flaws, state-changing GET requests |
| WSTG-SESS-06 | Testing for Logout Functionality | Session destruction on logout, token invalidation, cached page access |
| WSTG-SESS-07 | Testing Session Timeout | Idle timeout, absolute timeout, concurrent session limits |
| WSTG-SESS-08 | Testing for Session Puzzling | Session variable overloading, shared session state manipulation |
| WSTG-SESS-09 | Testing for Session Hijacking | Session token theft via XSS, network sniffing, prediction |

---

#### WSTG-INPV: Input Validation Testing (19 primary tests + subtypes)

| ID | Test Name | What the Tester Looks For |
|----|-----------|--------------------------|
| WSTG-INPV-01 | Testing for Reflected Cross Site Scripting | Script injection via URL parameters reflected in response |
| WSTG-INPV-02 | Testing for Stored Cross Site Scripting | Persistent script injection stored in database/files |
| WSTG-INPV-03 | Testing for HTTP Verb Tampering | Bypassing security controls by changing HTTP method |
| WSTG-INPV-04 | Testing for HTTP Parameter Pollution | Duplicate parameter injection to bypass validation |
| WSTG-INPV-05 | Testing for SQL Injection | SQL query manipulation via user input |
| WSTG-INPV-05.1 | Testing for Oracle SQL Injection | Oracle-specific SQL injection techniques |
| WSTG-INPV-05.2 | Testing for MySQL SQL Injection | MySQL-specific injection and data extraction |
| WSTG-INPV-05.3 | Testing for SQL Server Injection | MSSQL-specific injection, xp_cmdshell, linked servers |
| WSTG-INPV-05.4 | Testing for PostgreSQL Injection | PostgreSQL-specific injection techniques |
| WSTG-INPV-05.5 | Testing for MS Access Injection | MS Access-specific injection |
| WSTG-INPV-05.6 | Testing for NoSQL Injection | MongoDB, CouchDB query injection |
| WSTG-INPV-05.7 | Testing for ORM Injection | Hibernate, ActiveRecord, Entity Framework injection |
| WSTG-INPV-05.8 | Testing for Client-side SQL Injection | Client-side database (WebSQL, IndexedDB) injection |
| WSTG-INPV-06 | Testing for LDAP Injection | LDAP query manipulation for auth bypass or data extraction |
| WSTG-INPV-07 | Testing for XML Injection | XML entity injection, XXE, XML data manipulation |
| WSTG-INPV-08 | Testing for SSI Injection | Server-Side Include directive injection |
| WSTG-INPV-09 | Testing for XPath Injection | XPath query manipulation for data extraction |
| WSTG-INPV-10 | Testing for IMAP/SMTP Injection | Email header/command injection |
| WSTG-INPV-11 | Testing for Code Injection | Server-side code execution via user input |
| WSTG-INPV-11.1 | Testing for Local File Inclusion | Including local server files via path manipulation |
| WSTG-INPV-11.2 | Testing for Remote File Inclusion | Including remote files/URLs for code execution |
| WSTG-INPV-12 | Testing for Command Injection | OS command execution via user input |
| WSTG-INPV-13 | Testing for Format String Injection | Format string vulnerabilities in user input |
| WSTG-INPV-14 | Testing for Incubated Vulnerability | Time-delayed or stored-then-triggered vulnerabilities |
| WSTG-INPV-15 | Testing for HTTP Splitting/Smuggling | HTTP response splitting, request smuggling |
| WSTG-INPV-16 | Testing for HTTP Incoming Requests | Server-side handling of incoming HTTP requests |
| WSTG-INPV-17 | Testing for Host Header Injection | Manipulating Host header for cache poisoning, password reset poisoning |
| WSTG-INPV-18 | Testing for Server-side Template Injection (SSTI) | Template engine code execution via user input |
| WSTG-INPV-19 | Testing for Server-Side Request Forgery (SSRF) | Making server issue requests to internal/external resources |

---

#### WSTG-ERRH: Testing for Error Handling (2 tests)

| ID | Test Name | What the Tester Looks For |
|----|-----------|--------------------------|
| WSTG-ERRH-01 | Testing for Improper Error Handling | Verbose error messages revealing stack traces, paths, versions |
| WSTG-ERRH-02 | Testing for Stack Traces | Detailed stack traces exposing internal code structure |

---

#### WSTG-CRYP: Testing for Weak Cryptography (4 tests)

| ID | Test Name | What the Tester Looks For |
|----|-----------|--------------------------|
| WSTG-CRYP-01 | Testing for Weak Transport Layer Security | Weak TLS versions, cipher suites, certificate issues |
| WSTG-CRYP-02 | Testing for Padding Oracle | CBC mode padding oracle attacks, encrypted cookie manipulation |
| WSTG-CRYP-03 | Testing for Sensitive Information Sent via Unencrypted Channels | Plaintext transmission of credentials, tokens, PII |
| WSTG-CRYP-04 | Testing for Weak Encryption | Weak algorithms (DES, RC4, MD5), insufficient key lengths |

---

#### WSTG-BUSL: Business Logic Testing (9 tests)

| ID | Test Name | What the Tester Looks For |
|----|-----------|--------------------------|
| WSTG-BUSL-01 | Test Business Logic Data Validation | Acceptance of invalid data in business context |
| WSTG-BUSL-02 | Test Ability to Forge Requests | Manipulating request sequences or parameters to bypass logic |
| WSTG-BUSL-03 | Test Integrity Checks | Tampering with data that should maintain integrity |
| WSTG-BUSL-04 | Test for Process Timing | Race conditions, time-of-check/time-of-use vulnerabilities |
| WSTG-BUSL-05 | Test Number of Times a Function Can Be Used Limits | Rate limiting bypass, unlimited resource consumption |
| WSTG-BUSL-06 | Testing for the Circumvention of Work Flows | Skipping steps in multi-step processes |
| WSTG-BUSL-07 | Test Defenses Against Application Misuse | Application abuse scenarios, automated attack detection |
| WSTG-BUSL-08 | Test Upload of Unexpected File Types | Bypassing file type restrictions, uploading executable files |
| WSTG-BUSL-09 | Test Upload of Malicious Files | Uploading web shells, malware, polyglot files |

---

#### WSTG-CLNT: Client-side Testing (13 tests)

| ID | Test Name | What the Tester Looks For |
|----|-----------|--------------------------|
| WSTG-CLNT-01 | Testing for DOM-Based Cross Site Scripting | XSS via DOM manipulation without server reflection |
| WSTG-CLNT-02 | Testing for JavaScript Execution | Arbitrary JavaScript execution via various injection points |
| WSTG-CLNT-03 | Testing for HTML Injection | HTML content injection for phishing or UI manipulation |
| WSTG-CLNT-04 | Testing for Client-side URL Redirect | Open redirects via client-side JavaScript |
| WSTG-CLNT-05 | Testing for CSS Injection | CSS-based data exfiltration and UI manipulation |
| WSTG-CLNT-06 | Testing for Client-side Resource Manipulation | DOM-based resource manipulation attacks |
| WSTG-CLNT-07 | Testing Cross Origin Resource Sharing (CORS) | Overly permissive CORS policies enabling cross-origin data theft |
| WSTG-CLNT-08 | Testing for Cross Site Flashing | Flash-based cross-site attacks (legacy) |
| WSTG-CLNT-09 | Testing for Clickjacking | UI redress attacks via iframe embedding |
| WSTG-CLNT-10 | Testing WebSockets | WebSocket security, authentication, input validation |
| WSTG-CLNT-11 | Testing Web Messaging | postMessage API security, origin validation |
| WSTG-CLNT-12 | Testing Browser Storage | Sensitive data in localStorage, sessionStorage, IndexedDB |
| WSTG-CLNT-13 | Testing for Cross Site Script Inclusion (XSSI) | Sensitive data leakage via script inclusion |

---

#### WSTG-APIT: API Testing (1 test)

| ID | Test Name | What the Tester Looks For |
|----|-----------|--------------------------|
| WSTG-APIT-01 | Testing GraphQL | GraphQL introspection, query injection, authorization bypass, DoS via nested queries |

---

### 2.3 Test Case Count Summary

| Category | Code | Count |
|----------|------|-------|
| Information Gathering | INFO | 10 |
| Configuration and Deployment Management | CONF | 11 |
| Identity Management | IDNT | 5 |
| Authentication | ATHN | 10 |
| Authorization | ATHZ | 4 |
| Session Management | SESS | 9 |
| Input Validation | INPV | 19 (+12 subtypes) |
| Error Handling | ERRH | 2 |
| Weak Cryptography | CRYP | 4 |
| Business Logic | BUSL | 9 |
| Client-side | CLNT | 13 |
| API Testing | APIT | 1 |
| **Total Primary Tests** | | **97** |
| **Total Including Subtypes** | | **109** |

---

## 3. Compliance Framework Mappings

### 3.1 PCI-DSS 4.0 Requirements Mapped to Penetration Testing

#### Key Requirement Numbers

| Requirement | Description | Testing Relevance |
|-------------|-------------|-------------------|
| **6.2.4** | Software is protected against common attacks | Defines specific vulnerability types that must be tested at the application layer |
| **11.4** | External and internal penetration testing | Primary penetration testing requirement |
| **11.4.1** | Documented penetration testing methodology | Must align with PTES, NIST SP 800-115, or OWASP |
| **11.4.2** | Internal penetration testing | At least annually and after significant changes |
| **11.4.3** | External penetration testing | At least annually and after significant changes |
| **11.4.4** | Vulnerability remediation and retesting | All findings must be remediated and verified |
| **11.4.5** | Network segmentation testing | Validate CDE isolation effectiveness |
| **11.4.6** | Service provider segmentation testing | Every six months for service providers |
| **11.3.1** | Internal vulnerability scanning | Quarterly minimum, resolve High/Critical findings |
| **11.3.2** | External vulnerability scanning (ASV) | Quarterly via Approved Scanning Vendor |

#### PCI-DSS 4.0 Requirement 6.2.4 - Vulnerability Types That Must Be Tested

Software must be protected against:

1. **Injection Attacks**
   - SQL Injection
   - LDAP Injection
   - XPath Injection
   - Command Injection
   - Parameter Injection
   - Object Injection
   - Fault Injection

2. **Data and Data Structure Attacks**
   - Buffer overflows
   - Cross-site scripting (XSS)
   - Cross-site request forgery (CSRF)

3. **Attacks on Cryptography Usage**
   - Weak cryptographic implementations
   - Improper key management
   - Insecure cryptographic storage

4. **Attacks on Business Logic**
   - Manipulation of APIs
   - Abuse of communication protocols and channels
   - Client-side functionality manipulation
   - Abuse of system/application functions and resources

5. **Attacks on Access Control Mechanisms**
   - Bypassing identification mechanisms
   - Bypassing authentication mechanisms
   - Bypassing authorization mechanisms
   - Exploiting implementation weaknesses in access controls

#### PCI-DSS Penetration Testing Scope Requirements

- **External Testing:** Internet-facing systems and services in the perimeter
- **Internal Testing:** Internal network, applications, and critical systems
- **Application-Layer Testing:** Must identify vulnerabilities listed in Requirement 6.2.4
- **Network-Layer Testing:** All components supporting network functions and operating systems
- **Segmentation Testing:** Validate isolation of Cardholder Data Environment (CDE)
- **After Significant Changes:** Major infrastructure modifications, new payment applications, network segment additions, firewall rule updates

#### PCI-DSS Tester Qualifications

- Must be qualified with demonstrated penetration testing expertise
- Organizationally independent from systems being tested
- Common certifications: OSCP, GPEN, CEH
- Internal testers acceptable if independence requirement is met

---

### 3.2 SOC 2 Trust Service Criteria Mapped to Security Controls

#### Five Trust Service Categories

| Category | Required? | Description |
|----------|-----------|-------------|
| **Security** | Mandatory | Protecting information from vulnerabilities and unauthorized access |
| **Availability** | Optional | Ensuring systems are operational and accessible |
| **Processing Integrity** | Optional | Verifying systems operate as intended |
| **Confidentiality** | Optional | Protecting confidential information |
| **Privacy** | Optional | Safeguarding sensitive personal information |

#### Nine Common Criteria (CC) Control Families

| CC Family | Name | Pentest Relevance |
|-----------|------|-------------------|
| **CC1** | Control Environment | Governance and oversight; pentest demonstrates control effectiveness |
| **CC2** | Communication and Information | Security policies communicated; pentest validates enforcement |
| **CC3** | Risk Assessment | Risk identification; pentest findings feed risk register |
| **CC4** | Monitoring Activities | Ongoing evaluations; pentest is evidence of CC4.1 monitoring |
| **CC5** | Control Activities | Specific controls; pentest validates access controls, segregation of duties |
| **CC6** | Logical and Physical Access Controls | Core pentest target area |
| **CC7** | System Operations | Incident detection; pentest validates monitoring and response |
| **CC8** | Change Management | Changes tested; pentest validates change control effectiveness |
| **CC9** | Risk Mitigation | Risk treatment; pentest validates mitigation effectiveness |

#### Key SOC 2 Criteria for Penetration Testing

| Criteria ID | Description | Pentest Mapping |
|-------------|-------------|-----------------|
| **CC4.1** | Ongoing and separate evaluations of controls | Penetration testing serves as a "separate evaluation" providing independent verification |
| **CC6.1** | Logical access security implementation | Test authentication mechanisms, session management, access controls |
| **CC6.2** | Prior to issuing system credentials, registered/authorized users are verified | Test user registration, account provisioning, identity verification |
| **CC6.3** | Access is authorized, modified, and removed based on roles | Test RBAC, privilege escalation, authorization bypass |
| **CC6.6** | Security measures against threats outside system boundaries | Test external-facing controls, WAF, IDS/IPS effectiveness |
| **CC6.7** | Restrict information transmission to authorized channels | Test data exfiltration paths, unauthorized data transmission |
| **CC6.8** | Controls to prevent or detect deployment of unauthorized/malicious software | Test malware defenses, file upload controls |
| **CC7.1** | Detection of new vulnerabilities and susceptibilities | Vulnerability scanning and assessment results |
| **CC7.2** | Monitoring for anomalous or suspicious activity | Test detection capabilities, SIEM alerting |
| **CC7.3** | Evaluating security events for impact | Incident response testing |
| **CC7.4** | Responding to identified security incidents | Validate incident response procedures |
| **CC8.1** | Changes are authorized, designed, developed, configured, documented, and tested | Test change management controls |
| **CC9.1** | Risk mitigation activities | Pentest validates risk treatment effectiveness |

#### SOC 2 Pentest Report Requirements

- Must clearly map findings to relevant Trust Services Criteria
- Covers all in-scope systems: internal/external networks, cloud, applications, APIs
- Combines automated scanning with expert manual testing
- Provides evidence for auditors to verify control effectiveness

---

### 3.3 HIPAA Security Rule Requirements

#### Safeguard Categories Overview

| CFR Section | Safeguard Type | Standards Count |
|-------------|---------------|-----------------|
| **164.308** | Administrative | 9 standards |
| **164.310** | Physical | 4 standards |
| **164.312** | Technical | 5 standards |
| **164.316** | Documentation | 2 standards |

#### Administrative Safeguards (45 CFR 164.308)

| Section | Standard | R/A | Pentest Relevance |
|---------|----------|-----|-------------------|
| 164.308(a)(1) | Security Management Process | Required | Risk analysis and risk management; pentest validates security posture |
| 164.308(a)(2) | Assigned Security Responsibility | Required | Security Official designation |
| 164.308(a)(3) | Workforce Security | Required | Onboarding/offboarding, least-privilege validation |
| 164.308(a)(4) | Information Access Management | Required | Role-based access; pentest validates access controls |
| 164.308(a)(5) | Security Awareness and Training | Required | Phishing simulations as part of social engineering testing |
| 164.308(a)(6) | Security Incident Procedures | Required | Incident response; pentest may test detection/response |
| 164.308(a)(7) | Contingency Planning | Required | Backup and disaster recovery validation |
| 164.308(a)(8) | Evaluation | Required | **Periodic technical and nontechnical assessments confirming safeguard effectiveness** - direct mandate for penetration testing |
| 164.308(b) | Business Associate Management | Required | BAA requirements, vendor security review |

#### Technical Safeguards (45 CFR 164.312)

| Section | Standard | R/A | Pentest Relevance |
|---------|----------|-----|-------------------|
| 164.312(a)(1) | Access Control | Required | Unique IDs, MFA, role-based access, privileged access management, break-glass access |
| 164.312(a)(2)(i) | Unique User Identification | Required | Test for shared accounts, default credentials |
| 164.312(a)(2)(ii) | Emergency Access Procedure | Required | Break-glass procedure validation |
| 164.312(a)(2)(iii) | Automatic Logoff | Addressable | Session timeout testing |
| 164.312(a)(2)(iv) | Encryption and Decryption | Addressable | Encryption at rest validation |
| 164.312(b) | Audit Controls | Required | Logging, SIEM, immutable logs, anomaly detection |
| 164.312(c)(1) | Integrity | Required | Hashing, digital signatures, change monitoring, tamper-evident storage |
| 164.312(d) | Person or Entity Authentication | Required | Strong authentication, API authentication, device certificates |
| 164.312(e)(1) | Transmission Security | Addressable | TLS validation, VPN testing, encrypted messaging |

#### Physical Safeguards (45 CFR 164.310)

| Section | Standard | R/A | Pentest Relevance |
|---------|----------|-----|-------------------|
| 164.310(a) | Facility Access Controls | Required | Badge access, physical security testing |
| 164.310(b) | Workstation Use | Required | Screen lock, clean desk |
| 164.310(c) | Workstation Security | Required | Endpoint protection, hardened images |
| 164.310(d) | Device and Media Controls | Required | Asset inventory, secure disposal |

#### HIPAA 2025 Proposed Rule Updates

- **Penetration testing:** Required at least once every 12 months
- **Vulnerability scanning:** Required at least every 6 months
- **Network segmentation:** Now explicitly required
- **System restoration:** Within 72 hours of incident
- **Testing by qualified persons** with appropriate cybersecurity knowledge
- Shift from documentation-based to demonstration-based compliance

---

### 3.4 ISO 27001:2022 Control Mappings

#### Control Structure Overview

ISO 27001:2022 contains **93 controls** organized into 4 themes:

| Theme | Control Range | Count |
|-------|--------------|-------|
| Organizational Controls | A.5.1 - A.5.37 | 37 |
| People Controls | A.6.1 - A.6.8 | 8 |
| Physical Controls | A.7.1 - A.7.14 | 14 |
| Technological Controls | A.8.1 - A.8.34 | 34 |

#### Technological Controls (A.8.x) - Complete List

| Control | Name | Pentest Relevance |
|---------|------|-------------------|
| A.8.1 | User Endpoint Devices | Endpoint security validation |
| A.8.2 | Privileged Access Rights | Privilege escalation testing |
| A.8.3 | Information Access Restriction | Access control testing |
| A.8.4 | Access to Source Code | Source code access controls |
| A.8.5 | Secure Authentication | Authentication mechanism testing |
| A.8.6 | Capacity Management | DoS/resource exhaustion testing |
| A.8.7 | Protection Against Malware | Malware defense validation |
| **A.8.8** | **Management of Technical Vulnerabilities** | **Primary: vulnerability scanning, assessment, and patching validation** |
| A.8.9 | Configuration Management | Misconfiguration testing |
| A.8.10 | Information Deletion | Secure deletion validation |
| A.8.11 | Data Masking | Data masking effectiveness |
| A.8.12 | Data Leakage Prevention | DLP bypass testing |
| A.8.13 | Information Backup | Backup integrity testing |
| A.8.14 | Redundancy of Information Processing Facilities | Redundancy validation |
| A.8.15 | Logging | Log completeness and integrity |
| A.8.16 | Monitoring Activities | Detection capability testing |
| A.8.17 | Clock Synchronization | Time synchronization validation |
| A.8.18 | Use of Privileged Utility Programs | Privileged tool access controls |
| A.8.19 | Installation of Software on Operational Systems | Software installation controls |
| **A.8.20** | **Networks Security** | **Network penetration testing: firewall resilience, segmentation, lateral movement** |
| A.8.21 | Security of Network Services | Network service security testing |
| A.8.22 | Segregation of Networks | Network segmentation validation |
| A.8.23 | Web Filtering | Web filter bypass testing |
| A.8.24 | Use of Cryptography | Cryptographic implementation testing |
| A.8.25 | Secure Development Life Cycle | SDLC security review |
| A.8.26 | Application Security Requirements | Application security testing |
| A.8.27 | Secure System Architecture and Engineering Principles | Architecture security review |
| A.8.28 | Secure Coding | Code review and injection testing |
| **A.8.29** | **Security Testing in Development and Acceptance** | **Mandates security tests during development: DAST, SAST, pentest before go-live** |
| A.8.30 | Outsourced Development | Third-party code security review |
| A.8.31 | Separation of Development, Test and Production Environments | Environment isolation testing |
| A.8.32 | Change Management | Change control validation |
| A.8.33 | Test Information | Test data protection |
| A.8.34 | Protection of Information Systems During Audit Testing | Audit testing controls |

#### Key Organizational Controls for Pentest Mapping

| Control | Name | Relevance |
|---------|------|-----------|
| A.5.7 | Threat Intelligence | Threat-informed testing approach |
| A.5.24 | Information Security Incident Management Planning | Incident response testing |
| A.5.25 | Assessment and Decision on Information Security Events | Security event evaluation |
| A.5.26 | Response to Information Security Incidents | Incident response validation |
| A.5.27 | Learning From Information Security Incidents | Post-incident improvement |
| A.5.35 | Independent Review of Information Security | Independent security assessments (penetration testing) |
| A.5.36 | Compliance with Policies, Rules and Standards | Compliance validation through testing |

#### ISO 27001 Pentest Report Requirements for Auditors

- Signed pentest report dated within 12 months
- Scope, methodology, tester qualifications, and findings with severity ratings
- Remediation log showing closure of high-risk findings with retesting evidence
- Documented testing plan with Rules of Engagement
- Findings mapped to specific Annex A controls
- Reports feed directly into: Risk Register, Risk Treatment Plan, Statement of Applicability (SoA)

---

### 3.5 Cross-Framework Compliance Comparison

| Requirement Area | PCI-DSS 4.0 | SOC 2 | HIPAA | ISO 27001 |
|-----------------|-------------|-------|-------|-----------|
| **Pentest Required?** | Yes (Req 11.4) | Not explicitly, but expected | Yes (proposed 2025 rule) | Recommended (A.8.8, A.8.29) |
| **Frequency** | Annual + after changes | Per auditor expectation | Annual minimum | Per risk assessment |
| **External Testing** | Required | Expected | Required (proposed) | Recommended |
| **Internal Testing** | Required | Expected | Required (proposed) | Recommended |
| **Vuln Scanning** | Quarterly (internal + ASV) | Expected (CC7.1) | Every 6 months (proposed) | Per A.8.8 |
| **Remediation** | Required + retesting | Evidence of closure | Required | Required |
| **Segmentation Testing** | Required if CDE isolated | N/A | Network segmentation required | A.8.22 |
| **Report Mapping** | To PCI requirements | To Trust Service Criteria | To safeguard sections | To Annex A controls |
| **Tester Independence** | Required | Expected | Required (proposed) | Recommended (A.5.35) |

---

## 4. Pentest Report Structure

### 4.1 Standard Report Sections

A professional penetration test report contains the following sections:

#### Section 1: Cover Page
- Client name and logo
- Report title ("Penetration Test Report")
- Testing period dates
- Report date
- Classification level (Confidential)
- Testing organization name
- Report version number

#### Section 2: Table of Contents
- Automated, linked table of contents

#### Section 3: Executive Summary (1-2 pages)
- **Purpose:** Help non-technical leaders understand findings and take strategic action
- **Contents:**
  - Engagement overview (what was tested, when, by whom)
  - Overall risk rating/posture assessment
  - Key findings summary (count by severity)
  - Critical/High findings highlighted with business impact
  - Strategic recommendations
  - Positive findings (what worked well)
- **Audience:** C-suite, board members, compliance officers

#### Section 4: Scope and Methodology
- **Scope Definition:**
  - IP addresses, domains, applications tested
  - In-scope vs out-of-scope systems
  - Testing type (black-box, gray-box, white-box)
- **Methodology:**
  - Framework used (PTES, OWASP WSTG, NIST 800-115)
  - Testing approach and phases
  - Tools used (with versions)
  - Testing limitations and constraints
- **Rules of Engagement:**
  - Testing windows
  - Emergency contacts
  - Restricted activities

#### Section 5: Finding Summary
- **Finding Count by Severity:**

| Severity | Count |
|----------|-------|
| Critical | X |
| High | X |
| Medium | X |
| Low | X |
| Informational | X |
| **Total** | **X** |

- Risk heatmap or severity distribution chart
- Finding categories breakdown

#### Section 6: Detailed Findings (Individual Finding Format)

Each finding is documented with the following structure:

```
┌─────────────────────────────────────────────────────────────┐
│ FINDING: [Finding Title]                                     │
├─────────────────────────────────────────────────────────────┤
│ Finding ID:        VULN-001                                  │
│ Severity:          Critical / High / Medium / Low / Info     │
│ CVSS 3.1 Score:    9.8                                       │
│ CVSS Vector:       CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/   │
│                    I:H/A:H                                   │
│ CWE ID:            CWE-89 (SQL Injection)                    │
│ OWASP Category:    A03:2021 - Injection                      │
│ Affected Asset:    https://app.example.com/api/users         │
│ Status:            Open / Remediated / Risk Accepted         │
├─────────────────────────────────────────────────────────────┤
│ DESCRIPTION                                                  │
│ Detailed technical description of the vulnerability,         │
│ including context and how it was discovered.                 │
├─────────────────────────────────────────────────────────────┤
│ IMPACT                                                       │
│ Business and technical impact if exploited.                  │
│ What data/systems are at risk.                               │
├─────────────────────────────────────────────────────────────┤
│ EVIDENCE / PROOF OF CONCEPT                                  │
│ - Screenshots of exploitation                               │
│ - HTTP request/response pairs                               │
│ - Command output                                            │
│ - Step-by-step reproduction instructions                    │
├─────────────────────────────────────────────────────────────┤
│ REMEDIATION                                                  │
│ - Immediate fix (short-term)                                │
│ - Recommended solution (medium-term)                        │
│ - Strategic improvement (long-term)                         │
│ - Code-level fix examples where applicable                  │
├─────────────────────────────────────────────────────────────┤
│ REFERENCES                                                   │
│ - CVE IDs if applicable                                     │
│ - OWASP Testing Guide reference                            │
│ - Vendor advisories                                         │
│ - Compliance mapping (PCI-DSS, SOC2, HIPAA, ISO 27001)     │
└─────────────────────────────────────────────────────────────┘
```

#### Section 7: Remediation Summary
- Prioritized remediation roadmap
- Short-term fixes (0-30 days): Critical and High findings
- Medium-term improvements (30-90 days): Medium findings
- Long-term strategic changes (90+ days): Architecture improvements
- Ownership assignment recommendations

#### Section 8: Compliance Mapping
- Findings mapped to applicable compliance frameworks
- Gap analysis against relevant standards
- Compliance impact assessment

#### Section 9: Appendices
- Tool output and raw scan results
- Full vulnerability scan reports
- Network diagrams
- Change logs and artifact listings
- Tester credentials and certifications
- Glossary of terms

---

### 4.2 CVSS 3.1 Scoring Methodology

#### Metric Groups

**Base Metrics (Mandatory) - Intrinsic vulnerability characteristics:**

| Metric | Values | Description |
|--------|--------|-------------|
| **Attack Vector (AV)** | Network (N), Adjacent (A), Local (L), Physical (P) | How the vulnerability is exploited. Network = remotely exploitable |
| **Attack Complexity (AC)** | Low (L), High (H) | Conditions beyond attacker's control needed for exploitation |
| **Privileges Required (PR)** | None (N), Low (L), High (H) | Privilege level needed before exploitation |
| **User Interaction (UI)** | None (N), Required (R) | Whether a user must participate in the attack |
| **Scope (S)** | Unchanged (U), Changed (C) | Whether the vulnerability can affect resources beyond its security scope |
| **Confidentiality Impact (C)** | None (N), Low (L), High (H) | Impact on data confidentiality |
| **Integrity Impact (I)** | None (N), Low (L), High (H) | Impact on data integrity |
| **Availability Impact (A)** | None (N), Low (L), High (H) | Impact on system availability |

**Temporal Metrics (Optional) - Current state of exploit techniques:**

| Metric | Values | Description |
|--------|--------|-------------|
| **Exploit Code Maturity (E)** | Not Defined (X), Unproven (U), Proof-of-Concept (P), Functional (F), High (H) | Availability and sophistication of exploits |
| **Remediation Level (RL)** | Not Defined (X), Official Fix (O), Temporary Fix (T), Workaround (W), Unavailable (U) | Type of fix available |
| **Report Confidence (RC)** | Not Defined (X), Unknown (U), Reasonable (R), Confirmed (C) | Confidence in vulnerability details |

**Environmental Metrics (Optional) - Organizational context:**

| Metric | Values | Description |
|--------|--------|-------------|
| **Confidentiality Requirement (CR)** | Not Defined (X), Low (L), Medium (M), High (H) | Organizational importance of confidentiality |
| **Integrity Requirement (IR)** | Not Defined (X), Low (L), Medium (M), High (H) | Organizational importance of integrity |
| **Availability Requirement (AR)** | Not Defined (X), Low (L), Medium (M), High (H) | Organizational importance of availability |
| **Modified Base Metrics** | Same values as Base | Customized base metrics for organization's environment |

#### CVSS Vector String Format

```
CVSS:3.1/AV:[N|A|L|P]/AC:[L|H]/PR:[N|L|H]/UI:[N|R]/S:[U|C]/C:[N|L|H]/I:[N|L|H]/A:[N|L|H]
```

**Example:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = Score 9.8 (Critical)

#### Severity Rating Scale

| Rating | CVSS Score Range | Description | Typical Remediation Timeline |
|--------|-----------------|-------------|------------------------------|
| **None** | 0.0 | No security impact | N/A |
| **Low** | 0.1 - 3.9 | Minor impact, difficult to exploit | 90+ days |
| **Medium** | 4.0 - 6.9 | Moderate impact, may require specific conditions | 30-90 days |
| **High** | 7.0 - 8.9 | Significant impact, relatively easy to exploit | 7-30 days |
| **Critical** | 9.0 - 10.0 | Severe impact, trivial to exploit remotely | Immediate (0-7 days) |

#### Common CVSS Score Examples

| Vulnerability Type | Typical CVSS Vector | Score | Severity |
|-------------------|---------------------|-------|----------|
| Unauthenticated RCE | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 | Critical |
| SQL Injection (data extraction) | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 9.1 | Critical |
| Stored XSS (admin context) | AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N | 8.7 | High |
| IDOR (data exposure) | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 6.5 | Medium |
| Missing security headers | AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N | 3.1 | Low |
| Information disclosure (version) | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | 5.3 | Medium |
| CSRF (state change) | AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N | 6.5 | Medium |
| Privilege escalation (local) | AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | 7.8 | High |
| Default credentials | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 | Critical |
| Weak TLS configuration | AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N | 5.9 | Medium |

---

## 5. Cross-Reference: Vulnerability Types to Compliance

### 5.1 Vulnerability-to-Compliance Mapping Matrix

| Vulnerability Type | OWASP WSTG | PCI-DSS 4.0 | SOC 2 | HIPAA | ISO 27001 |
|-------------------|------------|-------------|-------|-------|-----------|
| **SQL Injection** | WSTG-INPV-05 | 6.2.4 (Injection) | CC6.1, CC5.2 | 164.312(a)(1) | A.8.26, A.8.28 |
| **XSS (Reflected/Stored)** | WSTG-INPV-01/02 | 6.2.4 (Data attacks) | CC6.1 | 164.312(a)(1) | A.8.26, A.8.28 |
| **CSRF** | WSTG-SESS-05 | 6.2.4 (Data attacks) | CC6.1 | 164.312(a)(1) | A.8.26 |
| **Broken Authentication** | WSTG-ATHN-01-10 | 8.2, 8.3, 8.6 | CC6.1, CC6.2 | 164.312(d) | A.8.5 |
| **Broken Access Control / IDOR** | WSTG-ATHZ-01-04 | 6.2.4 (Access control) | CC6.1, CC6.3 | 164.312(a)(1), 164.308(a)(4) | A.8.3 |
| **Security Misconfiguration** | WSTG-CONF-01-11 | 2.2, 6.2.4 | CC6.1, CC8.1 | 164.312(a)(1) | A.8.9 |
| **Sensitive Data Exposure** | WSTG-CRYP-01-04 | 3.4, 3.5, 4.2 | CC6.1, CC6.7 | 164.312(e)(1), 164.312(a)(2)(iv) | A.8.24 |
| **XML External Entities (XXE)** | WSTG-INPV-07 | 6.2.4 (Injection) | CC6.1 | 164.312(a)(1) | A.8.26 |
| **SSRF** | WSTG-INPV-19 | 6.2.4 (Injection) | CC6.1 | 164.312(a)(1) | A.8.26 |
| **Command Injection** | WSTG-INPV-12 | 6.2.4 (Injection) | CC6.1 | 164.312(a)(1) | A.8.28 |
| **Weak Cryptography** | WSTG-CRYP-01-04 | 4.2, 6.2.4 (Crypto) | CC6.1, CC6.7 | 164.312(e)(1) | A.8.24 |
| **Session Management Flaws** | WSTG-SESS-01-09 | 6.2.4 | CC6.1 | 164.312(a)(2)(iii) | A.8.5 |
| **Missing Security Headers** | WSTG-CONF-07 | 6.2.4 | CC6.1 | 164.312(a)(1) | A.8.9 |
| **File Upload Vulnerabilities** | WSTG-BUSL-08/09 | 6.2.4 (Business logic) | CC6.8 | 164.312(a)(1) | A.8.7 |
| **Privilege Escalation** | WSTG-ATHZ-03 | 6.2.4 (Access control) | CC6.1, CC6.3 | 164.308(a)(4) | A.8.2 |
| **Default Credentials** | WSTG-ATHN-02 | 2.1, 8.6 | CC6.1, CC6.2 | 164.312(d) | A.8.5 |
| **Subdomain Takeover** | WSTG-CONF-10 | 11.4 | CC6.1 | 164.312(a)(1) | A.8.20 |
| **CORS Misconfiguration** | WSTG-CLNT-07 | 6.2.4 | CC6.1 | 164.312(a)(1) | A.8.26 |
| **Directory Traversal / LFI** | WSTG-ATHZ-01 | 6.2.4 (Injection) | CC6.1 | 164.312(a)(1) | A.8.3 |
| **Information Disclosure** | WSTG-INFO-05, WSTG-ERRH-01/02 | 6.5 | CC6.1 | 164.312(a)(1) | A.8.9, A.8.15 |
| **Insufficient Logging** | WSTG-ERRH-01 | 10.1-10.7 | CC7.1, CC7.2 | 164.312(b) | A.8.15, A.8.16 |
| **Insecure Deserialization** | WSTG-INPV-11 | 6.2.4 | CC6.1 | 164.312(a)(1) | A.8.28 |
| **SSTI** | WSTG-INPV-18 | 6.2.4 (Injection) | CC6.1 | 164.312(a)(1) | A.8.28 |
| **Clickjacking** | WSTG-CLNT-09 | 6.2.4 | CC6.1 | 164.312(a)(1) | A.8.26 |
| **Weak TLS/SSL** | WSTG-CRYP-01 | 4.2.1 | CC6.7 | 164.312(e)(1) | A.8.24 |
| **Open Redirect** | WSTG-CLNT-04 | 6.2.4 | CC6.1 | 164.312(a)(1) | A.8.26 |
| **Network Segmentation Failure** | N/A (network-layer) | 11.4.5 | CC6.6 | 164.312(a)(1) | A.8.22 |
| **Unpatched Software** | WSTG-CONF-02 | 6.3.3 | CC7.1 | 164.308(a)(1) | A.8.8 |
| **Cloud Storage Exposure** | WSTG-CONF-11 | 11.4 | CC6.1 | 164.312(a)(1) | A.8.3 |

### 5.2 How Pentest Findings Map to Compliance Violations

#### Finding Impact Chain

```
Pentest Finding
    ├── Vulnerability Description (OWASP WSTG reference)
    ├── CWE Classification (weakness type)
    ├── CVSS Score (risk quantification)
    ├── Business Impact (data exposure, system compromise)
    └── Compliance Violations
         ├── PCI-DSS: Specific requirement violated
         ├── SOC 2: Trust Service Criteria not met
         ├── HIPAA: Safeguard section non-compliance
         └── ISO 27001: Annex A control failure
```

#### Example Compliance Impact Mapping

**Finding:** SQL Injection in User Login Form (CVSS 9.8 Critical)

| Framework | Violation | Description |
|-----------|-----------|-------------|
| PCI-DSS | Req 6.2.4 | Application not protected against injection attacks |
| PCI-DSS | Req 11.4 | Penetration test identified exploitable vulnerability |
| SOC 2 | CC6.1 | Logical access controls ineffective |
| SOC 2 | CC5.2 | Control activities failed to prevent exploitation |
| HIPAA | 164.312(a)(1) | Access control failed to prevent unauthorized access to ePHI |
| HIPAA | 164.308(a)(1) | Risk management process failed to identify/mitigate risk |
| ISO 27001 | A.8.26 | Application security requirements not met |
| ISO 27001 | A.8.28 | Secure coding practices not followed |
| ISO 27001 | A.8.8 | Technical vulnerability not identified/remediated |

---

## Appendix A: Methodology Selection Guide

| Methodology | Best For | Coverage | Prescriptiveness |
|-------------|----------|----------|------------------|
| **PTES** | Full-scope penetration tests | End-to-end lifecycle | High (detailed technical guidance) |
| **OWASP WSTG** | Web application testing | Application-layer depth | Very High (specific test cases) |
| **NIST SP 800-115** | Government/regulated environments | Broad assessment types | Medium (framework-level) |
| **OSSTMM** | Operational security testing | Trust and access controls | High |
| **MITRE ATT&CK** | Threat-informed testing | Adversary emulation | High (TTP-based) |

## Appendix B: Tool Reference

| Phase | Tools | Purpose |
|-------|-------|---------|
| Reconnaissance | Nmap, Amass, theHarvester, Shodan, Maltego | Network/target enumeration |
| Vulnerability Scanning | Nessus, OpenVAS, Qualys, Burp Suite, OWASP ZAP | Automated vulnerability detection |
| Web App Testing | Burp Suite Pro, OWASP ZAP, SQLMap, Nikto, ffuf, Gobuster | Web-specific vulnerability testing |
| Exploitation | Metasploit, Cobalt Strike, custom scripts | Vulnerability exploitation |
| Post-Exploitation | Mimikatz, BloodHound, CrackMapExec, Chisel, Impacket | Lateral movement, privilege escalation |
| Cryptography | testssl.sh, SSLyze, CipherScan | TLS/SSL configuration testing |
| Password Testing | Hashcat, John the Ripper, Hydra, Medusa | Password cracking and brute force |
| Reporting | Dradis, PlexTrac, AttackForge, custom templates | Finding management and report generation |

## Appendix C: CWE Top 25 Most Dangerous Software Weaknesses (Reference)

| Rank | CWE ID | Name | OWASP WSTG Mapping |
|------|--------|------|---------------------|
| 1 | CWE-787 | Out-of-bounds Write | WSTG-INPV-13 |
| 2 | CWE-79 | Cross-site Scripting (XSS) | WSTG-INPV-01/02, WSTG-CLNT-01 |
| 3 | CWE-89 | SQL Injection | WSTG-INPV-05 |
| 4 | CWE-416 | Use After Free | N/A (binary-level) |
| 5 | CWE-78 | OS Command Injection | WSTG-INPV-12 |
| 6 | CWE-20 | Improper Input Validation | WSTG-INPV-* (all) |
| 7 | CWE-125 | Out-of-bounds Read | WSTG-INPV-13 |
| 8 | CWE-22 | Path Traversal | WSTG-ATHZ-01 |
| 9 | CWE-352 | Cross-Site Request Forgery (CSRF) | WSTG-SESS-05 |
| 10 | CWE-434 | Unrestricted Upload of File with Dangerous Type | WSTG-BUSL-08/09 |
| 11 | CWE-862 | Missing Authorization | WSTG-ATHZ-02 |
| 12 | CWE-476 | NULL Pointer Dereference | N/A (binary-level) |
| 13 | CWE-287 | Improper Authentication | WSTG-ATHN-04 |
| 14 | CWE-190 | Integer Overflow/Wraparound | N/A (binary-level) |
| 15 | CWE-502 | Deserialization of Untrusted Data | WSTG-INPV-11 |
| 16 | CWE-77 | Command Injection | WSTG-INPV-12 |
| 17 | CWE-119 | Improper Buffer Operations | WSTG-INPV-13 |
| 18 | CWE-798 | Use of Hard-coded Credentials | WSTG-ATHN-02 |
| 19 | CWE-918 | Server-Side Request Forgery (SSRF) | WSTG-INPV-19 |
| 20 | CWE-306 | Missing Authentication for Critical Function | WSTG-ATHN-04 |
| 21 | CWE-362 | Race Condition | WSTG-BUSL-04 |
| 22 | CWE-269 | Improper Privilege Management | WSTG-ATHZ-03 |
| 23 | CWE-94 | Code Injection | WSTG-INPV-11 |
| 24 | CWE-863 | Incorrect Authorization | WSTG-ATHZ-02 |
| 25 | CWE-276 | Incorrect Default Permissions | WSTG-CONF-09 |

---

## Appendix D: Pentest Finding Severity Decision Tree

```
Is the vulnerability exploitable remotely without authentication?
├── YES → Is the impact to CIA all HIGH?
│   ├── YES → CRITICAL (9.0-10.0)
│   └── NO → Does it affect confidentiality or integrity significantly?
│       ├── YES → HIGH (7.0-8.9)
│       └── NO → MEDIUM (4.0-6.9)
└── NO → Does it require authentication or local access?
    ├── YES → Is the impact significant?
    │   ├── YES → HIGH (7.0-8.9) or MEDIUM (4.0-6.9)
    │   └── NO → LOW (0.1-3.9)
    └── NO → Does it require physical access?
        ├── YES → LOW (0.1-3.9) to MEDIUM (4.0-6.9)
        └── NO → INFORMATIONAL (0.0)
```

---

*Document compiled from: PTES, OWASP WSTG v4.2, NIST SP 800-115, PCI-DSS v4.0, SOC 2 Trust Services Criteria, HIPAA Security Rule (45 CFR 164.308-316), ISO 27001:2022, CVSS v3.1 Specification (FIRST.org)*
