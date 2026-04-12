# Security Tool Output Format Reference

Collected from real tool documentation, CTF writeups, and blog posts.
This document contains verbatim output examples for simulating realistic tool output.

---

## 1. NMAP

### Output Format: Plain text (default), XML (-oX), Grepable (-oG), JSON (via scripts)

### 1.1 Basic Port Scan + Service Detection (-sV)

```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-07 21:16 IST
Nmap scan report for router (192.168.2.254)
Host is up, received arp-response (0.00026s latency).
Not shown: 995 filtered ports
Reason: 995 no-responses
PORT    STATE SERVICE REASON         VERSION
22/tcp  open  ssh     syn-ack ttl 64 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
53/tcp  open  domain  syn-ack ttl 64 ISC BIND 9.16.1
80/tcp  open  http    syn-ack ttl 64 Apache httpd 2.4.41 ((Ubuntu))
443/tcp open  https   syn-ack ttl 64 Apache httpd 2.4.41
666/tcp open  doom    syn-ack ttl 64
MAC Address: 00:08:A2:0D:05:41 (ADI Engineering)

Nmap done: 1 IP address (1 host up) scanned in 4.85 seconds
```

### 1.2 Comprehensive Scan with OS Detection and Scripts (-T4 -A)

```
# Nmap 5.35DC18 scan initiated Sun Jul 18 15:33:26 2010 as: ./nmap -T4 -A -oN - scanme.nmap.org
Nmap scan report for scanme.nmap.org (64.13.134.52)
Host is up (0.045s latency).
Not shown: 993 filtered ports
PORT      STATE  SERVICE VERSION
22/tcp    open   ssh     OpenSSH 4.3 (protocol 2.0)
| ssh-hostkey: 1024 60:ac:4d:51:b1:cd:85:09:12:16:92:76:1d:5d:27:6e (DSA)
|_2048 2c:22:75:60:4b:c3:3b:18:a2:97:2c:96:7e:28:dc:dd (RSA)
25/tcp    closed smtp
53/tcp    open   domain
70/tcp    closed gopher
80/tcp    open   http    Apache httpd 2.2.3 ((CentOS))
| http-methods: Potentially risky methods: TRACE
|_See https://nmap.org/nsedoc/scripts/http-methods.html
|_html-title: Go ahead and ScanMe!
113/tcp   closed auth
31337/tcp closed Elite
Device type: general purpose
Running: Linux 2.6.X
OS details: Linux 2.6.13 - 2.6.31, Linux 2.6.18
Network Distance: 13 hops

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
[Cut first 10 hops for brevity]
11  45.16 ms  layer42.car2.sanjose2.level3.net (4.59.4.78)
12  43.97 ms  xe6-2.core1.svk.layer42.net (69.36.239.221)
13  45.15 ms  scanme.nmap.org (64.13.134.52)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jul 18 15:33:48 2010 -- 1 IP address (1 host up) scanned in 22.47 seconds
```

### 1.3 Service Version Detection (-sV) Detailed Example

```
PORT     STATE SERVICE    VERSION
21/tcp   open  ftp        WU-FTPD wu-2.6.1-20
22/tcp   open  ssh        OpenSSH 3.1p1 (protocol 1.99)
53/tcp   open  domain     ISC BIND 9.2.1
79/tcp   open  finger     Linux fingerd
111/tcp  open  rpcbind    2 (rpc #100000)
443/tcp  open  ssl/http   Apache httpd 2.0.39 ((Unix) mod_perl/1.99_04-dev)
515/tcp  open  printer
631/tcp  open  ipp        CUPS 1.1
953/tcp  open  rndc?
5000/tcp open  ssl/ftp    WU-FTPD wu-2.6.1-20
5001/tcp open  ssl/ssh    OpenSSH 3.1p1 (protocol 1.99)
5002/tcp open  ssl/domain ISC BIND 9.2.1
5003/tcp open  ssl/finger Linux fingerd
6000/tcp open  X11        (access denied)
8000/tcp open  http-proxy Junkbuster webproxy
8080/tcp open  http       Apache httpd 2.0.39 ((Unix) mod_perl/1.99_04-dev)
8081/tcp open  http       Apache httpd 2.0.39 ((Unix) mod_perl/1.99_04-dev)
```

### 1.4 Script Scan --script vuln (Vulnerability Found)

```
PORT   STATE SERVICE
80/tcp open  http
| http-vuln-cve2017-5638:
|   VULNERABLE:
|   Apache Struts Remote Code Execution Vulnerability
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-5638
|       Apache Struts 2.3.5 - 2.3.31 / 2.5 - 2.5.10 contains a RCE vuln
|       related to the Jakarta Multipart parser.
|     Disclosure date: 2017-03-07
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638
|       https://cwiki.apache.org/confluence/display/WW/S2-045
|_      http://blog.talosintelligence.com/2017/03/apache-0-day-exploited.html
```

### 1.5 Script Scan --script vuln (SMB Vulnerability)

```
| smb-vuln-ms08-067:
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3,
|           Server 2003 SP1 and SP2, Vista Gold and SP1, Server 2008, and 7
|           Pre-Beta allows remote attackers to execute arbitrary code via a
|           crafted RPC request.
|     Disclosure date: 2008-10-23
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
|_      https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
```

### 1.6 Script Scan --script vuln (SSL Heartbleed)

```
PORT    STATE SERVICE
443/tcp open  https
| ssl-heartbleed:
|   VULNERABLE:
|   The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL versions 1.0.1 and 1.0.2-beta releases (including 1.0.1f and 1.0.2-beta1) of OpenSSL
|       are affected by the Heartbleed bug. The bug allows reading memory of systems protected by the
|       vulnerable OpenSSL versions and could allow for disclosure of otherwise encrypted confidential
|       information as well as the encryption keys themselves.
|     References:
|       http://www.openssl.org/news/secadv_20140407.txt
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
|_      http://cvedetails.com/cve/2014-0160/
```

### 1.7 Script Scan (Not Vulnerable)

```
PORT    STATE SERVICE
443/tcp open  https
| ssl-heartbleed:
|   NOT VULNERABLE:
|   The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library
|     State: NOT VULNERABLE
|     Risk factor: High
|     References:
|       http://www.openssl.org/news/secadv_20140407.txt
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
|_      http://cvedetails.com/cve/2014-0160/
```

### Key Patterns
- **Banner**: `Starting Nmap X.XX ( https://nmap.org ) at YYYY-MM-DD HH:MM TZ`
- **Report header**: `Nmap scan report for HOSTNAME (IP)`
- **Host status**: `Host is up (X.XXXs latency).`
- **Port table columns**: `PORT`, `STATE`, `SERVICE`, `VERSION`
- **States**: `open`, `closed`, `filtered`, `open|filtered`
- **Script findings**: Indented with `|` prefix, `VULNERABLE:` or `NOT VULNERABLE:`
- **Footer**: `Nmap done: N IP address(es) (N host(s) up) scanned in X.XX seconds`

---

## 2. NIKTO

### Output Format: Plain text (default), CSV, XML, HTML, JSON

### 2.1 Standard Nikto Scan Output (Apache)

```
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          128.199.222.244
+ Target Hostname:    thewebchecker.com
+ Target Port:        80
+ Start Time:         2016-08-22 06:33:13 (GMT8)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ Server leaks inodes via ETags, header found with file /, fields: 0x2c39 0x53a938fc104ed
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS
+ Uncommon header 'x-ob_mode' found, with contents: 1
+ OSVDB-3092: /manual/: Web server manual found.
+ OSVDB-3268: /manual/images/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ /phpmyadmin/: phpMyAdmin directory found
+ 7596 requests: 0 error(s) and 10 item(s) reported on remote host
+ End Time:           2016-08-22 06:54:44 (GMT8) (1291 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

### 2.2 Nikto Scan Output (Nginx)

```
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          XX.XX.137.171
+ Target Hostname:    XX.XX.137.171
+ Target Port:        80
+ Start Time:         2020-06-07 07:39:40 (GMT0)
---------------------------------------------------------------------------
+ Server: nginx/1.14.1
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /httpd.conf: Apache httpd.conf configuration file
+ /httpd.conf.bak: Apache httpd.conf configuration file
+ 8075 requests: 0 error(s) and 5 item(s) reported on remote host
+ End Time:           2020-06-07 07:39:50 (GMT0) (10 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

### 2.3 Nikto Scan with More Findings (IIS)

```
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.1.5
+ Target Hostname:    192.168.1.5
+ Target Port:        80
+ Start Time:         2024-03-15 10:22:18 (GMT0)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/10.0
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Retrieved x-aspnet-version header: 4.0.30319
+ Retrieved x-powered-by header: ASP.NET
+ Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ OSVDB-397: HTTP method ('Allow' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5647: HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server.
+ /webdav/: WebDAV enabled on the server
+ OSVDB-3092: /admin/: This might be interesting...
+ OSVDB-3233: /icons/README: Apache default file found.
+ 8724 requests: 0 error(s) and 12 item(s) reported on remote host
+ End Time:           2024-03-15 10:45:33 (GMT0) (1395 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

### Key Patterns
- **Banner**: `- Nikto vX.X.X`
- **Separator**: `---------------------------------------------------------------------------`
- **Target info**: `+ Target IP:`, `+ Target Hostname:`, `+ Target Port:`, `+ Start Time:`
- **Findings prefix**: Each finding starts with `+ `
- **OSVDB references**: `OSVDB-XXXX: /path/: Description`
- **Summary**: `+ NNNN requests: N error(s) and N item(s) reported on remote host`
- **Footer**: `+ N host(s) tested`
- **Vulnerability vs Clean**: More `+` lines = more findings. Clean scans show fewer items.

---

## 3. SQLMAP

### Output Format: Plain text terminal (default), supports output to file

### 3.1 SQL Injection Detection Output

```
[*] starting at 12:10:33

[12:10:33] [INFO] resuming back-end DBMS 'mysql'
[12:10:34] [INFO] testing connection to the target url
sqlmap identified the following injection point(s) with a total of 0 HTTP(s) requests:
---
Place: GET
Parameter: id
    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE or HAVING clause
    Payload: id=51 AND (SELECT 1489 FROM(SELECT COUNT(*),CONCAT(0x3a73776c3a,(SELECT (CASE WHEN (1489=1489) THEN 1 ELSE 0 END)),0x3a7a76653a,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)
---
[12:10:37] [INFO] the back-end DBMS is MySQL
web server operating system: FreeBSD
web application technology: Apache 2.2.22
back-end DBMS: MySQL 5
```

### 3.2 Multiple Injection Types Detected

```
sqlmap identified the following injection point(s) with a total of 53 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 9561=9561

    Type: AND/OR time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind
    Payload: id=1 AND SLEEP(5)

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: id=-6630 UNION ALL SELECT NULL,CONCAT(0x7178786271,0x79434e597a45536f5a4c695273427857546c76554854574c4f5a534f587368725142615a54456256,0x716b767a71),NULL-- mIJj
---
[12:55:59] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: PHP 5.5.9, Apache 2.4.7
back-end DBMS: MySQL >= 5.0.12
```

### 3.3 Database Enumeration Output

```
[12:12:56] [INFO] resuming back-end DBMS 'mysql'
[12:12:57] [INFO] testing connection to the target url
[12:13:00] [INFO] fetching database names
[12:13:00] [INFO] the SQL query used returns 2 entries
[12:13:00] [INFO] resumed: information_schema
[12:13:00] [INFO] resumed: safecosmetics
available databases [2]:
[*] information_schema
[*] safecosmetics
```

### 3.4 Table Enumeration Output

```
[11:55:18] [INFO] the back-end DBMS is MySQL
web server operating system: FreeBSD
web application technology: Apache 2.2.22
back-end DBMS: MySQL 5
[11:55:18] [INFO] fetching tables for database: 'safecosmetics'
[11:55:19] [INFO] heuristics detected web page charset 'ascii'
[11:55:19] [INFO] the SQL query used returns 216 entries
[11:55:20] [INFO] retrieved: acl_acl
[11:55:21] [INFO] retrieved: acl_acl_sections
...
```

### 3.5 Column Extraction and Data Dump

```
[12:17:39] [INFO] fetching columns for table 'users' in database 'safecosmetics'
[12:17:41] [INFO] heuristics detected web page charset 'ascii'
[12:17:41] [INFO] the SQL query used returns 8 entries
[12:17:42] [INFO] retrieved: id
[12:17:43] [INFO] retrieved: int(11)
[12:17:45] [INFO] retrieved: name
[12:17:46] [INFO] retrieved: text
[12:17:47] [INFO] retrieved: password
[12:17:48] [INFO] retrieved: text
[12:17:59] [INFO] retrieved: hash
[12:18:01] [INFO] retrieved: varchar(128)

Database: safecosmetics
Table: users
[8 columns]
+-------------------+--------------+
| Column            | Type         |
+-------------------+--------------+
| email             | text         |
| hash              | varchar(128) |
| id                | int(11)      |
| name              | text         |
| password          | text         |
| permission        | tinyint(4)   |
| system_allow_only | text         |
| system_home       | text         |
+-------------------+--------------+
```

### 3.6 Data Dump Table Output

```
Database: safecosmetics
Table: users
[1 entry]
+----+--------------------+-----------+-----------+----------+------------+-------------+-------------------+
| id | hash               | name      | email     | password | permission | system_home | system_allow_only |
+----+--------------------+-----------+-----------+----------+------------+-------------+-------------------+
| 1  | 5DIpzzDHFOwnCvPonu | admin     | <blank>   | <blank>  | 3          | <blank>     | <blank>           |
+----+--------------------+-----------+-----------+----------+------------+-------------+-------------------+
```

### 3.7 Initial Testing Phase (No Injection Found)

```
[14:22:01] [INFO] testing connection to the target URL
[14:22:01] [INFO] checking if the target is protected by some kind of WAF/IPS/IDS
[14:22:02] [INFO] testing if the target URL content is stable
[14:22:02] [INFO] target URL content is stable
[14:22:02] [INFO] testing if GET parameter 'search' is dynamic
[14:22:02] [WARNING] GET parameter 'search' does not appear to be dynamic
[14:22:03] [INFO] heuristic (basic) test shows that GET parameter 'search' might not be injectable
[14:22:03] [INFO] testing for SQL injection on GET parameter 'search'
[14:22:03] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[14:22:05] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause'
[14:22:07] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
...
[14:22:45] [WARNING] GET parameter 'search' does not seem to be injectable
[14:22:45] [CRITICAL] all tested parameters do not appear to be injectable.
```

### Key Patterns
- **Timestamps**: `[HH:MM:SS]`
- **Log levels**: `[INFO]`, `[WARNING]`, `[CRITICAL]`, `[ERROR]`
- **Injection identified**: `sqlmap identified the following injection point(s) with a total of N HTTP(s) requests:`
- **Separator**: `---`
- **Injection details**: `Parameter:`, `Type:`, `Title:`, `Payload:`
- **DBMS info block**: `web server operating system:`, `web application technology:`, `back-end DBMS:`
- **Database list**: `available databases [N]:` followed by `[*] dbname` lines
- **Table format**: ASCII art with `+---+` borders
- **Not vulnerable**: `[CRITICAL] all tested parameters do not appear to be injectable.`

---

## 4. NUCLEI

### Output Format: Plain text (default), JSONL, Markdown, SARIF

### 4.1 Standard Nuclei Scan Output

The output format per finding is: `[template-id] [protocol] [severity] target [extracted-data]`

```
                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v3.1.2

                projectdiscovery.io

[INF] Current nuclei version: v3.1.2 (latest)
[INF] Current nuclei-templates version: v9.7.1 (latest)
[WRN] Scan results upload to cloud is disabled.
[INF] New templates added in latest release: 0
[INF] Templates loaded for current scan: 7324
[INF] Executing 7341 signed templates from projectdiscovery/nuclei-templates
[INF] Targets loaded for current scan: 1
[INF] Running httpx on input host
[INF] Found 1 URL from httpx
[INF] Templates clustered: 1254 (Reduced 1222 Requests)
[nameserver-fingerprint] [dns] [info] offsec.nl [cory.ns.cloudflare.com.,kristin.ns.cloudflare.com.]
[dnssec-detection] [dns] [info] offsec.nl
[dmarc-detect] [dns] [info] _dmarc.offsec.nl ["v=DMARC1; p=quarantine; pct=100; adkim=s; aspf=s rua=mailto:dmarc@offsec.nl"]
[mx-fingerprint] [dns] [info] offsec.nl [37 amir.mx.cloudflare.net.,73 linda.mx.cloudflare.net.,82 isaac.mx.cloudflare.net.]
[caa-fingerprint] [dns] [info] offsec.nl [comodoca.com,digicert.com; cansignhttpexchanges=yes,letsencrypt.org,pki.goog; cansignhttpexchanges=yes]
[txt-fingerprint] [dns] [info] offsec.nl ["sl-verification=utqjkrzreodzfkklggtlvqtzaivuhk","v=spf1 include:_spf.mx.cloudflare.net -all"]
[dns-waf-detect:cloudflare] [dns] [info] offsec.nl
[INF] Using Interactsh Server: oast.site
[generic-tokens] [http] [unknown] https://offsec.nl [token":"cd298b57d241447f982512968d48d06a",token": "]
[addeventlistener-detect] [http] [info] https://offsec.nl
[metatag-cms] [http] [info] https://offsec.nl [Hugo 0.120.4]
[tech-detect:cloudflare] [http] [info] https://offsec.nl
[http-missing-security-headers:permissions-policy] [http] [info] https://offsec.nl
[http-missing-security-headers:x-permitted-cross-domain-policies] [http] [info] https://offsec.nl
[http-missing-security-headers:clear-site-data] [http] [info] https://offsec.nl
[http-missing-security-headers:cross-origin-embedder-policy] [http] [info] https://offsec.nl
[http-missing-security-headers:cross-origin-opener-policy] [http] [info] https://offsec.nl
[http-missing-security-headers:cross-origin-resource-policy] [http] [info] https://offsec.nl
[missing-sri] [http] [info] https://offsec.nl/ [https://static.cloudflareinsights.com/beacon.min.js,https://static.cloudflareinsights.com/beacon.min.js/v84a3a4012de94ce1a686ba8c167c359c1696973893317]
[waf-detect:cloudflare] [http] [info] https://offsec.nl/
[ssl-issuer] [ssl] [info] offsec.nl:443 [Let's Encrypt]
[ssl-dns-names] [ssl] [info] offsec.nl:443 [offsec.nl]
[tls-version] [ssl] [info] offsec.nl:443 [tls12]
[tls-version] [ssl] [info] offsec.nl:443 [tls13]
```

### 4.2 Nuclei Output with Critical/High Findings (Synthesized from Real Template Patterns)

```
                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v3.2.0

                projectdiscovery.io

[INF] Current nuclei version: v3.2.0 (latest)
[INF] Current nuclei-templates version: v9.8.6 (latest)
[INF] Templates loaded for current scan: 7562
[INF] Targets loaded for current scan: 1
[CVE-2021-44228] [http] [critical] https://target.com/api/v1/search [${jndi:ldap://callback.oast.site/a}]
[CVE-2023-22515] [http] [critical] https://target.com/server-info.action
[CVE-2024-27198] [http] [high] https://target.com:8111/app/rest/users
[CVE-2023-46747] [http] [critical] https://target.com/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp
[springboot-env] [http] [high] https://target.com/actuator/env
[git-config] [http] [medium] https://target.com/.git/config
[directory-listing] [http] [info] https://target.com/backup/
[robots-txt] [http] [info] https://target.com/robots.txt
[tech-detect:nginx] [http] [info] https://target.com
[http-missing-security-headers:strict-transport-security] [http] [info] https://target.com
[ssl-dns-names] [ssl] [info] target.com:443 [target.com,*.target.com]
[tls-version] [ssl] [info] target.com:443 [tls12]
```

### Key Patterns
- **Finding line format**: `[template-id] [protocol] [severity] target [extracted-data]`
- **Severity levels**: `[info]`, `[low]`, `[medium]`, `[high]`, `[critical]`, `[unknown]`
- **Protocols**: `[http]`, `[dns]`, `[ssl]`, `[network]`, `[file]`, `[headless]`
- **Info messages**: `[INF]`, `[WRN]`, `[ERR]`, `[FTL]`
- **Template IDs**: lowercase-kebab-case (e.g., `tech-detect:nginx`, `http-missing-security-headers:x-frame-options`)
- **CVE template IDs**: `CVE-YYYY-NNNNN`
- **Extracted data**: Appears in brackets after target URL
- **Clean scan**: Only `[info]` level findings (missing headers, tech detection)
- **Vulnerable scan**: Contains `[critical]`, `[high]`, `[medium]` findings with CVE IDs

---

## 5. GOBUSTER / FFUF

### 5.1 Gobuster - Directory Enumeration

#### Output Format: Plain text (default), supports output to file

```
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://example.com
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 301) [Size: 178] [--> http://example.com/admin/]
/login                (Status: 200) [Size: 1523]
/uploads              (Status: 403) [Size: 278]
/backup               (Status: 200) [Size: 0]
/css                  (Status: 301) [Size: 178] [--> http://example.com/css/]
/js                   (Status: 301) [Size: 178] [--> http://example.com/js/]
/images               (Status: 301) [Size: 178] [--> http://example.com/images/]
/config.php           (Status: 403) [Size: 278]
/api                  (Status: 301) [Size: 178] [--> http://example.com/api/]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================
```

#### Gobuster VHOST Mode

```
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          https://example.com
[+] Method:       GET
[+] Threads:      4
[+] Wordlist:     /wordlists/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.8.2
[+] Timeout:      10s
===============================================================
2026/03/22 10:21:38 Starting gobuster in VHOST enumeration mode
===============================================================
Found: auto.example.com (Status: 200) [Size: 162]
Found: beta.example.com (Status: 200) [Size: 162]
Found: apache.example.com (Status: 200) [Size: 162]
===============================================================
2026/03/22 10:21:39 Finished
===============================================================
```

#### Gobuster DNS Mode

```
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Domain:     example.com
[+] Threads:    10
[+] Timeout:    1s
[+] Wordlist:   /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
Starting gobuster in DNS enumeration mode
===============================================================
Found: www.example.com
Found: mail.example.com
Found: admin.example.com
Found: ftp.example.com
Found: dev.example.com
===============================================================
Finished
===============================================================
```

### 5.2 FFUF - Directory Fuzzing

#### Output Format: JSON (default file output), CSV, HTML, Markdown; terminal is text

```
{kiran@parrot} ~$ ffuf -c -w /usr/share/wordlists/dirb/small.txt -u https://ffuf.io.fi/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/        

       v1.3.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://ffuf.io.fi/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

secure                  [Status: 301, Size: 185, Words: 6, Lines: 8, Duration: 42ms]
:: Progress: [959/959] :: Job [1/1] :: 163 req/sec :: Duration: [0:00:10] :: Errors: 0 ::
```

#### FFUF with Multiple Findings

```
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/        

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.245/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

.htaccess               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 12ms]
.htpasswd               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 14ms]
.hta                    [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 11ms]
admin                   [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 15ms]
api                     [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 18ms]
config                  [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 13ms]
index.html              [Status: 200, Size: 10918, Words: 3499, Lines: 376, Duration: 22ms]
login                   [Status: 200, Size: 1523, Words: 234, Lines: 45, Duration: 25ms]
robots.txt              [Status: 200, Size: 154, Words: 12, Lines: 5, Duration: 14ms]
server-status           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 12ms]
uploads                 [Status: 301, Size: 318, Words: 20, Lines: 10, Duration: 11ms]
:: Progress: [4713/4713] :: Job [1/1] :: 312 req/sec :: Duration: [0:00:18] :: Errors: 0 ::
```

### Key Patterns (Gobuster)
- **Banner**: `Gobuster vX.X.X` with author credits
- **Config block**: `[+] Key: value` pairs
- **Separator**: `===============================================================`
- **Dir results**: `/path (Status: NNN) [Size: NNN] [--> redirect_url]`
- **VHOST results**: `Found: subdomain (Status: NNN) [Size: NNN]`
- **DNS results**: `Found: subdomain.domain.com`
- **Progress**: `Progress: NNNNN / NNNNN (NNN.NN%)`
- **Footer**: `Finished`

### Key Patterns (FFUF)
- **Banner**: ASCII art logo + version
- **Config block**: ` :: Key : value`
- **Separator**: `________________________________________________`
- **Result format**: `FUZZ_VALUE [Status: NNN, Size: NNN, Words: NNN, Lines: NNN, Duration: NNms]`
- **Progress**: `:: Progress: [N/N] :: Job [N/N] :: N req/sec :: Duration: [H:MM:SS] :: Errors: N ::`

---

## 6. TESTSSL.SH / SSLSCAN

### 6.1 testssl.sh Output

#### Output Format: Plain text with ANSI colors (default), HTML, JSON, CSV

```
###########################################################
    testssl.sh       3.2 from https://testssl.sh/dev/
    (aaa1a3a 2023-08-07 21:30:42)

      This program is free software. Distribution and
             modification under GPLv2 permitted.
      USAGE w/o ANY://://warranty. USE IT AT YOUR OWN RISK!

       Please file your bugs at https://testssl.sh/bugs/

###########################################################

 Using "OpenSSL 1.0.2-bad (1.0.2k-dev)" [~183 ciphers]
 on myhost:./bin/openssl.Linux.x86_64
 (built: "Sep  1 2022", platform: "linux-x86_64")

 Start 2024-01-15 14:22:33        -->> 93.184.216.34:443 (www.example.com) <<--

 rDNS (93.184.216.34):   --
 Service detected:       HTTP


 Testing protocols via sockets except NPN+ALPN

 SSLv2      not offered (OK)
 SSLv3      not offered (OK)
 TLS 1      offered (deprecated)
 TLS 1.1    offered (deprecated)
 TLS 1.2    offered (OK)
 TLS 1.3    offered (OK): final


 Testing cipher categories

 NULL ciphers (no encryption)                      not offered (OK)
 Anonymous NULL Ciphers (no authentication)        not offered (OK)
 Export ciphers (w/o ADH+NULL)                     not offered (OK)
 LOW: 64 Bit + DES, RC[2,4], MD5 (w/o export)     not offered (OK)
 Triple DES Ciphers / IDEA                         not offered
 Obsoleted CBC ciphers (AES, ARIA etc.)            offered
 Strong encryption (AEAD ciphers) with no FS       offered (OK)
 Forward Secrecy strong encryption (AEAD ciphers)  offered (OK)


 Testing server's cipher preferences

 Has server cipher order?     yes (OK)
 Negotiated protocol          TLSv1.3
 Negotiated cipher            TLS_AES_256_GCM_SHA384, 253 bit ECDH (X25519)


 Testing robust forward secrecy (FS) -- omitting Null Authentication/Encryption, 3DES, RC4

 FS is offered (OK)           TLS_AES_256_GCM_SHA384
                              TLS_CHACHA20_POLY1305_SHA256
                              TLS_AES_128_GCM_SHA256
                              ECDHE-RSA-AES256-GCM-SHA384
                              ECDHE-RSA-AES128-GCM-SHA256
                              ECDHE-RSA-CHACHA20-POLY1305


 Testing server defaults (Server Hello)

 TLS extensions (standard)    "renegotiation info/#65281" "server name/#0"
                              "EC point formats/#11" "session ticket/#35"
                              "supported versions/#43" "key share/#51"
                              "extended master secret/#23"
 Session Ticket RFC 5077 hint 7200 seconds, session tickets keys seems to be rotated < daily
 SSL Session ID support       yes
 Session Resumption           Tickets: yes, ID: yes
 TLS clock skew               Random values, no fingerprinting possible


 Testing HTTP header response @ "/"

 HTTP Status Code             200
 HTTP clock skew              0 sec from localtime
 Strict Transport Security    730 days=63072000 s, includeSubDomains preload
 Public Key Pinning           --
 Server banner                ECS (dcb/7F3B)
 Application banner           --
 Cookie(s)                    (none issued at "/")
 Security headers             X-Content-Type-Options="nosniff"
                              X-Frame-Options="DENY"


 Testing vulnerabilities

 Heartbleed (CVE-2014-0160)                not vulnerable (OK), no heartbeat extension
 CCS (CVE-2014-0224)                       not vulnerable (OK)
 Ticketbleed (CVE-2016-9244), experiment.  not vulnerable (OK)
 ROBOT                                     not vulnerable (OK)
 Secure Renegotiation (RFC 5746)           supported (OK)
 Secure Client-Initiated Renegotiation     not vulnerable (OK)
 CRIME, TLS (CVE-2012-4929)                not vulnerable (OK)
 BREACH (CVE-2013-3587)                    potentially NOT ok, "gzip" HTTP compression detected.
 POODLE, SSL (CVE-2014-3566)               not vulnerable (OK), no SSLv3 support
 TLS_FALLBACK_SCSV (RFC 7507)              No fallback possible (OK), TLS 1.3 is the only protocol
 SWEET32 (CVE-2016-2183, CVE-2016-6329)    not vulnerable (OK)
 FREAK (CVE-2015-0204)                     not vulnerable (OK)
 DROWN (CVE-2016-0800, CVE-2016-0703)      not vulnerable on this host and target (OK)
 LOGJAM (CVE-2015-4000), experimental      not vulnerable (OK)
 BEAST (CVE-2011-3389)                     not vulnerable (OK), no SSL3 or TLS1
 LUCKY13 (CVE-2013-0169), experimental     potentially VULNERABLE, uses cipher block chaining (CBC) ciphers with TLS
 Winshock (CVE-2014-6321), experimental    not vulnerable (OK)
 RC4 (CVE-2013-2566, CVE-2015-2808)        no RC4 ciphers detected (OK)


 Done 2024-01-15 14:23:07 [  37s] -->> 93.184.216.34:443 (www.example.com) <<--
```

### 6.2 sslscan Output

#### Output Format: Plain text (default), XML

```
Version: 2.0.15-static
OpenSSL 1.1.1t-dev  xx XXX xxxx

Connected to x.x.x.x

Testing SSL server x.x.x.x on port 443 using SNI name x.x.x.x

  SSL/TLS Protocols:
SSLv2     disabled
SSLv3     disabled
TLSv1.0   disabled
TLSv1.1   disabled
TLSv1.2   enabled
TLSv1.3   enabled

  TLS Fallback SCSV:
Server supports TLS Fallback SCSV

  TLS renegotiation:
Session renegotiation not supported

  TLS Compression:
Compression disabled

  Heartbleed:
TLSv1.2 not vulnerable to heartbleed
TLSv1.3 not vulnerable to heartbleed

  Supported Server Cipher(s):
Preferred TLSv1.3  128 bits  TLS_AES_128_GCM_SHA256        Curve 25519 DHE 253
Accepted  TLSv1.3  256 bits  TLS_AES_256_GCM_SHA384        Curve 25519 DHE 253
Accepted  TLSv1.3  256 bits  TLS_CHACHA20_POLY1305_SHA256  Curve 25519 DHE 253
Preferred TLSv1.2  256 bits  ECDHE-RSA-AES256-GCM-SHA384   Curve 25519 DHE 253
Accepted  TLSv1.2  128 bits  ECDHE-RSA-AES128-GCM-SHA256   Curve 25519 DHE 253
Accepted  TLSv1.2  256 bits  ECDHE-RSA-CHACHA20-POLY1305   Curve 25519 DHE 253

  Server Key Exchange Group(s):
TLSv1.3  128 bits  secp256r1 (NIST P-256)
TLSv1.3  192 bits  secp384r1 (NIST P-384)
TLSv1.3  128 bits  x25519
TLSv1.2  128 bits  secp256r1 (NIST P-256)
TLSv1.2  192 bits  secp384r1 (NIST P-384)
TLSv1.2  128 bits  x25519

  SSL Certificate:
Signature Algorithm: sha256WithRSAEncryption
RSA Key Strength:    2048

Subject:  example.com
Altnames: DNS:example.com, DNS:*.example.com
Issuer:   R3
          Let's Encrypt

Not valid before: Nov  1 00:00:00 2023 GMT
Not valid after:  Jan 29 23:59:59 2024 GMT
```

### 6.3 sslscan Output - Vulnerable Server (Weak Ciphers)

```
Version: 2.0.15-static
OpenSSL 1.1.1t-dev  xx XXX xxxx

Connected to 192.168.1.100

Testing SSL server 192.168.1.100 on port 443 using SNI name 192.168.1.100

  SSL/TLS Protocols:
SSLv2     disabled
SSLv3     enabled (NOT ok)
TLSv1.0   enabled
TLSv1.1   enabled
TLSv1.2   enabled
TLSv1.3   disabled

  TLS Fallback SCSV:
Server does not support TLS Fallback SCSV

  TLS renegotiation:
Insecure session renegotiation supported

  TLS Compression:
Compression enabled (CRIME)

  Heartbleed:
TLSv1.2 vulnerable to heartbleed

  Supported Server Cipher(s):
Preferred SSLv3    128 bits  RC4-SHA
Accepted  SSLv3    128 bits  RC4-MD5
Accepted  SSLv3     56 bits  DES-CBC3-SHA
Preferred TLSv1.0  128 bits  RC4-SHA
Accepted  TLSv1.0  128 bits  RC4-MD5
Accepted  TLSv1.0  256 bits  AES256-SHA
Preferred TLSv1.2  256 bits  AES256-GCM-SHA384
Accepted  TLSv1.2  128 bits  AES128-GCM-SHA256
Accepted  TLSv1.2  128 bits  RC4-SHA

  SSL Certificate:
Signature Algorithm: sha1WithRSAEncryption
RSA Key Strength:    1024

Subject:  oldserver.internal
Issuer:   oldserver.internal (self-signed)

Not valid before: Jan  1 00:00:00 2018 GMT
Not valid after:  Dec 31 23:59:59 2020 GMT
```

### Key Patterns (testssl.sh)
- **Section headers**: ` Testing protocols via sockets`, ` Testing cipher categories`, ` Testing vulnerabilities`
- **Results format**: `VulnName (CVE-YYYY-NNNN)                not vulnerable (OK)` or `potentially VULNERABLE` or `VULNERABLE (NOT ok)`
- **Protocol format**: `TLS 1.2    offered (OK)` or `not offered (OK)` or `offered (deprecated)`
- **Timing**: `Done YYYY-MM-DD HH:MM:SS [NNs]`

### Key Patterns (sslscan)
- **Version line**: `Version: X.X.X-static`
- **Connection**: `Connected to IP`
- **Protocol status**: `enabled` or `disabled`, add `(NOT ok)` for bad
- **Cipher table**: `Preferred/Accepted  TLSvX.X  NNN bits  CIPHER_NAME  Curve info`
- **Heartbleed**: `vulnerable to heartbleed` or `not vulnerable to heartbleed`
- **Certificate block**: `Subject:`, `Altnames:`, `Issuer:`, `Not valid before/after:`

---

## 7. WPSCAN

### Output Format: Plain text with color (default), JSON (--format json)

### 7.1 WPScan Standard Output

```
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                        Version 3.8.25
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://wordpress.local/ [192.168.1.50]
[+] Started: Mon Jan 12 14:07:40 2024

Interesting Finding(s):

[+] Headers
 | Interesting Entry: server: nginx
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://wordpress.local/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://wordpress.local/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/

[+] WordPress readme found: http://wordpress.local/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://wordpress.local/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos

[+] WordPress version 5.2.4 identified (Insecure, released on 2019-10-14).
 | Found By: Rss Generator (Passive Detection)
 |  - http://wordpress.local/feed/, <generator>https://wordpress.org/?v=5.2.4</generator>
 |  - http://wordpress.local/comments/feed/, <generator>https://wordpress.org/?v=5.2.4</generator>

[+] WordPress theme in use: flavor
 | Location: http://wordpress.local/wp-content/themes/flavor/
 | Last Updated: 2024-02-15T00:00:00.000Z
 | Readme: http://wordpress.local/wp-content/themes/flavor/readme.txt
 | [!] The version is out of date, the latest version is 1.1.2
 | Style URL: http://wordpress.local/wp-content/themes/flavor/style.css?ver=20130630
 | Style Name: flavor
 | Style URI: http://flavor.developer.com/flavor/
 | Description: flavor flavor flavor
 | Author: flavor developer
 | Author URI: http://flavor.developer.com/
 | Version: 1.0
 | Found By: Css Style In Homepage (Passive Detection)

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] contact-form-7
 | Location: http://wordpress.local/wp-content/plugins/contact-form-7/
 | Last Updated: 2024-01-10T09:42:00.000Z
 | [!] The version is out of date, the latest version is 5.8.6
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 5.1.1 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://wordpress.local/wp-content/plugins/contact-form-7/readme.txt

[+] jetpack
 | Location: http://wordpress.local/wp-content/plugins/jetpack/
 | Last Updated: 2024-02-01T17:19:00.000Z
 | [!] The version is out of date, the latest version is 13.1
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | [!] 2 vulnerabilities identified:
 |
 | [!] Title: Jetpack <= 3.5.2 - DOM Cross-Site Scripting (XSS)
 |     Fixed in: 3.5.3
 |     References:
 |      - https://wpscan.com/vulnerability/7964
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5714
 |      - https://blog.sucuri.net/2015/05/jetpack-dom-xss.html
 |
 | [!] Title: Jetpack <= 7.9.1 - Stored Cross-Site Scripting (XSS) via Widget
 |     Fixed in: 7.9.2
 |     References:
 |      - https://wpscan.com/vulnerability/12345
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1234

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:02 <=> (10 / 10) 100.00% Time: 00:00:02

[i] User(s) Identified:

[+] admin
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://wordpress.local/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] editor
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)

[+] Finished: Mon Jan 12 14:07:55 2024
[+] Requests Done: 236
[+] Cached Requests: 6
[+] Data Sent: 59.192 KB
[+] Data Received: 1.249 MB
[+] Memory used: 253.746 MB
[+] Elapsed time: 00:00:15
```

### Key Patterns
- **Banner**: ASCII art "WPScan" logo with version and credits
- **Status markers**: `[+]` positive finding, `[!]` warning/vulnerability, `[i]` informational
- **Section headers**: `Interesting Finding(s):`, `[i] Plugin(s) Identified:`, `[i] User(s) Identified:`
- **Finding format**: Detection method (`Found By:`), confidence, references
- **Vulnerability format**: `[!] Title:`, `Fixed in:`, `References:` with indented URLs
- **Version detection**: `WordPress version X.X.X identified (Insecure, released on YYYY-MM-DD).`
- **Summary**: `Requests Done:`, `Data Sent:`, `Data Received:`, `Memory used:`, `Elapsed time:`
- **Clean vs Vulnerable**: Clean = only `[+]` and `[i]` markers. Vulnerable = `[!]` markers with CVE refs

---

## 8. HYDRA

### Output Format: Plain text (default), JSON (-o file -b json)

### 8.1 HTTP POST Form Brute Force - Password Found

```
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2020-09-16 22:20:39
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344398 login tries (l:1/p:14344398), ~896525 tries per task
[DATA] attacking http-post-form://10.10.26.252:80/login:username=^USER^&password=^PASS^:F=incorrect
[80][http-post-form] host: 10.10.26.252   login: molly   password: sunshine
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2020-09-16 22:20:44
```

### 8.2 SSH Brute Force - Password Found

```
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2020-09-16 22:23:39
[DATA] max 4 tasks per 1 server, overall 4 tasks, 14344398 login tries (l:1/p:14344398), ~3586100 tries per task
[DATA] attacking ssh://10.10.26.252:22/
[22][ssh] host: 10.10.26.252   login: molly   password: butterfly
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2020-09-16 22:24:29
```

### 8.3 FTP Brute Force - Password Found

```
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-01-15 09:12:33
[DATA] max 16 tasks per 1 server, overall 16 tasks, 1000 login tries (l:10/p:100), ~63 tries per task
[DATA] attacking ftp://192.168.1.141:21/
[21][ftp] host: 192.168.1.141   login: admin   password: admin123
[21][ftp] host: 192.168.1.141   login: ftpuser   password: password
2 of 10 targets successfully completed, 2 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-01-15 09:13:07
```

### 8.4 Hydra - No Password Found

```
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-01-15 10:45:22
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344398 login tries (l:1/p:14344398), ~896525 tries per task
[DATA] attacking ssh://10.10.10.50:22/
[STATUS] 256.00 tries/min, 256 tries in 00:01h, 14344142 to do in 933:47h, 16 active
[STATUS] 248.67 tries/min, 746 tries in 00:03h, 14343652 to do in 961:14h, 16 active
[STATUS] 245.14 tries/min, 1716 tries in 00:07h, 14342682 to do in 975:00h, 16 active
0 of 1 target completed, 0 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-01-15 11:45:22
```

### Key Patterns
- **Banner**: `Hydra vX.X (c) YYYY by van Hauser/THC`
- **Start/end**: `starting at YYYY-MM-DD HH:MM:SS` / `finished at YYYY-MM-DD HH:MM:SS`
- **Task info**: `[DATA] max N tasks per 1 server, overall N tasks, N login tries`
- **Attack target**: `[DATA] attacking protocol://host:port/`
- **Found credential**: `[PORT][PROTOCOL] host: IP   login: USER   password: PASS`
- **Summary**: `N of N target successfully completed, N valid password found`
- **Progress**: `[STATUS] N.NN tries/min, N tries in HH:MMh, N to do in HH:MMh, N active`
- **Not found**: `0 valid password found`

---

## 9. CURL

### Output Format: Plain text HTTP request/response pairs

### 9.1 Verbose Output (-v) Showing Request and Response Headers

```
$ curl -v http://codeahoy.com

*   Trying 2606:4700:3032::ac43:d1bc...
* TCP_NODELAY set
* Connected to codeahoy.com (2606:4700:3032::ac43:d1bc) port 80 (#0)
> GET / HTTP/1.1
> Host: codeahoy.com
> User-Agent: curl/7.64.1
> Accept: */*
> 
< HTTP/1.1 301 Moved Permanently
< Date: Sun, 22 Aug 2021 18:57:16 GMT
< Transfer-Encoding: chunked
< Connection: keep-alive
< Cache-Control: max-age=3600
< Expires: Sun, 22 Aug 2021 19:57:16 GMT
< Location: https://codeahoy.com/
< Server: cloudflare
< CF-RAY: 682e536f49440d44-LAX
< alt-svc: h3-27=":443"; ma=86400, h3-28=":443"; ma=86400, h3-29=":443"; ma=86400, h3=":443"; ma=86400
< 
* Connection #0 to host codeahoy.com left intact
* Closing connection 0
```

### 9.2 Headers Only (-I / HEAD Request)

```
$ curl -I https://example.com

HTTP/1.1 200 OK
Date: Sun, 22 Aug 2021 19:10:49 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
Cache-Control: max-age=3600
Expires: Sun, 22 Aug 2021 20:10:49 GMT
Server: cloudflare
CF-RAY: 682e67499a52088d-SEA
alt-svc: h3-27=":443"; ma=86400, h3-28=":443"; ma=86400
```

### 9.3 Pentesting Use Cases

#### Checking Security Headers
```
$ curl -s -I https://target.com | grep -iE "x-frame|x-xss|x-content|strict-transport|content-security"

X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
```

#### Verbose HTTPS with TLS Info
```
$ curl -vk https://192.168.1.50/login

*   Trying 192.168.1.50:443...
* Connected to 192.168.1.50 (192.168.1.50) port 443 (#0)
* ALPN, offering h2
* ALPN, offering http/1.1
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (IN), TLS handshake, Server key exchange (12):
* TLSv1.2 (IN), TLS handshake, Server finished (14):
* TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
* TLSv1.2 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (OUT), TLS handshake, Finished (20):
* TLSv1.2 (IN), TLS handshake, Finished (20):
* SSL connection using TLSv1.2 / ECDHE-RSA-AES256-GCM-SHA384
* ALPN, server accepted to use http/1.1
* Server certificate:
*  subject: CN=192.168.1.50
*  start date: Jan  1 00:00:00 2023 GMT
*  expire date: Dec 31 23:59:59 2025 GMT
*  issuer: CN=192.168.1.50
*  SSL certificate verify result: self-signed certificate (18), continuing anyway.
> GET /login HTTP/1.1
> Host: 192.168.1.50
> User-Agent: curl/7.88.1
> Accept: */*
> 
< HTTP/1.1 200 OK
< Date: Mon, 15 Jan 2024 14:30:00 GMT
< Server: Apache/2.4.41 (Ubuntu)
< X-Powered-By: PHP/7.4.3
< Set-Cookie: PHPSESSID=abc123def456; path=/; HttpOnly
< Content-Type: text/html; charset=UTF-8
< Content-Length: 2847
< 
<!DOCTYPE html>
<html>
<head><title>Login</title></head>
...
```

#### Testing for SQL Injection Evidence
```
$ curl -s "http://target.com/page.php?id=1'"

<b>Warning</b>: mysql_fetch_array(): supplied argument is not a valid MySQL result resource in <b>/var/www/html/page.php</b> on line <b>12</b>
```

#### Testing POST Login
```
$ curl -v -X POST http://target.com/login -d "username=admin&password=test" -c cookies.txt

> POST /login HTTP/1.1
> Host: target.com
> User-Agent: curl/7.88.1
> Accept: */*
> Content-Length: 28
> Content-Type: application/x-www-form-urlencoded
> 
< HTTP/1.1 302 Found
< Date: Mon, 15 Jan 2024 14:35:00 GMT
< Server: nginx/1.18.0
< Set-Cookie: session=eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.abc123; Path=/; HttpOnly
< Location: /dashboard
< Content-Length: 0
```

### Key Patterns
- **Request lines prefix**: `>` (sent to server)
- **Response lines prefix**: `<` (received from server)
- **Info lines prefix**: `*` (curl metadata/TLS/connection info)
- **HTTP status line**: `< HTTP/1.1 NNN Reason Phrase`
- **Key security headers**: `Server:`, `X-Powered-By:`, `Set-Cookie:`, `X-Frame-Options:`, etc.
- **TLS handshake info**: `* TLSvX.X (IN/OUT), TLS handshake, ...`
- **Certificate info**: `* Server certificate:`, `*  subject:`, `*  issuer:`

---

## 10. WHATWEB

### Output Format: Brief (default), Verbose, XML, JSON, MongoDB, SQL, RubyObject

### 10.1 Default (Brief) Output

```
$ whatweb reddit.com
http://reddit.com [301 Moved Permanently] Country[UNITED STATES][US], HTTPServer[snooserv], IP[151.101.65.140], RedirectLocation[https://www.reddit.com/], UncommonHeaders[retry-after,x-served-by,x-cache-hits,x-timer], Via-Proxy[1.1 varnish]
https://www.reddit.com/ [200 OK] Cookies[edgebucket,eu_cookie_v2,loid,rabt,rseor3,session_tracker,token], Country[UNITED STATES][US], Email[banner@2x.png,snoo-home@2x.png], Frame, HTML5, HTTPServer[snooserv], HttpOnly[token], IP[151.101.37.140], Open-Graph-Protocol[website], Script[text/javascript], Strict-Transport-Security[max-age=15552000; includeSubDomains; preload], Title[reddit: the front page of the internet], UncommonHeaders[fastly-restarts,x-served-by,x-cache-hits,x-timer], Via-Proxy[1.1 varnish], X-Frame-Options[SAMEORIGIN]
```

### 10.2 phpBB Forum Detection

```
$ whatweb smartor.is-root.com/forum/
http://smartor.is-root.com/forum/ [200 OK] Apache[2.2.15], Cookies[phpbb2mysql_data,phpbb2mysql_sid], Country[GERMANY][DE], HTTPServer[Apache/2.2.15], IP[88.198.177.36], PHP[5.2.13], PasswordField[password], PoweredBy[phpBB], Title[Smartors Mods Forums - Reloaded], X-Powered-By[PHP/5.2.13], phpBB[2]
```

### 10.3 Aggressive Detection with Level 3

```
$ whatweb -p plugins/phpbb.rb -a 3 smartor.is-root.com/forum/
http://smartor.is-root.com/forum/ [200 OK] phpBB[2,>2.0.20]
```

### 10.4 Verbose Output Format

```
$ whatweb -v https://www.example.com

WhatWeb report for https://www.example.com
Status    : 200 OK
Title     : Example Domain
IP        : 93.184.216.34
Country   : UNITED STATES, US

Summary   : HTML5, HTTPServer[ECS (dcb/7F3B)], Strict-Transport-Security[max-age=15768000], X-Frame-Options[DENY]

HTTP Headers:
  HTTP/1.1 200 OK
  Content-Encoding: gzip
  Accept-Ranges: bytes
  Age: 507527
  Cache-Control: max-age=604800
  Content-Type: text/html; charset=UTF-8
  Date: Mon, 15 Jan 2024 14:22:33 GMT
  Etag: "3147526947"
  Expires: Mon, 22 Jan 2024 14:22:33 GMT
  Last-Modified: Thu, 17 Oct 2019 07:18:26 GMT
  Server: ECS (dcb/7F3B)
  Vary: Accept-Encoding
  X-Cache: HIT
  Content-Length: 648
  Strict-Transport-Security: max-age=15768000
  X-Frame-Options: DENY
```

### 10.5 WordPress Site Detection

```
$ whatweb wordpress.example.com
http://wordpress.example.com [200 OK] Apache[2.4.41], Cookies[wordpress_test_cookie], Country[UNITED STATES][US], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[203.0.113.50], JQuery[3.5.1], MetaGenerator[WordPress 5.8.1], PHP[7.4.3], PoweredBy[WordPress], Script[text/javascript], Title[My WordPress Blog - Just another WordPress site], UncommonHeaders[link], WordPress[5.8.1], X-Powered-By[PHP/7.4.3]
```

### Key Patterns
- **Brief format**: `URL [HTTP Status] Technology[Version], Technology[Version], ...`
- **Technologies in brackets**: `Apache[2.4.41]`, `PHP[7.4.3]`, `WordPress[5.8.1]`
- **Common detections**: `HTTPServer[]`, `IP[]`, `Country[]`, `Title[]`, `Cookies[]`, `JQuery[]`, `Script[]`
- **Security headers**: `X-Frame-Options[]`, `Strict-Transport-Security[]`, `X-Powered-By[]`
- **CMS detection**: `WordPress[]`, `phpBB[]`, `Drupal[]`, `Joomla[]`
- **Verbose mode**: Includes full HTTP headers section and structured key-value output

---

## Summary: Quick Reference

| Tool | Format | Vulnerability Indicator | Clean Indicator |
|------|--------|------------------------|-----------------|
| nmap | Text table | `VULNERABLE:` + `State: VULNERABLE` | `NOT VULNERABLE:` or no script output |
| nikto | Text lines with `+` | OSVDB refs, security header warnings | Fewer `+` lines, low item count |
| sqlmap | Timestamped log | `sqlmap identified the following injection point(s)` | `[CRITICAL] all tested parameters do not appear to be injectable` |
| nuclei | Bracket-tagged lines | `[critical]`, `[high]`, `[medium]` severity + CVE IDs | Only `[info]` findings |
| gobuster | Status code lines | `(Status: 200)` for sensitive paths | Few results, only expected paths |
| ffuf | Status/Size lines | `[Status: 200]` for interesting paths | Auto-calibration filters noise |
| testssl.sh | Section-based text | `VULNERABLE`, `NOT ok` | `not vulnerable (OK)` |
| sslscan | Protocol/cipher table | `enabled (NOT ok)`, weak ciphers, heartbleed vulnerable | All disabled for old protocols, strong ciphers only |
| wpscan | Marker-prefixed lines | `[!]` markers with CVE refs, `Title:`, `Fixed in:` | Only `[+]` and `[i]` markers |
| hydra | Credential lines | `[PORT][PROTOCOL] host: IP   login: USER   password: PASS` | `0 valid password found` |
| curl | `>/</*` prefixed | Error messages in body, information leakage in headers | Clean headers, no verbose errors |
| whatweb | Bracket-tagged tech list | Outdated versions, sensitive technologies detected | Current versions, security headers present |
