#  Deep-Dive Architectural Study: Information Disclosure Vulnerabilities

**Category**: Sensitive Data Leakage & Infrastructure Exposure  
**Severity**: Medium to Critical (Direct Data Breach or Enabling High-Severity Attacks)  
**CWE Mapping**: CWE-200 (Primary), CWE-532, CWE-538, CWE-614  
**OWASP Top 10**: Not directly mapped (falls under A05:2021 Security Misconfiguration)

---

##  What are Information Disclosure Vulnerabilities?

**Information Disclosure** (also known as **Information Leakage**, **Data Leakage**, or **Sensitive Data Exposure**) is when a website unintentionally reveals sensitive information to its users. This includes:

| Information Type | Examples |
|-----------------|----------|
| **User Data** | Usernames, emails, financial information, personal details |
| **Business Data** | Commercial secrets, internal documents, customer databases |
| **Technical Details** | Infrastructure configuration, framework versions, source code |
| **Credentials** | API keys, database passwords, secret keys, encryption tokens |

Unlike other vulnerabilities that **exploit** functionality, information disclosure **reveals** the missing pieces attackers need to construct complex exploits.

### Key Characteristics

| Characteristic | Description |
|----------------|-------------|
| **Often Invisible** | May not cause immediate harm but enables other attacks |
| **Context Dependent** | Severity depends on what attacker can do with leaked info |
| **Enabler Vulnerability** | Frequently the "missing piece" for high-severity attacks |
| **Unintentional** | Website reveals data it shouldn't expose |
| **Diverse Sources** | Can occur through errors, configs, backups, debugging |

### Why They Occur

1. **Failure to remove internal content** from public content (developer comments, debug info)
2. **Insecure configuration** of website and related technologies (debugging enabled, verbose errors)
3. **Default configurations** left unchanged (directory listing, backup files accessible)
4. **Flawed design and behavior** (distinct error messages revealing internal state)
5. **Careless deployment practices** (source code backups, version control exposed)
6. **Insufficient awareness** of what information is considered sensitive

---

##  1. Low-Level Architectural Mechanics

### The Information Disclosure Attack Chain

```text
[ Information Leakage ] 
        │ (Website reveals sensitive data unintentionally)
        ▼
[ Attacker Analysis ] 
        │ (Studies leaked information for attack value)
        ▼
[ Attack Surface Identification ] 
        │ (Identifies new vulnerabilities from leaked config/versions)
        ▼
[ Primary Exploit Execution ] 
        │ (Uses known exploits for disclosed framework version)
        ▼
[ High-Severity Attack Completed ]
```

### The Root Cause: Improper Data Sanitization

Information disclosure occurs when applications:
- **Expose debug information** to users (stack traces, variable values)
- **Return verbose error messages** (database schema, table names)
- **Leave sensitive files accessible** (backup files, config files, .git)
- **Hard-code credentials** in source code (API keys, passwords)
- **Enable directory listing** (reveals file structure)
- **Publish developer comments** (internal notes, TODO comments)
- **Expose version control** (.git, .svn directories accessible)

---

## ⚙️ 2. Comprehensive Information Disclosure Typology Matrix

### Type A: Verbose Error Messages (Stack Trace Disclosure)

**Description**: Application returns full stack traces, database schema, or framework versions in error messages.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Send malformed input to trigger exceptions, study error responses |
| **Impact** | Framework version disclosure (enables known exploit), database schema exposure |
| **Detection** | Test with invalid data types, check error message verbosity |

#### 🎯 Example: Framework Version Disclosure via Stack Trace

**Demo Scenario**: Web application uses Apache Struts and returns full stack trace on error

**Normal Request**:
```http
GET /product?productId=1 HTTP/1.1
Host: shop.example.com
```

**Malicious Payload (Type Manipulation)**:
```http
GET /product?productId="example" HTTP/1.1
Host: shop.example.com
```

**Error Response**:
org.apache.struts2.strutsException: Invalid input type
at com.example.ProductController.getProduct(ProductController.java:45)
at org.apache.struts2.dispatcher.Dispatcher.service(Dispatcher.java:23.3.31)

Apache Struts 2.3.31 detected

**Expected Output**: Generic error message ("Invalid product ID")  
**Actual Output**: Full stack trace with framework version  
**Result**: Attacker knows Struts 2.3.31 is vulnerable to CVE-2016-3089

**Implementation**:
```python
# ❌ VULNERABLE
def get_product(product_id):
    try:
        product = db.get_product(product_id)
        return product
    except Exception as e:
        return f"Error: {e}"  # Returns full exception

# ✅ SECURE
def get_product_secure(product_id):
    try:
        product = db.get_product(product_id)
        return product
    except Exception:
        return "Error: Invalid product ID"  # Generic message
    
    # Log detailed error internally
    logger.error(f"Product error: {product_id}", exc_info=True)
```

---

### Type B: Debug Page Exposure (phpinfo.php Disclosure)

**Description**: Debug or diagnostic pages (phpinfo, admin panels) accessible in production environment.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Discover debug pages via comments, common paths, or content discovery |
| **Impact** | Environment variables, server configuration, secret keys exposed |
| **Detection** | Find comments in HTML, test common debug paths (/phpinfo, /debug, /admin) |

#### 🎯 Example: SECRET_KEY Disclosure via phpinfo.php

**Demo Scenario**: Debug page at `/cgi-bin/phpinfo.php` exposes environment variables

**Discovery (HTML Comment)**:
```html
<!-- Debug page available at /cgi-bin/phpinfo.php -->
```

**Payload**:
```http
GET /cgi-bin/phpinfo.php HTTP/1.1
Host: vulnerable-app.com
```

**Response**:
PHP Version 7.4.3
System: Linux server 5.4.0
SERVER_NAME: vulnerable-app.com

Environment:
SECRET_KEY => w7d9f8a6b5c4d3e2f1a0b9c8d7e6f5a4
DATABASE_URL => postgres://admin:password123@db.internal:5432/app
API_SECRET => 3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c


**Expected Output**: Debug page not accessible (404 or 403)  
**Actual Output**: Full phpinfo output with SECRET_KEY  
**Result**: Attacker can forge JWT tokens, access database

**Implementation**:
```python
# ❌ VULNERABLE
# debug.py accessible in production
@app.route('/cgi-bin/phpinfo.php')
def debug_page():
    return phpinfo()  # Exposes all environment variables

# ✅ SECURE
# debug.py only accessible in development
@app.route('/cgi-bin/phpinfo.php')
def debug_page_secure():
    if not app.config['DEBUG_MODE']:
        return "Not Found", 404
    return phpinfo()
```

---

### Type C: Source Code Disclosure via Backup Files

**Description**: Source code backups (.bak, .backup, .old) accessible in hidden directories.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Discover backup files via robots.txt, content discovery, or common patterns |
| **Impact** | Hard-coded credentials, source logic exposure, vulnerable code patterns |
| **Detection** | Check robots.txt, test common backup extensions (.bak, .backup, .old, .sql) |

#### 🎯 Example: Database Password via ProductTemplate.java.bak

**Demo Scenario**: Java source code backup in `/backup/` directory

**Discovery (robots.txt)**:
User-agent: *
Disallow: /backup/ (or any sensitive folder/endpoint)


**Payload**:
```http
GET /backup/ProductTemplate.java.bak HTTP/1.1
Host: shop.example.com
```

**Source Code Response**:
```java
public class ProductTemplate {
    private static final String DB_HOST = "postgres.internal:5432";
    private static final String DB_USER = "admin";
    private static final String DB_PASSWORD = "SuperSecret123!";
    
    public Connection getConnection() {
        return DriverManager.getConnection(DB_HOST, DB_USER, DB_PASSWORD);
    }
}
```

**Expected Output**: File not accessible (403 or 404)  
**Actual Output**: Full source code with database password  
**Result**: Direct database access, data breach

**Implementation**:
```bash
# ❌ VULNERABLE (Docker deployment)
# backup files not excluded from deployment
COPY . /app

# ✅ SECURE (Docker deployment)
# .dockerignore excludes backup files
COPY . /app
EXCLUDE *.bak
EXCLUDE *.backup
EXCLUDE *.old
EXCLUDE .git
EXCLUDE .env
```

---

### Type D: Authentication Bypass via Information Disclosure

**Description**: Sensitive header names, IP validation logic, or auth tokens disclosed enabling authentication bypass.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Use TRACE method to reveal headers, analyze error messages for auth logic |
| **Impact** | Authentication bypass, admin panel access, privilege escalation |
| **Detection** | Test HTTP methods (TRACE, DEBUG), analyze auth error messages |

#### 🎯 Example: Custom Header Discovery via TRACE

**Demo Scenario**: Admin panel requires `X-Custom-IP-Authorization` header from localhost

**Normal Request**:
```http
GET /admin HTTP/1.1
Host: app.example.com

Response: 403 Forbidden
"Admin panel only accessible from localhost or as administrator"
```

**Payload (TRACE Method)**:
```http
TRACE /admin HTTP/1.1
Host: app.example.com

Response:
X-Custom-IP-Authorization: 192.168.1.100
```

**Bypass Payload**:
```http
# Configure Burp Match/Replace:
Match: (empty)
Replace: X-Custom-IP-Authorization: 127.0.0.1

GET /admin HTTP/1.1
Host: app.example.com
X-Custom-IP-Authorization: 127.0.0.1

Response: 200 OK
[Admin Panel Contents]
```

**Expected Output**: 403 Forbidden (not localhost)  
**Actual Output**: 200 OK (header falsed as localhost)  
**Result**: Admin panel access, user deletion

**Implementation**:
```python
# ❌ VULNERABLE
@app.route('/admin')
def admin_panel(request):
    ip_header = request.headers['X-Custom-IP-Authorization']
    if ip_header == '127.0.0.1' or request.user.is_admin:
        return admin_content()
    return "Forbidden", 403

# ✅ SECURE
@app.route('/admin')
def admin_panel_secure(request, user_session):
    # Use server-side IP detection (NOT client header)
    client_ip = request.remote_addr
    if client_ip == '127.0.0.1' or user_session['is_admin']:
        return admin_content()
    return "Forbidden", 403
```

---

### Type E: Version Control History Disclosure (.git Exposure)

**Description**: Version control directories (.git, .svn, .hg) accessible, revealing commit history with sensitive data.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Access /.git/, download entire repo, analyze commit diffs for removed secrets |
| **Impact** | Past passwords, API keys, configuration secrets from old commits |
| **Detection** | Test common VCS paths (/.git, /.svn, /.hg), check for accessible config files |

#### 🎯 Example: Admin Password via Git Commit Diff

**Demo Scenario**: Git repository at `/.git/` exposes commit with removed password

**Discovery**:
```http
GET /.git/ HTTP/1.1
Host: vulnerable-app.com

Response: 200 OK
[Directory listing of .git contents]
```

**Download Repository**:
```bash
# Linux
wget -r https://YOUR-LAB-ID.web-security-academy.net/.git/

# Explore locally
cd .git
git log
```

**Commit History**:
commit a1b2c3d4e5f6
Author: developer@example.com
Date: 2024-05-15

Remove admin password from config

diff --git admin.conf

    ADMIN_PASSWORD = "HardcodedPassword123!"

    ADMIN_PASSWORD = os.environ['ADMIN_PASSWORD']


**Expected Output**: .git directory not accessible (403)  
**Actual Output**: Full git repo with commit diffs  
**Result**: Admin password "HardcodedPassword123!" recovered

**Implementation**:
```bash
# ❌ VULNERABLE (Nginx config)
# .git directory accessible
server {
    root /var/www/app;
    # No exclusion for .git
}

# ✅ SECURE (Nginx config)
# .git directory blocked
server {
    root /var/www/app;
    
    # Block version control directories
    location ~ /(\.git|\.svn|\.hg) {
        deny all;
        return 404;
    }
}
```

---

### Type F: Directory Listing Enabled

**Description**: Web server configured to show directory contents, revealing file structure and hidden files.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Browse to directories without index files, discover backup/config files |
| **Impact** | File structure exposure, sensitive file discovery |
| **Detection** | Test directories without index.html, check for auto-generated listings |

#### 🎯 Example: Backup Files via Directory Listing

**Demo Scenario**: `/uploads/` directory has no index.html, directory listing enabled

**Payload**:
```http
GET /uploads/ HTTP/1.1
Host: vulnerable-app.com

Response: 200 OK
[Directory Listing]
├── user_uploads/
├── config_backup.json
├── database.sql
├── .env.backup
├── password_list.txt
```

**Expected Output**: 403 Forbidden or custom error  
**Actual Output**: Full directory listing with sensitive files  
**Result**: database.sql, .env.backup, password_list.txt accessible

**Implementation**:
```apache
# ❌ VULNERABLE (Apache config)
# Directory listing enabled
<Directory /var/www/app>
    Options Indexes
</Directory>

# ✅ SECURE (Apache config)
# Directory listing disabled
<Directory /var/www/app>
    Options -Indexes
</Directory>
```

---

### Type G: Developer Comments in Production

**Description**: HTML comments containing internal notes, TODO items, or debug links visible in production.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | View source code, find comments with debug URLs, internal notes |
| **Impact** | Debug page exposure, internal system details, TODO security flaws |
| **Detection** | Inspect HTML source, search for `<!-- -->` comments |

#### 🎯 Example: Debug Link via HTML Comment

**Demo Scenario**: HTML comment reveals debug page location

**Normal Page**:
```html
<!DOCTYPE html>
<html>
<head><title>Home Page</title></head>
<body>
    <!-- TODO: Remove debug page before production -->
    <!-- Debug page: /cgi-bin/phpinfo.php -->
    
    <h1>Welcome to our shop</h1>
</body>
</html>
```

**Payload**:
```http
GET /cgi-bin/phpinfo.php HTTP/1.1
Host: vulnerable-app.com
```

**Expected Output**: Debug comment removed in production  
**Actual Output**: Debug link visible  
**Result**: phpinfo page accessed, SECRET_KEY exposed

**Implementation**:
```html
# ❌ VULNERABLE (Build process)
# Comments not stripped in production
<!-- DEBUG: /cgi-bin/phpinfo.php -->
<h1>Welcome</h1>

# ✅ SECURE (Build process)
# Comments stripped using build tool
<!-- DEBUG: /cgi-bin/phpinfo.php -->  <!-- Removed by strip-comments plugin -->
<h1>Welcome</h1>

# webpack.config.js
module.exports = {
  plugins: [
    new StripCommentPlugin({ pattern: /DEBUG:/ })
  ]
}
```

---

### Type H: API Key / Credential Hard-Coding

**Description**: API keys, passwords, or secrets hard-coded in source code accessible via public endpoints.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Access source code files, JavaScript files, config files |
| **Impact** | API abuse, service compromise, data breach |
| **Detection** | Search for `api_key`, `secret`, `password`, `token` in code |

#### 🎯 Example: AWS Credentials in JavaScript

**Demo Scenario**: Frontend JavaScript exposes AWS credentials

**Payload**:
```http
GET /static/app.js HTTP/1.1
Host: app.example.com
```

**JavaScript Response**:
```javascript
const AWS_CONFIG = {
  region: 'us-east-1',
  accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  bucket: 'user-uploads'
};

function uploadFile(file) {
  const s3 = new AWS.S3(AWS_CONFIG);
  s3.upload({ Bucket: AWS_CONFIG.bucket, Body: file });
}
```

**Expected Output**: No credentials in frontend code  
**Actual Output**: Full AWS credentials exposed  
**Result**: S3 bucket accessed, files downloaded/deleted

**Implementation**:
```javascript
# ❌ VULNERABLE
// config.js
export const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';
export const AWS_SECRET = 'wJalrXUtnFEMI...';

# ✅ SECURE
// config.js - Use environment variables
export const AWS_KEY = process.env.AWS_ACCESS_KEY_ID;
export const AWS_SECRET = process.env.AWS_SECRET_ACCESS_KEY;

# .env (NOT committed to repo)
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI...
```

---

### Type I: Database Error Messages (Schema Disclosure)

**Description**: Database error messages reveal table names, column names, or query structure.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Send malformed SQL input, trigger database errors |
| **Impact** | Database schema exposure, SQL injection enablement |
| **Detection** | Test with invalid SQL syntax, check error message detail |

#### 🎯 Example: Table Names via SQL Error

**Demo Scenario**: Application returns raw SQL error messages

**Payload**:
```http
GET /user?id=" OR "1"="1 HTTP/1.1
Host: vulnerable-app.com

Response: 500 Internal Server Error
```

**Error Message**:
SQL Error: SELECT * FROM users WHERE id = "" OR "1"="1"
Table 'users' has columns: id, username, email, password_hash, admin_level

**Expected Output**: Generic error ("Something went wrong")  
**Actual Output**: Full SQL query with table/column names  
**Result**: Database schema known, SQL injection planned

**Implementation**:
```python
# ❌ VULNERABLE
def get_user(user_id):
    try:
        query = f"SELECT * FROM users WHERE id = '{user_id}'"
        return db.execute(query)
    except Exception as e:
        return f"SQL Error: {e}"

# ✅ SECURE
def get_user_secure(user_id):
    try:
        query = "SELECT * FROM users WHERE id = ?"
        return db.execute(query, [user_id])  # Parameterized query
    except Exception:
        return "Error: Invalid user ID"
    
    logger.error(f"User error: {user_id}", exc_info=True)
```

---

### Type J: Configuration File Exposure

**Description**: Configuration files (.env, config.json, web.config, .htaccess) accessible via web.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Access common config paths, test for file extensions |
| **Impact** | Environment variables, database credentials, API keys exposed |
| **Detection** | Test common config paths (/.env, /config.json, /web.config) |

#### 🎯 Example: .env File Disclosure

**Demo Scenario**: Environment file at `/.env` exposed

**Payload**:
```http
GET /.env HTTP/1.1
Host: vulnerable-app.com
```

**Response**:
DB_HOST=postgres.internal:5432
DB_USER=admin
DB_PASSWORD=SuperSecret123!
API_KEY=sk-1234567890abcdef
JWT_SECRET=w7d9f8a6b5c4d3e2f1a0
ADMIN_EMAIL=admin@company.com


**Expected Output**: .env not accessible (403)  
**Actual Output**: Full environment variables  
**Result**: Database access, JWT forgery, API abuse

**Implementation**:
```nginx
# ❌ VULNERABLE (Nginx config)
# .env file accessible
server {
    root /var/www/app;
}

# ✅ SECURE (Nginx config)
# .env file blocked
server {
    root /var/www/app;
    
    # Block sensitive files
    location ~ /(\.env|\.git|\.svn|config\.json) {
        deny all;
        return 404;
    }
}
```

---

### Type K: Cross-Site Traffic Ledger (CSLT) / HTTP TRACE

**Description**: SERVER allows TRACE method, revealing request headers and authentication tokens.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Send TRACE request to any endpoint, capture headers |
| **Impact** | Session tokens, custom headers, auth logic exposed |
| **Detection** | Test HTTP TRACE method, check for header reflection |

#### 🎯 Example: Session Token via TRACE

**Demo Scenario**: Server reflects all headers via TRACE method

**Payload**:
```http
TRACE / HTTP/1.1
Host: vulnerable-app.com
Cookie: session=abc123xyz
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5c...

Response:
TRACE / HTTP/1.1
Cookie: session=abc123xyz
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5c...
```

**Expected Output**: TRACE method disabled (405)  
**Actual Output**: Full request headers reflected  
**Result**: Session token stolen, JWT stolen

**Implementation**:
```apache
# ❌ VULNERABLE (Apache config)
# TRACE method enabled
<IfModule mod_trace.c>
    TraceEnable On
</IfModule>

# ✅ SECURE (Apache config)
# TRACE method disabled
<IfModule mod_trace.c>
    TraceEnable Off
</IfModule>
```

---

### Type L: Sensitive File Type Enumeration

**Description**: Application reveals existence/absence of files via distinct error messages or response codes.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Test file existence via different response codes, analyze error differences |
| **Impact** | File enumeration, username enumeration, resource discovery |
| **Detection** | Test file paths, compare response codes for existing vs. missing files |

#### 🎯 Example: Username Enumeration via Error Differences

**Demo Scenario**: Login page returns different errors for missing user vs. wrong password

**Payload 1 (Missing User)**:
```http
POST /login HTTP/1.1
Host: app.example.com

username=nonexistent&password=test

Response: 401
"User not found"
```

**Payload 2 (Wrong Password)**:
```http
POST /login HTTP/1.1
Host: app.example.com

username=admin&password=wrong

Response: 401
"Invalid password"
```

**Expected Output**: Same error for both ("Login failed")  
**Actual Output**: Distinct errors revealing user exists  
**Result**: Valid usernames enumerated, brute force targeted

**Implementation**:
```python
# ❌ VULNERABLE
def login(username, password):
    user = db.get_user(username)
    if not user:
        return "User not found"  # Reveals user doesn't exist
    if user.password != password:
        return "Invalid password"  # Reveals user exists
    return "Login successful"

# ✅ SECURE
def login_secure(username, password):
    user = db.get_user(username)
    if not user or user.password != password:
        return "Login failed"  # Generic error for both cases
    return "Login successful"
```

---

### Type M: Backup Database Files (.sql, .dump)

**Description**: Database backup files accessible via web, containing full data exports.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Access common backup paths (/backup.sql, /database.dump, /data.sql) |
| **Impact** | Complete database exposure, all user data stolen |
| **Detection** | Test common backup file extensions (.sql, .dump, .backup) |

#### 🎯 Example: Full Database via backup.sql

**Demo Scenario**: Database backup at `/backup/database.sql` accessible

**Payload**:
```http
GET /backup/database.sql HTTP/1.1
Host: vulnerable-app.com
```

**Response**:
```sql
-- MySQL dump 10.13
-- Database: app_production

CREATE TABLE users (
  id INT PRIMARY KEY,
  username VARCHAR(50),
  email VARCHAR(100),
  password_hash VARCHAR(64)
);

INSERT INTO users VALUES
(1, 'admin', 'admin@company.com', '5f4dcc3b5aa765d61d8327deb882cf99'),
(2, 'carlos', 'carlos@company.com', 'e10adc3949ba59abbe56e05dff20244c');
```

**Expected Output**: backup.sql not accessible (403)  
**Actual Output**: Full database dump  
**Result**: All user accounts, passwords stolen

**Implementation**:
```bash
# ❌ VULNERABLE (Deployment script)
# Backup files copied to web root
cp /var/backups/database.sql /var/www/app/backup.sql

# ✅ SECURE (Deployment script)
# Backup files stored outside web root
cp /var/backups/database.sql /varSecure/backups/database.sql
chown root:root /varSecure/backups/database.sql
chmod 600 /varSecure/backups/database.sql
```

---

### Type N: SSL/TLS Certificate Disclosure

**Description**: SSL certificates accessible, revealing internal hostnames, organization details, past keys.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Extract certificate via SSL handshake, analyze certificate details |
| **Impact** | Internal infrastructure mapping, organization details, past vulnerabilities |
| **Detection** | Use `openssl s_client`, check certificate CommonName (CN) and Organization (O) |

#### 🎯 Example: Internal Hostnames via Certificate

**Demo Scenario**: SSL certificate reveals internal server names

**Payload**:
```bash
openssl s_client -connect vulnerable-app.com:443 -showcerts
```

**Certificate Response**:
Subject: CN=vulnerable-app.com, O=Company Inc, C=US

Issuer: CN=DigiCert TLS RSA SHA256 2020 CA1

X509v3 Extension: subjectAltName
DNS:vulnerable-app.com
DNS:internal-db.company.local
DNS:admin-portal.company.local
DNS:backup-server.company.local

**Expected Output**: Certificate shows only public domain  
**Actual Output**: Certificate reveals internal infrastructure  
**Result**: Internal servers discovered for SSRF attacks

**Implementation**:
```bash
# ❌ VULNERABLE (Certificate generation)
# Certificate includes internal hosts
openssl req -new -x509 -keyout key.pem -out cert.pem -days 365 \
  -subj "/CN=vulnerable-app.com" \
  -addext "subjectAltName = DNS:vulnerable-app.com, DNS:internal-db.company.local"

# ✅ SECURE (Certificate generation)
# Certificate only includes public domains
openssl req -new -x509 -keyout key.pem -out cert.pem -days 365 \
  -subj "/CN=vulnerable-app.com" \
  -addext "subjectAltName = DNS:vulnerable-app.com"
```

---

### Type O: Log File Exposure

**Description**: Application log files (.log, logs/) accessible via web, containing sensitive data.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Access log paths (/logs/app.log, /var/log/access.log) |
| **Impact** | User data in logs, error details, API calls exposed |
| **Detection** | Test common log paths, check for accessible .log files |

#### 🎯 Example: User Data in access.log

**Demo Scenario**: Access log at `/logs/access.log` exposed

**Payload**:
```http
GET /logs/access.log HTTP/1.1
Host: vulnerable-app.com
```

**Response**:
2024-06-20 10:23:45 GET /user?id=123 Cookie: session=abc123
2024-06-20 10:24:12 POST /login username=admin&password=Secret123
2024-06-20 10:25:33 GET /api/users?token=sk-1234567890abcdef
2024-06-20 10:26:01 ERROR: Database connection failed - password=SuperSecret123!

**Expected Output**: Log files not accessible (403)  
**Actual Output**: Full access logs with credentials  
**Result**: Passwords, API tokens, session IDs stolen

**Implementation**:
```nginx
# ❌ VULNERABLE (Nginx config)
# Log directory accessible
server {
    root /var/www/app;
    # No exclusion for /logs
}

# ✅ SECURE (Nginx config)
# Log directory blocked
server {
    root /var/www/app;
    
    # Block log files
    location /logs {
        deny all;
        return 404;
    }
    
    location ~ \.log$ {
        deny all;
        return 404;
    }
}
```

---

## 🛠️ 3. Testing & Detection Framework

### A. Content Discovery (Finding Hidden Files)

```bash
# Step 1: Check robots.txt
GET /robots.txt

# Step 2: Find HTML comments
Burp Suite → Target → Site map → Right-click domain
Engagement tools → Find comments

# Step 3: Discover content
Engagement tools → Discover content
Launch session to find hidden directories

# Step 4: Test common paths
/backup/
/.git/
/.env
/config.json
/phpinfo.php
/debug
/admin
/logs/
```

### B. Error Message Testing

| Test Input | Expected Response |
|------------|-------------------|
| Invalid type: `productId="string"` | Stack trace with framework version |
| SQL injection: `id=" OR "1"="1` | Database schema in error |
| Missing file: `/nonexistent.php` | Distinct error vs. existing file |
| Invalid auth: `username=nonexistent` | "User not found" (enumeration) |

### C. File Extension Testing

```bash
# Test backup extensions
/product.jsp.bak
/product.jsp.backup
/product.jsp.old
/product.jsp.txt
/database.sql
/database.dump
/.env
/.git/config
/web.config
.htaccess
```

### D. HTTP Method Testing

```bash
# Test TRACE method (header reflection)
TRACE /admin HTTP/1.1

# Test DEBUG method
DEBUG / HTTP/1.1

# Test unexpected methods
GET /admin HTTP/1.1
OPTIONS /admin HTTP/1.1
```

---

## 🛡️ 4. Defensive Engineering & Remediation

### ✅ Primary Defense: Generic Error Messages

```python
# ❌ VULNERABLE
except Exception as e:
    return f"Error: {e}"  # Returns full exception

# ✅ SECURE
except Exception:
    return "Error: Something went wrong"  # Generic message
    logger.error(f"Detailed error", exc_info=True)  # Log internally
```

---

### ✅ Secondary Defense: Disable Debug in Production

```python
# ❌ VULNERABLE
app.run(debug=True)  # Debug enabled in production

# ✅ SECURE
app.run(debug=False)  # Debug disabled in production

# Environment-based
app.run(debug=os.environ['DEBUG_MODE'] == 'true')
```

---

### ✅ Third Defense: Block Sensitive Files

```nginx
# ✅ SECURE (Nginx config)
server {
    root /var/www/app;
    
    # Block version control
    location ~ /(\.git|\.svn|\.hg) { deny all; }
    
    # Block config files
    location ~ /(\.env|\.config|config\.json) { deny all; }
    
    # Block backup files
    location ~ /\.bak|\.backup|\.old { deny all; }
    
    # Block log files
    location ~ \.log$ { deny all; }
}
```

---

### ✅ Fourth Defense: Remove Developer Comments

```html
# ❌ VULNERABLE (Build process)
<!-- DEBUG: /cgi-bin/phpinfo.php -->
<h1>Welcome</h1>

# ✅ SECURE (webpack.config.js)
plugins: [
  new StripCommentPlugin({ pattern: /DEBUG:|TODO:/ })
]
```

---

### ✅ Fifth Defense: Parameterized Queries

```python
# ❌ VULNERABLE
query = f"SELECT * FROM users WHERE id = '{user_id}'"

# ✅ SECURE
query = "SELECT * FROM users WHERE id = ?"
db.execute(query, [user_id])  # Parameterized
```

---

### ✅ Sixth Defense: Environment Variables for Secrets

```javascript
# ❌ VULNERABLE
const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';

# ✅ SECURE
const AWS_KEY = process.env.AWS_ACCESS_KEY_ID;

# .env (NOT committed)
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
```

---

## 📋 5. Information Disclosure Testing Checklist

### File Discovery
- ✅ Check robots.txt for excluded paths
- ✅ Find HTML comments (debug URLs, internal notes)
- ✅ Content discovery for hidden directories
- ✅ Test common backup paths (/backup/, /.git/, /.env)

### Error Message Testing
- ✅ Send invalid data types (strings instead of integers)
- ✅ Test SQL injection to trigger database errors
- ✅ Compare error responses for existing vs. missing resources
- ✅ Test auth endpoints for username/password enumeration

### Configuration Testing
- ✅ Access common config files (/.env, /config.json, /web.config)
- ✅ Check for accessible .git, .svn directories
- ✅ Test for phpinfo.php, debug pages
- ✅ Verify log files not accessible (/logs/, .log)

### HTTP Method Testing
- ✅ Test TRACE method (header reflection)
- ✅ Test DEBUG method
- ✅ Test unexpected methods (OPTIONS, PUT)

### Source Code Testing
- ✅ Access JavaScript files for API keys
- ✅ Check for backup files (.bak, .backup, .old)
- ✅ Test for database dumps (.sql, .dump)
- ✅ Search for hardcoded credentials in code

---

## 🎓 6. Key Takeaways

| Principle | Description |
|-----------|-------------|
| **Generic Errors** | Never return detailed error messages to users |
| **Disable Debug** | Turn off debugging in production environments |
| **Block Sensitive Files** | Exclude .git, .env, backups from web root |
| **Remove Comments** | Strip developer comments before deployment |
| **Parameterized Queries** | Use parameterized queries to prevent SQL errors |
| **Environment Variables** | Never hard-code secrets in source code |
| **Context Matters** | Severity depends on what attacker can do with leaked info |
| **Enabler Vulnerability** | Information disclosure often enables high-severity attacks |

---

## 🔗 7. References & Resources

- **OWASP**: [Information Disclosure](https://owasp.org/www-project-web-security-testing-guide/)
- **CWE-200**: [Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
- **PortSwigger**: [Information Disclosure Academy](https://portswigger.net/web-security/information-disclosure)
- **OWASP Testing Guide**: [Information Disclosure Testing](https://owasp.org/www-project-web-security-testing-guide/)
- **NIST**: [SD-104: Information Leakage](https://www.nist.gov/)

---
