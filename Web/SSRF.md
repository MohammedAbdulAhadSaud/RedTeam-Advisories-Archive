# Server-Side Request Forgery (SSRF)

**Category**: Server-Side Request Trust & URL Fetch Flaws  
**Severity Focus**: High to Critical (Internal Admin Access, Credential Theft, Blind Pivoting, RCE)  
**CWE Mapping**: CWE-918 (Primary), CWE-20, CWE-200, CWE-611, CWE-78  
**OWASP Top 10 2021**: A10:2021-Server-Side Request Forgery (SSRF)  
**OWASP API Top 10 2023**: API7:2023-Server-Side Request Forgery

---

##  1. SSRF Fundamentals

### What is SSRF?
Server-side request forgery is a web security vulnerability that allows an attacker to induce the server-side application to make requests to an unintended location. [web:156]

In an SSRF attack, the application fetches a remote resource without properly validating the user-supplied URL, which can let an attacker force requests to internal resources, metadata services, or other unexpected destinations. [web:151][web:152][web:157]

### Module 01: SSRF Overview and Trust Boundaries
*   **CWE Mapping**: CWE-918 (Server-Side Request Forgery)
*   **OWASP Top 10 Reference**: A10:2021-SSRF

#### Low-Level Architectural Mechanics
SSRF happens when server-side code fetches a URL supplied directly or indirectly by a user. The server then becomes the trusted requester, which can bypass network controls that would block the user’s browser. [web:151][web:152]

**Core abuse pattern**:
- User supplies a URL, hostname, path, or callback target.
- Server-side code issues the request.
- The response may be returned to the user, logged, or processed internally.
- The attacker chooses a destination the server should never contact. [web:151][web:152]

**Impact**:
- Internal admin access.
- Credential theft from metadata services.
- Access to private back-end services.
- Blind pivoting and, in some cases, command execution. [web:151][web:152][web:157]

#### Example SSRF Flow
```python
# ❌ VULNERABLE
@app.route('/fetch')
def fetch():
    url = request.args.get('url')
    return requests.get(url).text
```

#### Raw SSRF Request
```text
GET /fetch?url=http://localhost/admin HTTP/1.1
Host: vulnerable-app.com
```

#### Secure Pattern
```python
# ✅ SECURE
ALLOWED_HOSTS = {"api.partner.com"}

@app.route('/fetch')
def fetch():
    url = request.args.get('url')
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValidationError("Scheme not allowed")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValidationError("Host not allowed")
    return requests.get(url, timeout=3, allow_redirects=False).text
```

---

### Module 02: SSRF Attack Surface Discovery
*   **CWE Mapping**: CWE-918, CWE-200
*   **OWASP Top 10 Reference**: A10:2021-SSRF

#### Low-Level Architectural Mechanics
SSRF is often hidden inside features that look harmless but fetch remote content behind the scenes. [web:151][web:157]

**Common attack surface**:
- Stock check or inventory lookup.
- URL preview or link unfurling.
- PDF, image, or document fetchers.
- Webhooks and callback handlers.
- Import-by-URL features.
- Analytics or logging tools that process request headers.
- XML or structured data parsers that resolve URLs. [web:151][web:155][web:157]

#### Common Indicators
- Parameters named `url`, `uri`, `next`, `path`, `stockApi`, `feed`, `callback`.
- Server-side timeouts or DNS lookups during input processing.
- Errors mentioning connection failure, invalid host, or parse problems. [web:151][web:156]

#### Secure Pattern
```python
# ✅ SECURE
def is_safe_url(value):
    parsed = urlparse(value)
    return parsed.scheme in {"https"} and parsed.hostname in ALLOWED_HOSTS
```

---

## 🔬 2. Basic SSRF

### Module 03: SSRF Against the Local Server
*   **CWE Mapping**: CWE-918
*   **OWASP Top 10 Reference**: A10:2021-SSRF

#### Low-Level Architectural Mechanics
If the application fetches a URL supplied by the user, pointing it at `localhost` or `127.0.0.1` can make the server request its own internal services. This may bypass front-end controls or trust checks that treat local requests differently. [web:151][web:152]

#### Raw Exploit Request
```text
POST /product/stock HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/x-www-form-urlencoded

stockApi=http://localhost/admin
```

#### Why It Works
The server makes the request from its own network context, so the target may see it as trusted or local. That can expose administrative pages that are not reachable from the public internet. [web:151][web:152]

#### Secure Pattern
```python
# ✅ SECURE
blocked_hosts = {"localhost", "127.0.0.1", "::1"}

if parsed.hostname in blocked_hosts:
    raise ValidationError("Local addresses are not allowed")
```

---

### Module 04: SSRF Against Other Back-End Systems
*   **CWE Mapping**: CWE-918
*   **OWASP Top 10 Reference**: A10:2021-SSRF

#### Low-Level Architectural Mechanics
The application server may be able to reach private IP ranges and internal services that users cannot access directly. SSRF can be used to pivot into these internal systems. [web:151][web:152]

**Common targets**:
- `10.x.x.x`
- `192.168.x.x`
- `172.16.x.x` to `172.31.x.x`
- Internal APIs.
- Admin dashboards.
- Service discovery endpoints. [web:151][web:157]

#### Raw Exploit Request
```text
POST /product/stock HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/x-www-form-urlencoded

stockApi=http://192.168.0.68/admin
```

#### Secure Pattern
```python
# ✅ SECURE
def is_private_ip(hostname):
    ip = socket.gethostbyname(hostname)
    return ipaddress.ip_address(ip).is_private
```

---

## 🔬 3. SSRF Filter Bypasses

### Module 05: Blacklist-Based Filter Bypass
*   **CWE Mapping**: CWE-918, CWE-20
*   **OWASP Top 10 Reference**: A10:2021-SSRF

#### Low-Level Architectural Mechanics
Blacklists are fragile because attackers can often reach the same destination through alternate IP encodings, obfuscation, or redirects. [web:147][web:152]

**Common bypasses**:
- `127.1` instead of `127.0.0.1`.
- Decimal or octal IP forms.
- URL encoding and double encoding.
- Case variation.
- Redirect chains through a controlled host. [web:147][web:152]

#### Raw Bypass Example
```text
POST /product/stock HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/x-www-form-urlencoded

stockApi=http://127.1/admin
```

#### Secure Pattern
```python
# ✅ SECURE
# Use allowlists rather than blacklists.
if parsed.hostname not in {"stock.weliketoshop.net"}:
    raise ValidationError("Host not allowed")
```

---

### Module 06: Whitelist-Based Filter Bypass
*   **CWE Mapping**: CWE-918, CWE-20
*   **OWASP Top 10 Reference**: A10:2021-SSRF

#### Low-Level Architectural Mechanics
Allowlist validation can fail when the validation layer parses a URL differently than the request layer. URL syntax features such as embedded credentials, fragments, and encoding tricks can be abused. [web:157][web:145]

**Bypass techniques**:
- Embedded credentials: `user@host`.
- Fragment tricks: `#`.
- Subdomain confusion: `expected-host.attacker.com`.
- URL encoding or double encoding.
- Parser discrepancies between validation and the HTTP client. [web:157][web:145]

#### Raw Bypass Example
```text
POST /product/stock HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/x-www-form-urlencoded

stockApi=http://localhost:80%2523@stock.weliketoshop.net/admin/delete?username=carlos
```

#### Secure Pattern
```python
# ✅ SECURE
def normalize_and_validate(url):
    parsed = urlparse(url)
    if parsed.username or parsed.password:
        raise ValidationError("Credentials not allowed")
    if parsed.fragment:
        raise ValidationError("Fragments not allowed")
    if parsed.hostname != "stock.weliketoshop.net":
        raise ValidationError("Host not allowed")
```

---

### Module 07: Open-Redirect SSRF Bypass
*   **CWE Mapping**: CWE-918, CWE-601
*   **OWASP Top 10 Reference**: A10:2021-SSRF

#### Low-Level Architectural Mechanics
A supposedly allowed URL can redirect to an internal or attacker-chosen destination if the HTTP client follows redirects. This turns an allowlisted URL into a pivot point. [web:147][web:157]

#### Raw Exploit Request
```text
POST /product/stock HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/x-www-form-urlencoded

stockApi=/product/nextProduct?path=http://192.168.0.12:8080/admin
```

#### Secure Pattern
```python
# ✅ SECURE
requests.get(url, allow_redirects=False, timeout=3)
```

---

## 🔬 4. Blind SSRF

### Module 08: Blind SSRF and Out-of-Band Detection
*   **CWE Mapping**: CWE-918
*   **OWASP Top 10 Reference**: A10:2021-SSRF

#### Low-Level Architectural Mechanics
Blind SSRF occurs when the server makes the request, but the response is not returned to the attacker. The attacker must rely on DNS lookups, timing, or callback traffic to confirm the behavior. [web:155][web:146]

**Detection signals**:
- DNS lookup to attacker-controlled domain.
- HTTP callback to Burp Collaborator.
- Time delay or timeout.
- Side effects in logs or telemetry. [web:155][web:146]

#### Raw Collaborator Probe
```text
GET /product/1 HTTP/1.1
Host: vulnerable-app.com
Referer: http://YOUR-COLLABORATOR-DOMAIN
```

#### Secure Pattern
```python
# ✅ SECURE
# Store headers as text; do not fetch them.
analytics.log(request.headers.get("Referer"))
```

---

### Module 09: Blind SSRF via Shellshock
*   **CWE Mapping**: CWE-918, CWE-78
*   **OWASP Top 10 Reference**: A10:2021-SSRF

#### Low-Level Architectural Mechanics
If the internal target is vulnerable to Shellshock or another command execution bug, blind SSRF can be escalated into command execution. The attacker uses SSRF to deliver a crafted request and confirms impact through an out-of-band callback. [web:146][web:155]

#### Attack Flow
1. Identify a blind SSRF sink.
2. Force a request to an internal service on port 8080.
3. Send a Shellshock-style payload in a header.
4. Exfiltrate output via DNS or another callback. [web:146][web:155]

#### Secure Pattern
```python
# ✅ SECURE
# Patch internal services and remove legacy shell parsing.
```

---

## 🔬 5. Hidden SSRF Surfaces

### Module 10: SSRF via Referer Header
*   **CWE Mapping**: CWE-918, CWE-200
*   **OWASP Top 10 Reference**: A10:2021-SSRF

#### Low-Level Architectural Mechanics
Analytics or logging systems may fetch URLs found in the `Referer` header. If they do this server-side, the header becomes an SSRF input surface. [web:155][web:146]

#### Raw Example
```text
GET /product/1 HTTP/1.1
Host: vulnerable-app.com
Referer: http://YOUR-COLLABORATOR-DOMAIN
```

#### Impact
- Blind confirmation via out-of-band traffic.
- Internal analytics pivoting.
- Secondary SSRF into internal dashboards. [web:155]

#### Secure Pattern
```python
# ✅ SECURE
# Log the header; do not fetch it.
analytics.log(request.headers.get("Referer"))
```

---

### Module 11: SSRF via XML and Data Parsers
*   **CWE Mapping**: CWE-918, CWE-611
*   **OWASP Top 10 Reference**: A10:2021-SSRF

#### Low-Level Architectural Mechanics
Structured formats may permit URLs that parsers resolve automatically. XML is the classic example, and SSRF can appear through external entity resolution or similar fetch behavior. [web:151][web:155]

**Attack surface**:
- XML imports.
- Feed parsers.
- Document importers.
- Rich-content previewers. [web:151][web:155]

#### Secure Pattern
```python
# ✅ SECURE
parser = XMLParser(resolve_entities=False, no_network=True)
```

---

## 🔬 6. Advanced SSRF Topics

### Module 12: SSRF to Cloud Metadata Services
*   **CWE Mapping**: CWE-918, CWE-200
*   **OWASP Top 10 Reference**: A10:2021-SSRF

#### Low-Level Architectural Mechanics
Cloud environments expose metadata and identity services that may return credentials, instance details, or access tokens. SSRF to these endpoints is often one of the highest-impact outcomes. [web:151][web:157]

**Examples**:
- AWS instance metadata.
- GCP metadata service.
- Azure metadata endpoint. [web:151][web:157]

#### Impact
- Temporary cloud credentials.
- Access tokens.
- Instance identity.
- Cloud privilege escalation. [web:151][web:157]

#### Secure Pattern
```python
# ✅ SECURE
blocked_ips = {"169.254.169.254"}
```

---

### Module 13: SSRF Using Alternate Protocols
*   **CWE Mapping**: CWE-918, CWE-20
*   **OWASP Top 10 Reference**: A10:2021-SSRF

#### Low-Level Architectural Mechanics
Some libraries support non-HTTP protocols. If the application accepts a URL without restricting schemes, attackers may abuse `file://`, `gopher://`, or similar handlers depending on the environment. [web:145][web:157]

**Risks**:
- Local file access.
- Protocol smuggling.
- Raw socket-style behavior through URL handlers. [web:145][web:157]

#### Secure Pattern
```python
# ✅ SECURE
allowed_schemes = {"http", "https"}
if parsed.scheme not in allowed_schemes:
    raise ValidationError("Scheme not allowed")
```

---

### Module 14: DNS Rebinding and Resolver Quirks
*   **CWE Mapping**: CWE-918, CWE-20
*   **OWASP Top 10 Reference**: A10:2021-SSRF

#### Low-Level Architectural Mechanics
Validation may happen against one DNS answer, while the actual HTTP request resolves to another. DNS rebinding and resolver inconsistencies can break hostname-based defenses. [web:145][web:152]

**Risk factors**:
- Hostname validation before resolution.
- Different DNS contexts.
- Cached versus live IP mismatches.
- Short TTL records. [web:145][web:152]

#### Secure Pattern
```python
# ✅ SECURE
# Resolve once, validate the resolved IP, then connect.
```

---

### Module 15: SSRF Through URL Preview and Fetchers
*   **CWE Mapping**: CWE-918, CWE-200
*   **OWASP Top 10 Reference**: A10:2021-SSRF

#### Low-Level Architectural Mechanics
Link previews, image imports, and webhooks often fetch remote content server-side. These are common SSRF sinks because they are expected to retrieve untrusted URLs. [web:151][web:157]

**Examples**:
- Link previews.
- Image import.
- Document fetching.
- Webhook validation.
- Import-from-URL tools. [web:151][web:157]

#### Secure Pattern
```python
# ✅ SECURE
# Fetch only from trusted domains and cache results.
```

---

### Module 16: SSRF Chaining into Internal Pivoting
*   **CWE Mapping**: CWE-918, CWE-200
*   **OWASP Top 10 Reference**: A10:2021-SSRF

#### Low-Level Architectural Mechanics
SSRF is often more dangerous when chained with other issues. An attacker can pivot from one internal host to another, discover admin endpoints, or reach management ports. [web:151][web:152]

**Chaining examples**:
- SSRF to internal admin panel.
- SSRF to metadata service.
- SSRF to internal API docs.
- SSRF to another vulnerable internal service. [web:151][web:152]

#### Secure Pattern
```python
# ✅ SECURE
# Combine allowlists, egress filtering, timeouts, and logging.
```

---

## 🔬 7. Prevention Strategy

### Module 17: SSRF Prevention Architecture
*   **CWE Mapping**: CWE-918, CWE-20
*   **OWASP Top 10 Reference**: A10:2021-SSRF

#### Low-Level Architectural Mechanics
The best defense is layered. Do not rely on a single blacklist or regex check. Allowlist trusted destinations, block internal and metadata ranges, disable redirects, and enforce network egress controls. [web:145][web:157]

**Recommended controls**:
- Strict allowlists for hostnames.
- Reject private, loopback, link-local, and metadata IPs.
- Disable redirects for untrusted fetches.
- Restrict schemes to `http` and `https`.
- Resolve and validate IPs before connecting.
- Apply egress firewall rules.
- Log and alert on suspicious fetches. [web:145][web:157]

#### Secure Pattern
```python
# ✅ SECURE
def safe_fetch(url):
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValidationError("Invalid scheme")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValidationError("Host not allowed")
    response = requests.get(url, allow_redirects=False, timeout=3)
    return response.text
```

---

## 🔧 Detection Workflow

### Step 1: Find URL Inputs
- Look for parameters like `url`, `next`, `path`, `stockApi`, `callback`, `referer`.
- Inspect forms, JSON, headers, and XML fields.

### Step 2: Test for Fetching Behavior
- Replace external hostnames.
- Try `localhost`, `127.0.0.1`, and private IPs.
- Watch for timeouts, errors, redirects, or DNS lookups. [web:156][web:155]

### Step 3: Check for Bypasses
- Alternate IP forms.
- Redirect chaining.
- URL encoding and double encoding.
- Embedded credentials and fragments.
- Parser edge cases. [web:147][web:157]

### Step 4: Confirm Blind SSRF
- Use Burp Collaborator or a controlled DNS endpoint.
- Watch for DNS and HTTP interactions.
- Test timing differences. [web:155][web:146]

### Step 5: Assess Impact
- Internal admin access.
- Credential theft.
- Cloud metadata access.
- Command execution via internal services. [web:151][web:157]

---

##  References

- PortSwigger SSRF overview: [Server-side request forgery (SSRF)](https://portswigger.net/web-security/ssrf) [web:134]
- PortSwigger SSRF learning path: [SSRF attacks](https://portswigger.net/web-security/learning-paths/ssrf-attacks) [web:135]
- OWASP SSRF definition: [Server Side Request Forgery](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery) [web:151]
- OWASP Top 10 SSRF: [A10:2021 – Server-Side Request Forgery (SSRF)](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_(SSRF)/) [web:152]
- OWASP API SSRF: [API7:2023 Server Side Request Forgery](https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/) [web:157]
- OWASP SSRF prevention: [Server-Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) [web:145]
- Blind SSRF: [Blind SSRF vulnerabilities](https://portswigger.net/web-security/ssrf/blind) [web:155]
- Shellshock SSRF lab: [Blind SSRF with Shellshock exploitation](https://portswigger.net/web-security/ssrf/blind/lab-shellshock-exploitation) [web:146]
