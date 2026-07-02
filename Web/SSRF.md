# Server-Side Request Forgery (SSRF)

**Category**: Server-Side Request Trust & URL Fetch Flaws  
**Severity Focus**: High to Critical  
**CWE Mapping**: CWE-918 (Primary), CWE-20, CWE-200, CWE-601, CWE-611, CWE-78  
**OWASP Top 10 2021**: A10:2021-Server-Side Request Forgery (SSRF)
**OWASP API Top 10 2023**: API7:2023-Server Side Request Forgery 

---

## What is SSRF?

Server-side request forgery is a web security vulnerability that allows an attacker to induce the server-side application to make requests to an unintended location.   
In an SSRF attack, the attacker abuses functionality on the server to read or update internal resources, and may be able to reach internal services, cloud metadata, or other protected back-end targets. 

---

## Impact Overview

A successful SSRF attack can let an attacker access internal services, enumerate private infrastructure, bypass firewalls or VPN boundaries, and sometimes even trigger remote code execution on dependent systems.   
If the application is allowed to reach cloud metadata services, the attacker may be able to steal temporary credentials or access tokens.   
Blind SSRF can still be dangerous even when the response is hidden, because it can be used for port scanning, internal discovery, or out-of-band callbacks. 

---

## Module 01: SSRF Fundamentals

*   **CWE Mapping**: CWE-918 (Server-Side Request Forgery)
*   **OWASP Top 10 Reference**: A10:2021-SSRF 

### Low-Level Architectural Mechanics
SSRF happens when server-side code fetches a resource based on attacker-controlled input. The server then becomes the trusted requester, which can bypass browser-only protections and network controls. 

**Core abuse pattern**:
- User supplies a URL, hostname, path, or callback target.
- Server-side code issues the request.
- The response may be returned to the user, stored, or used internally.
- The attacker chooses a destination the server should never contact. 

**Typical consequences**:
- Internal admin page access.
- Credential theft from metadata services.
- Access to private back-end services.
- Proxying malicious traffic through the victim server. 

### Example SSRF Flow
```python
# ❌ VULNERABLE
@app.route('/fetch')
def fetch():
    url = request.args.get('url')
    return requests.get(url).text
```

### Raw SSRF Request
```text
GET /fetch?url=http://localhost/admin HTTP/1.1
Host: vulnerable-app.com
```

### Secure Pattern
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

## Module 02: SSRF Attack Surface Discovery

*   **CWE Mapping**: CWE-918, CWE-200
*   **OWASP Top 10 Reference**: A10:2021-SSRF 

### Low-Level Architectural Mechanics
SSRF often hides inside features that appear harmless but fetch remote content on the server side.   
These features become attack surface whenever attacker input influences the destination URL or host. 

**Common attack surface**:
- Stock checks and inventory lookup.
- URL previews and link unfurling.
- PDF, image, or document fetchers.
- Webhooks and callback handlers.
- Import-by-URL features.
- Analytics or logging systems that process request headers.
- XML or structured-data parsers that resolve URLs. 

### Common indicators
- Parameters named `url`, `uri`, `next`, `path`, `stockApi`, `feed`, `callback`.
- Timeouts, DNS lookups, or connection failures during input processing.
- Error messages mentioning invalid host, connection refused, or parse failure. 

### Secure Pattern
```python
# ✅ SECURE
def is_safe_url(value):
    parsed = urlparse(value)
    return parsed.scheme in {"https"} and parsed.hostname in ALLOWED_HOSTS
```

---

## Module 03: SSRF Against the Local Server

*   **CWE Mapping**: CWE-918
*   **OWASP Top 10 Reference**: A10:2021-SSRF 

### Low-Level Architectural Mechanics
If the application fetches a URL supplied by the user, pointing it at `localhost` or `127.0.0.1` can make the server request its own local services. This can bypass browser-facing access controls because the request now originates from the trusted server network context. 

### Raw Exploit Request
```text
POST /product/stock HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/x-www-form-urlencoded

stockApi=http://localhost/admin
```

### Why It Works
The local request may be treated as trusted by the target service, so administrative pages or debug interfaces become reachable even when they are not exposed externally. 

### Secure Pattern
```python
# ✅ SECURE
blocked_hosts = {"localhost", "127.0.0.1", "::1"}

if parsed.hostname in blocked_hosts:
    raise ValidationError("Local addresses are not allowed")
```

---

## Module 04: SSRF Against Other Back-End Systems

*   **CWE Mapping**: CWE-918
*   **OWASP Top 10 Reference**: A10:2021-SSRF 

### Low-Level Architectural Mechanics
The application server may be able to reach private IP ranges and internal services that users cannot access directly. SSRF can therefore become a pivot into internal systems protected by topology rather than authentication. 

**Common targets**:
- `10.x.x.x`
- `192.168.x.x`
- `172.16.x.x` to `172.31.x.x`
- Internal APIs.
- Admin dashboards.
- Service discovery endpoints. 

### Raw Exploit Request
```text
POST /product/stock HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/x-www-form-urlencoded

stockApi=http://192.168.0.68/admin
```

### Secure Pattern
```python
# ✅ SECURE
def is_private_ip(hostname):
    ip = socket.gethostbyname(hostname)
    return ipaddress.ip_address(ip).is_private
```

---

## Module 05: Blacklist-Based Filter Bypass

*   **CWE Mapping**: CWE-918, CWE-20
*   **OWASP Top 10 Reference**: A10:2021-SSRF 

### Low-Level Architectural Mechanics
Blacklists are fragile because attackers can often reach the same destination through alternate IP encodings, obfuscation, or redirect chains. 

**Common bypasses**:
- `127.1` instead of `127.0.0.1`.
- Decimal, octal, or hexadecimal IP forms.
- URL encoding and double encoding.
- Case variation.
- Redirect chains through a controlled host. 

### Raw Bypass Example
```text
POST /product/stock HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/x-www-form-urlencoded

stockApi=http://127.1/admin
```

### Secure Pattern
```python
# ✅ SECURE
# Use allowlists rather than blacklists.
if parsed.hostname not in {"stock.weliketoshop.net"}:
    raise ValidationError("Host not allowed")
```

---

## Module 06: Whitelist-Based Filter Bypass

*   **CWE Mapping**: CWE-918, CWE-20
*   **OWASP Top 10 Reference**: A10:2021-SSRF 

### Low-Level Architectural Mechanics
Allowlist validation can still fail when the validation layer parses a URL differently than the request layer. URL syntax features such as embedded credentials, fragments, and encoding tricks can be abused. 

**Bypass techniques**:
- Embedded credentials: `user@host`.
- Fragment tricks: `#`.
- Subdomain confusion: `expected-host.attacker.com`.
- URL encoding or double encoding.
- Parser discrepancies between validation and the HTTP client. 

### Raw Bypass Example
```text
POST /product/stock HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/x-www-form-urlencoded

stockApi=http://localhost:80%2523@stock.weliketoshop.net/admin/delete?username=carlos
```

### Secure Pattern
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

## Module 07: Open-Redirect SSRF Bypass

*   **CWE Mapping**: CWE-918, CWE-601
*   **OWASP Top 10 Reference**: A10:2021-SSRF 

### Low-Level Architectural Mechanics
A supposedly allowed URL can redirect to an internal or attacker-chosen destination if the HTTP client follows redirects. This turns an allowlisted URL into a pivot point. 

### Raw Exploit Request
```text
POST /product/stock HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/x-www-form-urlencoded

stockApi=/product/nextProduct?path=http://192.168.0.12:8080/admin
```

### Secure Pattern
```python
# ✅ SECURE
requests.get(url, allow_redirects=False, timeout=3)
```

---

## Module 08: Blind SSRF and Out-of-Band Detection

*   **CWE Mapping**: CWE-918
*   **OWASP Top 10 Reference**: A10:2021-SSRF 

### Low-Level Architectural Mechanics
Blind SSRF occurs when the server makes the request, but the response is not returned to the attacker. In that case, the attacker confirms behavior through DNS lookups, HTTP callbacks, timing differences, or other side effects. 

**Detection signals**:
- DNS lookup to attacker-controlled domain.
- HTTP callback to Burp Collaborator.
- Time delay or timeout.
- Side effects in logs or telemetry. 

### Raw Collaborator Probe
```text
GET /product/1 HTTP/1.1
Host: vulnerable-app.com
Referer: http://YOUR-COLLABORATOR-DOMAIN
```

### Secure Pattern
```python
# ✅ SECURE
# Store headers as text; do not fetch them.
analytics.log(request.headers.get("Referer"))
```

---

## Module 09: Blind SSRF via Shellshock

*   **CWE Mapping**: CWE-918, CWE-78
*   **OWASP Top 10 Reference**: A10:2021-SSRF 

### Low-Level Architectural Mechanics
If the internal target is vulnerable to Shellshock or another command execution bug, blind SSRF can be escalated into command execution. The attacker uses SSRF to deliver a crafted request and confirms impact through an out-of-band callback. 

### Attack Flow
1. Identify a blind SSRF sink.
2. Force a request to an internal service on port 8080.
3. Send a Shellshock-style payload in a header.
4. Exfiltrate output via DNS or another callback. 

### Secure Pattern
```python
# ✅ SECURE
# Patch internal services and remove legacy shell parsing.
```

---

## Module 10: SSRF via Referer Header

*   **CWE Mapping**: CWE-918, CWE-200
*   **OWASP Top 10 Reference**: A10:2021-SSRF 

### Low-Level Architectural Mechanics
Analytics or logging systems may fetch URLs found in the `Referer` header. If they do this server-side, the header becomes an SSRF input surface. 

### Raw Example
```text
GET /product/1 HTTP/1.1
Host: vulnerable-app.com
Referer: http://YOUR-COLLABORATOR-DOMAIN
```

### Impact
- Blind confirmation via out-of-band traffic.
- Internal analytics pivoting.
- Secondary SSRF into internal dashboards. 

### Secure Pattern
```python
# ✅ SECURE
# Log the header; do not fetch it.
analytics.log(request.headers.get("Referer"))
```

---

## Module 11: SSRF via XML and Data Parsers

*   **CWE Mapping**: CWE-918, CWE-611
*   **OWASP Top 10 Reference**: A10:2021-SSRF 

### Low-Level Architectural Mechanics
Structured formats may permit URLs that parsers resolve automatically. XML is the classic example, and SSRF can appear through external entity resolution or similar fetch behavior. 

**Attack surface**:
- XML imports.
- Feed parsers.
- Document importers.
- Rich-content previewers. 

### Secure Pattern
```python
# ✅ SECURE
parser = XMLParser(resolve_entities=False, no_network=True)
```

---

## Module 12: SSRF to Cloud Metadata Services

*   **CWE Mapping**: CWE-918, CWE-200
*   **OWASP Top 10 Reference**: A10:2021-SSRF 

### Low-Level Architectural Mechanics
Cloud environments expose metadata and identity services that may return credentials, instance details, or access tokens. SSRF to these endpoints is often one of the highest-impact outcomes. 

**Examples**:
- AWS instance metadata.
- GCP metadata service.
- Azure metadata endpoint. 

### Impact
- Temporary cloud credentials.
- Access tokens.
- Instance identity.
- Cloud privilege escalation. 

### Secure Pattern
```python
# ✅ SECURE
blocked_ips = {"169.254.169.254"}
```

---

## Module 13: SSRF Using Alternate Protocols

*   **CWE Mapping**: CWE-918, CWE-20
*   **OWASP Top 10 Reference**: A10:2021-SSRF 

### Low-Level Architectural Mechanics
Some libraries support non-HTTP protocols. If the application accepts a URL without restricting schemes, attackers may abuse `file://`, `gopher://`, or similar handlers depending on the environment. 

**Risks**:
- Local file access.
- Protocol smuggling.
- Raw socket-style behavior through URL handlers. 

### Secure Pattern
```python
# ✅ SECURE
allowed_schemes = {"http", "https"}
if parsed.scheme not in allowed_schemes:
    raise ValidationError("Scheme not allowed")
```

---

## Module 14: DNS Rebinding and Resolver Quirks

*   **CWE Mapping**: CWE-918, CWE-20
*   **OWASP Top 10 Reference**: A10:2021-SSRF 

### Low-Level Architectural Mechanics
Validation may happen against one DNS answer, while the actual HTTP request resolves to another. DNS rebinding and resolver inconsistencies can break hostname-based defenses. 

**Risk factors**:
- Hostname validation before resolution.
- Different DNS contexts.
- Cached versus live IP mismatches.
- Short TTL records. 

### Secure Pattern
```python
# ✅ SECURE
# Resolve once, validate the resolved IP, then connect.
```

---

## Module 15: SSRF Through URL Preview and Fetchers

*   **CWE Mapping**: CWE-918, CWE-200
*   **OWASP Top 10 Reference**: A10:2021-SSRF 

### Low-Level Architectural Mechanics
Link previews, image importers, and webhook validators often fetch remote content server-side. These features are common SSRF sinks because they are expected to retrieve untrusted URLs. 

**Examples**:
- Link previews.
- Image import.
- Document fetching.
- Webhook validation.
- Import-from-URL tools. 

### Secure Pattern
```python
# ✅ SECURE
# Fetch only from trusted domains and cache results.
```

---

## Module 16: SSRF Chaining into Internal Pivoting

*   **CWE Mapping**: CWE-918, CWE-200
*   **OWASP Top 10 Reference**: A10:2021-SSRF 

### Low-Level Architectural Mechanics
SSRF is often more dangerous when chained with other issues. An attacker can pivot from one internal host to another, discover admin endpoints, or reach management ports. 

**Chaining examples**:
- SSRF to internal admin panel.
- SSRF to metadata service.
- SSRF to internal API docs.
- SSRF to another vulnerable internal service. 

### Secure Pattern
```python
# ✅ SECURE
# Combine allowlists, egress filtering, timeouts, and logging.
```

---

## Module 17: SSRF Testing Workflow

*   **CWE Mapping**: CWE-918, CWE-20
*   **OWASP Top 10 Reference**: A10:2021-SSRF 

### Low-Level Architectural Mechanics
To test for SSRF, first identify a request that contains a full or partial URL, then probe whether the server issues a backend request based on that input. Burp Suite can be used to vary the destination host, test private ranges, and observe response differences. 

**Practical testing steps**:
1. Identify a URL-like input or header.
2. Replace the destination with a controlled host.
3. Try `localhost`, `127.0.0.1`, and internal IP ranges.
4. Test for alternate IP forms and encoding tricks.
5. Check for different status codes, response lengths, or delays.
6. Use Collaborator or DNS callbacks for blind cases. 

### Example Probe Pattern
```text
GET /fetch?url=http://YOUR-COLLABORATOR-DOMAIN HTTP/1.1
Host: vulnerable-app.com
```

### Secure Pattern
```python
# ✅ SECURE
# Log outbound destinations and alert on unexpected hosts.
```

---

## Module 18: SSRF Defensive Checklist

*   **CWE Mapping**: CWE-918, CWE-20
*   **OWASP Top 10 Reference**: A10:2021-SSRF 

### Low-Level Architectural Mechanics
SSRF should be handled with defense in depth rather than a single filter. OWASP recommends positive allowlists, disabling redirects, validating URL consistency, and applying network-layer controls such as deny-by-default egress filtering. 

**Checklist**:
- Validate and normalize the destination URL.
- Restrict schemes to `http` and `https`.
- Use allowlists for host, port, and destination.
- Block loopback, private, link-local, and metadata IPs.
- Disable redirects for untrusted fetches.
- Never return raw remote responses blindly.
- Enforce egress firewall policy.
- Log accepted and blocked outbound connections.
- Avoid putting sensitive services on front-end hosts. 

### Secure Pattern
```python
# ✅ SECURE
def safe_fetch(url):
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValidationError("Invalid scheme")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValidationError("Host not allowed")
    return requests.get(url, allow_redirects=False, timeout=3).text
```

---

## Detection Workflow

### Step 1: Find URL Inputs
Look for parameters like `url`, `next`, `path`, `stockApi`, `callback`, and `referer`. Check forms, JSON, headers, XML, and server-side import features. 

### Step 2: Test for Fetching Behavior
Replace the host with controlled domains, `localhost`, `127.0.0.1`, and private IPs. Watch for timeouts, redirects, DNS lookups, and unusual server errors. 

### Step 3: Check for Bypasses
Try alternate IP forms, redirect chaining, URL encoding, double encoding, embedded credentials, and parser edge cases. 

### Step 4: Confirm Blind SSRF
Use Burp Collaborator or a controlled DNS endpoint and watch for DNS and HTTP interactions. Timing differences can also confirm behavior. 

### Step 5: Assess Impact
Determine whether the issue reaches internal admin access, metadata services, credential theft, or command execution through a back-end service. 

---
