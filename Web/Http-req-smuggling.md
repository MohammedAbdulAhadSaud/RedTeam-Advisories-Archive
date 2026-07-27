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

