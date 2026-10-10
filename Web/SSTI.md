
# Server-Side Template Injection (SSTI)

**Category:** Server-Side Template Injection  
**Severity:** High or Critical

---

## Definition

**Server-Side Template Injection (SSTI)** occurs when an application unsafely embeds user-controlled input into a server-side template, causing the input to be interpreted as template code rather than ordinary data.

Template engines process templates to generate dynamic content, such as HTML pages. If an attacker can inject template expressions into an unsafe template, they may be able to manipulate the rendering process and, depending on the engine and its capabilities, execute server-side code.

In simple terms:

```text
User Input
    |
    | Embedded into template
    v
Server-Side Template
    |
    | Template evaluation
    v
Injected Expression Executed
    |
    v
Unexpected Application Behavior
```

---

## Basic Server-Side Template Injection (ERB)

- **The Objective:** Identify an ERB template injection vulnerability and exploit it to execute operating system commands.

- **The Mechanism:** The application unsafely incorporates user-controlled input from the `message` parameter into an ERB template. ERB uses `<%= ... %>` to evaluate an expression and render its result. If user input is interpreted as template code, an attacker may be able to execute Ruby functionality on the server.

- **Core Layout Structure:**

```text
User-Controlled Parameter
          |
          v
      message
          |
          v
Unsafe ERB Template
          |
          | Inject expression
          v
     <%= 7*7 %>
          |
          v
Expression Evaluated
          |
          v
      Output: 49
```

- **Exploitation:** Once template evaluation is confirmed, vulnerable ERB applications may expose Ruby functionality capable of executing operating system commands, depending on the application's environment and restrictions.

- **Security Impact:** Potential server-side code execution, unauthorized file operations, and compromise of resources accessible to the application process.


## Basic ERB Template Injection

- **The Mechanism:** The application uses the `message` parameter to render content through an unsafely constructed ERB template. ERB evaluates expressions enclosed in `<%= ... %>` and renders their results.

- **Detection Payload:**

```erb
<%= 7*7 %>
```

If the response renders `49`, this indicates that the input is being evaluated as a template expression.

- **Exploitation:** ERB runs within Ruby, so an exploitable template may allow access to methods such as `system()` to execute operating system commands.

```erb
<%= system("command") %>
```

- **Core Attack Flow:**

```text
message Parameter
       |
       v
Unsafe ERB Template
       |
       v
Expression Evaluation
       |
       v
Ruby Method Execution
       |
       v
Operating System Command
```

- **Root Cause:** User-controlled input is interpreted as ERB template code instead of being handled as data.

- **Security Impact:** Potential remote code execution and unauthorized file operations under the privileges of the application process.
