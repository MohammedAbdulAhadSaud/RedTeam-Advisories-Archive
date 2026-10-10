
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


## SSTI in Code Context (Tornado)

- **The Mechanism:** The application inserts the `blog-post-author-display` parameter into a Tornado template expression. By closing the existing expression with `}}`, an attacker may inject additional template syntax.

- **Detection Payload:**

```python
user.name}}{{7*7}}
```

If the rendered username includes `49`, this indicates that the injected expression was evaluated by the template engine.

- **Exploitation:** Tornado supports `{% ... %}` directives for Python statements. In a vulnerable template, these may be abused to import modules and execute operating system commands.

```python
{% import os %}
{{os.system('command')}}
```

- **Core Attack Flow:**

```text
User-Controlled Parameter
          |
          v
Existing Template Expression
          |
          v
Escape with }}
          |
          v
Inject Tornado Template Syntax
          |
          v
Python Code Execution
```

- **Root Cause:** User input is inserted into template code without safely separating data from template syntax.

- **Security Impact:** Potential remote code execution and unauthorized server-side file operations.


## SSTI Using Documentation (Freemarker)

- **The Mechanism:** Freemarker uses `${...}` to evaluate expressions. An invalid expression, such as `${foobar}`, can produce an error that reveals the template engine.

- **Identification:**

```text
${foobar}
    |
    v
Template Error
    |
    v
Identify Freemarker
```

- **Exploitation:** Freemarker's `new()` built-in can instantiate classes implementing `TemplateModel`. The `freemarker.template.utility.Execute` class can execute operating system commands.

```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("command")}
```

- **Root Cause:** User-controlled template content can invoke dangerous engine features without adequate restrictions.

- **Security Impact:** Potential remote code execution and unauthorized server-side operations.
