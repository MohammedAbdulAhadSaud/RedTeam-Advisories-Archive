# Insecure Deserialization

**Category:** Insecure Deserialization  
**Severity:** High or Critical

---

## Definition

**Insecure Deserialization** occurs when an application takes serialized data from an untrusted source and deserializes it without properly validating or controlling what is being processed.

**Serialization** is the process of converting an object or data structure into a format that can be stored or transmitted. **Deserialization** is the reverse process, where that data is converted back into an object that the application can use.

The vulnerability appears when the application **trusts serialized data that can be modified by an attacker**.

In simple terms:

```text
Object
   |
   | Serialization
   v
Serialized Data
   |
   | Sent to / stored by application
   v
Attacker modifies the data
   |
   | Deserialization
   v
Application reconstructs the object


## Modifying Serialized Objects

* **The Objective:** Exploit insecure deserialization by modifying a serialized object stored in a session cookie. The goal is to change the user's privilege level from a normal user to an administrator and access administrative functionality.

* **The Mechanism:** The application stores session information inside a serialized PHP object. The object contains an `admin` attribute that determines whether the user has administrative privileges. Because the application trusts the serialized object received from the client without adequately validating its integrity, an attacker can modify the serialized data and change the value of the `admin` attribute.

* **Core Layout Structure:**

```text
Session Cookie
      |
      | URL/Base64 decoding
      v
Serialized PHP Object
      |
      | Modify object attribute
      v
admin = false
      |
      | Change to
      v
admin = true
      |
      v
Application Deserializes Object
      |
      v
Administrative Privileges
```

* **The Session Cookie:** The application stores the serialized session object inside a client-side cookie. The cookie may appear unreadable because it is URL-encoded and Base64-encoded.

* **The Decoded Object:** After decoding the cookie, the underlying serialized PHP object can be inspected. A simplified representation may look like:

```text
admin = false
```

In PHP serialization, a boolean value is represented using the `b` type:

```text
b:0
```

represents:

```text
false
```

while:

```text
b:1
```

represents:

```text
true
```

* **The Vulnerability:** The application trusts security-sensitive values contained within the serialized object. Since the object is stored on the client side and is not protected against modification, an attacker can alter the privilege-related attribute before sending the cookie back to the server.

* **Modifying the Serialized Object:** The attacker changes the serialized `admin` attribute from:

```text
b:0
```

to:

```text
b:1
```

Conceptually:

```text
Before:
admin = false

After:
admin = true
```

The modified object is then re-encoded and supplied as the session cookie.

* **The Deserialization Process:** When the server receives the modified cookie, it decodes and deserializes the object. If there is no integrity validation, the application accepts the modified `admin` value and treats the attacker as an administrator.

* **The Privilege Escalation:**

```text
Normal User
    |
    | Modified session object
    v
admin = true
    |
    v
Application deserializes object
    |
    v
Administrator privileges
    |
    v
/admin
```

* **The Administrative Functionality:** Once the modified session is accepted, administrative functionality becomes accessible. The administrative interface may expose privileged operations such as viewing users or deleting accounts.

* **Example Administrative Request:**

```http
GET /admin HTTP/1.1
Host: target.com
Cookie: session=MODIFIED_SESSION_COOKIE
```

* **Administrative Action:** An administrative endpoint may provide functionality such as deleting a user:

```http
GET /admin/delete?username=carlos HTTP/1.1
Host: target.com
Cookie: session=MODIFIED_SESSION_COOKIE
```

* **Core Concept:** The important issue is not simply that the application uses serialization. The vulnerability occurs because **security-sensitive serialized data is controlled by the client and is trusted after deserialization without sufficient integrity protection or server-side validation**.

* **The Security Impact:** Insecure deserialization of modifiable session objects can lead to privilege escalation, authentication bypass, unauthorized administrative actions, account manipulation, and potentially more severe attacks depending on the capabilities of the serialized object and the deserialization process.

## Modifying Serialized Data Types

* **The Objective:** Exploit insecure deserialization by modifying the data types inside a serialized session object. The goal is to bypass authentication and make the application treat the attacker as the `administrator` user.

* **The Mechanism:** The application stores authentication information inside a serialized PHP object. The object contains a `username` attribute and an `access_token` attribute. Because the serialized object is stored in a client-controlled session cookie and is not adequately protected, the attacker can modify both the values and their underlying data types.

* **Core Layout Structure:**

```text
Session Cookie
      |
      | Decode
      v
Serialized PHP Object
      |
      | Modify values and data types
      v
username = administrator
access_token = integer 0
      |
      v
Application Deserializes Object
      |
      | Weak type comparison
      v
Authentication Bypass
      |
      v
Administrator Account
```

* **The Serialized Object:** A simplified PHP serialized object may contain fields similar to:

```text
O:4:"User":2:{
    s:8:"username";s:6:"wiener";
    s:12:"access_token";s:32:"RANDOM-TOKEN";
}
```

The important fields are the `username` and `access_token` values.

* **The Vulnerability:** The application relies on serialized client-side data when determining the user's identity. If the application also performs weak comparisons between values of different data types, changing the serialized data type can cause an unexpected authentication result.

* **The Data Type Modification:** PHP serialization identifies the type of each value. For example:

```text
s
```

represents a string, while:

```text
i
```

represents an integer.

Therefore:

```text
s:32:"RANDOM-TOKEN";
```

represents a string, while:

```text
i:0;
```

represents the integer `0`.

* **The Authentication Bypass:** The attacker modifies the serialized object so that the username becomes `administrator` and the access token becomes the integer `0`.

```text
Before:

username = wiener
access_token = "RANDOM-TOKEN"

After:

username = administrator
access_token = 0
```

* **Modified Serialized Object:**

```text
O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}
```

The important changes are:

``
