
# Insecure Deserialization

**Category:** Insecure Deserialization  
**Severity:** High or Critical

---

## Definition

**Insecure Deserialization** occurs when an application deserializes untrusted data without adequately validating or controlling the data being processed.

**Serialization** converts an object or data structure into a format that can be stored or transmitted. **Deserialization** converts that data back into an object the application can use.

The vulnerability occurs when an application trusts serialized data that an attacker can modify.

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
```

---

## Modifying Serialized Objects

- **The Objective:** Modify a serialized object stored in a session cookie to change the user's privilege level and gain administrative access.

- **The Mechanism:** The application stores session information in a serialized PHP object containing an `admin` attribute. If the application trusts the client-supplied object without adequately protecting its integrity, an attacker may modify the attribute from `false` to `true`.

- **Core Layout Structure:**

```text
Session Cookie
      |
      | URL/Base64 decoding
      v
Serialized PHP Object
      |
      | Modify admin attribute
      v
admin = b:0  (false)
      |
      | Change to
      v
admin = b:1  (true)
      |
      v
Application Deserializes Object
      |
      v
Potential Privilege Escalation
```

- **Security Impact:** Unauthorized administrative access and privilege escalation.
