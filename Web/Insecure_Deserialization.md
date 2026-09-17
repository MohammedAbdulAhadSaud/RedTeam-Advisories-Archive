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

### Modifying Serialized Objects

Attackers can modify security-sensitive values inside client-controlled serialized objects.

```text
Serialized PHP Object
        |
        v
admin = b:0
        |
        | Modify
        v
admin = b:1
        |
        v
Deserialization
        |
        v
Admin privileges
```

**Example:**

```text
b:0 → false
b:1 → true
```

If a session cookie contains a serialized object with an `admin` property, changing its value from `b:0` to `b:1` can result in **privilege escalation** when the application trusts the deserialized object.

### Modifying Serialized Data Types

Insecure deserialization can also be exploited by **changing the data type of a serialized property**.

```text
Original:
access_token = "valid-token"
        |
        v
Modified:
access_token = 0
```

PHP serialized types:

```text
s → string
i → integer
```

Example:

```text
s:12:"access_token";s:...:"token";
```

can be changed to:

```text
s:12:"access_token";i:0;
```

When the application compares the modified integer with another value using PHP's loose comparison behavior, this can result in an **authentication bypass**.

This technique depends on the PHP comparison behavior of the relevant PHP version.
### Using Application Functionality

Insecure deserialization can be exploited by modifying an object property that is later used by a legitimate application feature to perform a dangerous action.

```text
Serialized Object
      |
      v
Modify property
      |
      v
Application functionality
      |
      v
Dangerous action
```

Example:

```text
avatar_link
    ↓
/home/carlos/morale.txt
    ↓
Account deletion functionality
    ↓
File deletion
```

The attacker does not necessarily need direct access to a dangerous function. Instead, they can **manipulate serialized object data so that existing application functionality operates on an unintended resource**.

When modifying serialized strings, the corresponding **length indicator must also be updated**.
