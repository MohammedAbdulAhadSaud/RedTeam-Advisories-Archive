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

Lab: Arbitrary object injection in PHP

PRACTITIONER
LAB Solved

This lab uses a serialization-based session mechanism and is vulnerable to arbitrary object injection as a result. To solve the lab, create and inject a malicious serialized object to delete the morale.txt file from Carlos's home directory. You will need to obtain source code access to solve this lab.

You can log in to your own account using the following credentials: wiener:peter
Hint

You can sometimes read source code by appending a tilde (~) to a filename to retrieve an editor-generated backup file.
ACCESS THE LAB
Solution

    Log in to your own account and notice the session cookie contains a serialized PHP object.
    From the site map, notice that the website references the file /libs/CustomTemplate.php. Right-click on the file and select "Send to Repeater".
    In Burp Repeater, notice that you can read the source code by appending a tilde (~) to the filename in the request line.
    In the source code, notice the CustomTemplate class contains the __destruct() magic method. This will invoke the unlink() method on the lock_file_path attribute, which will delete the file on this path.

    In Burp Decoder, use the correct syntax for serialized PHP data to create a CustomTemplate object with the lock_file_path attribute set to /home/carlos/morale.txt. Make sure to use the correct data type labels and length indicators. The final object should look like this:
    O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}
    Base64 and URL-encode this object and save it to your clipboard.
    Send a request containing the session cookie to Burp Repeater.
    In Burp Repeater, replace the session cookie with the modified one in your clipboard.
    Send the request. The __destruct() magic method is automatically invoked and will delete Carlos's file.

### Java Deserialization Gadget Chains

Java deserialization can lead to **remote code execution (RCE)** when vulnerable classes and libraries contain usable gadget chains.

```text
Serialized Java Object
        |
        v
Deserialization
        |
        v
Gadget Chain
        |
        v
Dangerous Method / Command Execution
```

A common example is **Apache Commons Collections**, where pre-built gadget chains can be used to construct a malicious serialized object.

```text
Apache Commons Collections
          |
          v
   Gadget Chain
          |
          v
Malicious Serialized Object
          |
          v
Java Deserialization
          |
          v
       RCE
```

Tools such as **ysoserial** can generate serialized objects containing these gadget chains when the vulnerable library is available to the application.
