
#  Deep-Dive Architectural Study: Race Condition Vulnerabilities

**Category**: Concurrent Request Processing & Business Logic Flaws  
**Severity**: Medium to Critical (Limit Overruns, Authentication Bypass, Data Corruption)  
**CWE Mapping**: CWE-362 (Primary), CWE-820, CWE-944  
**OWASP Top 10**: A05:2021 (Security Misconfiguration) / Business Logic Flaws

---

##  What are Race Condition Vulnerabilities?

**Race Conditions** are vulnerabilities that occur when websites process requests **concurrently without adequate safeguards**. This allows multiple distinct threads to interact with the **same data at the same time**, resulting in a "collision" that causes **unintended application behavior**.

### Key Terminology

| Term | Definition |
|------|------------|
| **Race Window** | The time period during which a collision is possible (e.g., fraction of a second between database interactions) |
| **Sub-State** | A temporary state an application enters and exits before request processing completes |
| **TOCTOU** | Time-of-Check to Time-of-Use (classic race condition subtype) |
| **Network Jitter** | Unpredictable delays in network transmission affecting request timing |
| **Server-Side Jitter** | Internal latency in server processing affecting request order |

### Why They Occur

1. **No request locking** - Multiple requests processed simultaneously without synchronization
2. **Non-atomic state changes** - Data updates happen in multiple steps instead of single transaction
3. **Shared session state** - Session variables updated individually instead of in batch
4. **Background thread operations** - Email/validation sent after HTTP response, creating race windows
5. **Missing concurrency safeguards** - Database constraints, transactions, or locking mechanisms not used
6. **Time-based token generation** - Security tokens generated using timestamps instead of cryptographically secure random strings

---

## 🔬 1. Low-Level Architectural Mechanics

### The Race Condition Attack Chain

```text
[ Identify Target Endpoint ] 
        │ (Single-use/rate-limited endpoint with security impact)
        ▼
[ Predict Collision Potential ] 
        │ (Two+ requests triggering operations on same record)
        ▼
[ Minimize Network Jitter ] 
        │ (Use single-packet attack or last-byte synchronization)
        ▼
[ Trigger Collision ] 
        │ (Send parallel requests to line up race windows)
        ▼
[ Observe Sub-State Collision ] 
        │ (Application transitions through temporary vulnerable state)
        ▼
[ Exploit Unintended Behavior ] 
        │ (Limit overrun, auth bypass, data corruption)
```

### The Root Cause: Non-Atomic Operations

Race conditions occur when applications:
- **Check and update in separate steps** (TOCTOU flaws)
- **Update session variables individually** instead of in batch
- **Use background threads** for email/validation (sent after response)
- **Create objects in multiple SQL statements** (temporary uninitialized state)
- **Generate tokens using timestamps** (predictable, collision-prone)
- **Mix data from different storage** (sessions + database inconsistency)

---

## ⚙️ 2. Comprehensive Race Condition Typology Matrix

### Type A: Limit Overrun (TOCTOU)

**Description**: Exceed single-use or rate-limited endpoint by exploiting race window between check and update.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Send multiple parallel requests to single-use endpoint (promo codes, gift cards, CAPTCHA) |
| **Impact** | Multiple discounts, gift card redeems, CAPTCHA bypasses, rate limit bypasses |
| **Detection** | Identify single-use/rate-limited endpoints, test with parallel requests |

#### 🎯 Example: Promo Code Multiple Redemptions

**Demo Scenario**: Online store allows one-time promo code discount

**Normal Flow (Single Request)**:
```text
Request 1: apply_discount(code=SUMMER20)
  1. Check: Has SUMMER20 been used? → NO
  2. Apply: Discount 20% to order
  3. Update: Mark SUMMER20 as used ✓
```

**Race Attack (Parallel Requests)**:
```text
Request 1: apply_discount(code=SUMMER20) [TIME T0]
  1. Check: Has SUMMER20 been used? → NO ← BOTH PASS CHECK
  2. Apply: Discount 20% ✗
  3. Update: Mark as used (completes at T+50ms)

Request 2: apply_discount(code=SUMMER20) [TIME T+1ms]
  1. Check: Has SUMMER20 been used? → NO ← RACE WINDOW!
  2. Apply: Discount 20% ✗
  3. Update: Mark as used (completes at T+51ms)
```

**Expected Output**: One 20% discount applied  
**Actual Output**: TWO 20% discounts applied (40% total)  
**Result**: $100 item → $40 instead of $80

**Implementation**:
```python
# ❌ VULNERABLE (TOCTOU)
def apply_discount(code, order_total):
    # Step 1: Check if code used
    if db.code_used(code):
        raise Error("Code already used")
    
    # Step 2: Apply discount (NOT ATOMIC with Step 1)
    discount = db.get_discount_value(code)
    new_total = order_total * (1 - discount / 100)
    
    # Step 3: Mark code as used (separate from Steps 1-2)
    db.mark_code_used(code)
    
    return new_total

# ✅ SECURE (Atomic Transaction)
def apply_discount_secure(code, order_total):
    with db.transaction():
        # ALL operations in SINGLE transaction
        if db.code_used(code):
            raise Error("Code already used")
        
        discount = db.get_discount_value(code)
        new_total = order_total * (1 - discount / 100)
        
        db.mark_code_used(code)  # Atomic with check
        
        return new_total
```

---

### Type B: Single-Endpoint Race (Session Collision)

**Description**: Parallel requests to same endpoint with different values cause session state collision.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Send parallel requests to single endpoint with different parameters (usernames, tokens) |
| **Impact** | Token theft, user impersonation, password reset to wrong user |
| **Detection** | Test password reset, email confirmation, token generation endpoints |

#### 🎯 Example: Password Reset Token Collision

**Demo Scenario**: Password reset stores user ID and token in session

**Normal Flow (Single Request)**:
```text
POST /forgot-password (username=victim)
  1. session['reset-user'] = victim
  2. session['reset-token'] = 1234
  3. Send email to victim with token 1234
```

**Race Attack (Parallel Requests)**:
```text
Request 1: POST /forgot-password (username=attacker) [TIME T0]
  1. session['reset-user'] = attacker ← COLLISION!
  2. session['reset-token'] = 5678
  3. Send email to attacker with token 5678

Request 2: POST /forgot-password (username=victim) [TIME T+1ms]
  1. session['reset-user'] = victim ← OVERWRITES!
  2. session['reset-token'] = 5678 ← SAME TOKEN!
  3. Send email to victim with token 5678
```

**Expected Output**: Different tokens for each user  
**Actual Output**: SAME token (5678) for both users  
**Result**: Attacker resets victim's password using shared token

**Implementation**:
```python
# ❌ VULNERABLE (Session Updated Individually)
def forgot_password(username):
    session['reset-user'] = username  # Update 1
    token = generate_token()
    session['reset-token'] = token  # Update 2 (NOT ATOMIC)
    send_email(username, token)  # Background thread
    
# ✅ SECURE (Session Updated in Batch)
def forgot_password_secure(username):
    token = generate_token()
    
    # Single atomic session update
    session.update({
        'reset-user': username,
        'reset-token': token
    })
    
    send_email(username, token)
```

---

### Type C: Multi-Endpoint Race (Cart Manipulation)

**Description**: Multiple requests to different endpoints collide during multi-step workflow (payment → order confirmation).

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Send parallel requests to payment endpoint + cart modification endpoint |
| **Impact** | Add items after payment, bypass workflow validation, cheaper orders |
| **Detection** | Identify multi-step workflows (payment, confirmation, checkout) |

#### 🎯 Example: Add Items After Payment Validation

**Demo Scenario**: Online store validates payment, then confirms order

**Normal Flow (Sequential)**:
```text
1. Add item A (price $50) to cart
2. POST /payment (cart=[A], total=$50)
   a. Validate: Payment matches cart value → OK
   b. Confirm: Order created ✓
3. Order confirmation: Item A delivered
```

**Race Attack (Parallel)**:
```text
Request 1: POST /payment (cart=[A], total=$50) [TIME T0]
  a. Validate: Payment matches cart value → OK ✓ ← RACE WINDOW!
  b. Confirm: Order (completes at T+100ms)

Request 2: POST /cart/add (item=B, price=$50) [TIME T+1ms]
  - Add item B to cart ← ADDED AFTER PAYMENT!
  
Request 3: GET /order-confirmation
  - Order contains: Item A + Item B = $100 worth ✓
  - Paid: Only $50 ✗
```

**Expected Output**: $50 order (Item A only)  
**Actual Output**: $100 order (Items A + B) paid $50  
**Result**: $50 item stolen

**Implementation**:
```python
# ❌ VULNERABLE (Non-Atomic Payment Flow)
def process_payment(cart, payment_amount):
    # Step 1: Validate payment
    if payment_amount != calculate_cart_total(cart):
        raise Error("Invalid payment")
    
    # Step 2: Create order (NOT ATOMIC with Step 1)
    order = db.create_order(cart, payment_amount)
    
    return order

# ✅ SECURE (Atomic Transaction)
def process_payment_secure(cart, payment_amount):
    with db.transaction():
        # ALL in SINGLE transaction
        cart_total = calculate_cart_total(cart)
        
        if payment_amount != cart_total:
            raise Error("Invalid payment")
        
        # Clear cart BEFORE creating order
        db.clear_cart(cart.user_id)
        
        order = db.create_order(cart, payment_amount)
        
        return order
```

---

### Type D: Hidden Multi-Step Sequence (MFA Bypass)

**Description**: Single request transitions application through hidden sub-states (login → MFA enforcement), creating race window.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Send login request + sensitive endpoint request simultaneously |
| **Impact** | MFA bypass, authenticated access without second factor |
| **Detection** | Identify MFA workflows, session-based auth, multi-factor endpoints |

#### 🎯 Example: MFA Enforcement Race

**Demo Scenario**: Login creates session, then enforces MFA

**Normal Flow (Single Request)**:
```text
POST /login (username=attacker, password=correct)
  1. session['userid'] = attacker ← VALID SESSION
  2. session['enforce_mfa'] = True ← MFA ENFORCED
  3. Send MFA code to user
  4. Redirect to MFA entry form
```

**Race Attack (Parallel Requests)**:
```text
Request 1: POST /login (username=attacker, password=correct) [TIME T0]
  1. session['userid'] = attacker ← VALID SESSION
  2. session['enforce_mfa'] = True ← NOT YET SET!
  
Request 2: GET /sensitive-panel [TIME T+1ms]
  - Check: session['userid'] exists? → YES ✓
  - Check: session['enforce_mfa']? → NO ✗ ← RACE WINDOW!
  - Access: Sensitive panel granted ✓
```

**Expected Output**: MFA enforced before access  
**Actual Output**: Access granted before MFA enforcement  
**Result**: MFA bypassed via race condition

**Implementation**:
```python
# ❌ VULNERABLE (Session Updated Individually)
def login(username, password):
    user = db.get_user(username)
    
    if user.password != password:
        raise Error("Invalid credentials")
    
    session['userid'] = user.id  # Update 1
    session['enforce_mfa'] = user.mfa_enabled  # Update 2 (NOT ATOMIC)
    
    if user.mfa_enabled:
        send_mfa_code(user.email)
        redirect('/mfa-entry')
    
    redirect('/dashboard')

# ✅ SECURE (Atomic Session Update)
def login_secure(username, password):
    user = db.get_user(username)
    
    if user.password != password:
        raise Error("Invalid credentials")
    
    # Single atomic session update
    session.update({
        'userid': user.id,
        'enforce_mfa': user.mfa_enabled
    })
    
    if user.mfa_enabled:
        send_mfa_code(user.email)
        redirect('/mfa-entry')
    
    redirect('/dashboard')
```

---

### Type E: Partial Construction (Uninitialized State)

**Description**: Object creation in multiple steps leaves temporary middle state (user exists but API key uninitialized).

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Inject null/empty array value matching uninitialized database state |
| **Impact** | Email verification bypass, API authentication bypass, password bypass |
| **Detection** | Test user registration, API key creation, object initialization endpoints |

#### 🎯 Example: Email Verification Bypass via Empty Array

**Demo Scenario**: User registration creates user, then sets registration token

**Normal Flow (Sequential)**:
```text
POST /register (email=user@shop.com, username=newuser)
  1. INSERT user INTO users (id=100, token=NULL) ← USER EXISTS
  2. token = generate_token()
  3. UPDATE users WHERE id=100 SET token=5678 ← TOKEN SET
  4. Send email with token 5678

POST /confirm?token=5678
  - Check: token matches? → YES ✓
  - Action: Mark user verified ✓
```

**Race Attack (Parallel)**:
```text
Request 1: POST /register (email=user@shop.com, username=newuser) [TIME T0]
  1. INSERT user INTO users (id=100, token=NULL) ← USER CREATED
  2. token = generate_token()
  3. UPDATE users WHERE id=100 SET token=5678 (completes at T+50ms)

Request 2: POST /confirm?token[]= [TIME T+1ms]
  - token[]= sends empty array [] ← MATCHES NULL!
  - Check: token matches? → YES (NULL == []) ✓ ← RACE WINDOW!
  - Action: Mark user verified ✓
```

**Expected Output**: Token must match generated value (5678)  
**Actual Output**: Empty array [] matches uninitialized NULL  
**Result**: Email verification bypassed, account created

**Implementation**:
```python
# ❌ VULNERABLE (Multiple SQL Statements)
def register_user(email, username):
    # Step 1: Create user (token=NULL)
    user_id = db.execute(
        "INSERT INTO users (email, username, token) VALUES (?, ?, NULL)",
        [email, username]
    )
    
    # Step 2: Generate and set token (NOT ATOMIC)
    token = generate_token()
    db.execute(
        "UPDATE users SET token = ? WHERE id = ?",
        [token, user_id]
    )
    
    send_email(email, token)

# ✅ SECURE (Single Transaction)
def register_user_secure(email, username):
    with db.transaction():
        token = generate_token()
        
        # ONE atomic statement
        user_id = db.execute(
            "INSERT INTO users (email, username, token) VALUES (?, ?, ?)",
            [email, username, token]
        )
        
        send_email(email, token)
```

---

### Type F: Time-Sensitive Token (Timestamp Collision)

**Description**: Security tokens generated using timestamps instead of cryptographically secure random strings, enabling collision.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Trigger two password resets simultaneously to generate same timestamp |
| **Impact** | Token prediction, password reset to wrong user, session hijacking |
| **Detection** | Test token generation (password reset, email confirmation, session tokens) |

#### 🎯 Example: Same Password Reset Token via Timestamp

**Demo Scenario**: Password reset token uses timestamp

**Normal Flow**:
```text
POST /forgot-password (username=victim)
  token = hash(timestamp + secret)  # NOT RANDOM
  Send email with token
```

**Race Attack**:
```text
Request 1: POST /forgot-password (username=victim) [TIME T0:1234567890]
  token = hash(1234567890 + secret) = abc123

Request 2: POST /forgot-password (username=attacker) [TIME T0:1234567890]
  token = hash(1234567890 + secret) = abc123 ← SAME TOKEN!
```

**Expected Output**: Different tokens for each user  
**Actual Output**: SAME token (abc123)  
**Result**: Attacker resets victim's password

**Implementation**:
```python
# ❌ VULNERABLE (Timestamp-Based)
def generate_reset_token(username):
    timestamp = int(time.time())  # NOT SECURE
    secret = db.get_secret()
    token = hash(timestamp + secret + username)
    return token

# ✅ SECURE (Cryptographically Random)
def generate_reset_token_secure(username):
    token = secrets.token_urlsafe(32)  # SECURE RANDOM
    db.store_token(username, token)
    return token
```

---

### Type G: Rate Limit Bypass via Race

**Description**: Anti-brute-force rate limits bypassed by sending parallel requests to overflow limit counter.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Send 20-30 parallel requests to rate-limited endpoint simultaneously |
| **Impact** | Brute force passwords, overflow CAPTCHA, bypass anti-brute-force |
| **Detection** | Identify rate-limited endpoints (login, CAPTCHA, API) |

#### 🎯 Example: Password Brute Force via Rate Limit Overflow

**Demo Scenario**: Login endpoint allows 5 attempts per minute

**Normal Flow (Sequential)**:
```text
Attempt 1: POST /login (password=pass1) → OK (count=1)
Attempt 2: POST /login (password=pass2) → OK (count=2)
Attempt 3: POST /login (password=pass3) → OK (count=3)
Attempt 4: POST /login (password=pass4) → OK (count=4)
Attempt 5: POST /login (password=pass5) → OK (count=5)
Attempt 6: POST /login (password=pass6) → 403 Rate Limited ✗
```

**Race Attack (Parallel)**:
```text
Send 30 requests simultaneously:
for i in range(30):
  POST /login (password=pass{i}) [TIME T0]

All 30 requests processed before counter updates
Result: 30 attempts instead of 5 ✓
```

**Expected Output**: 5 attempts blocked, then rate limited  
**Actual Output**: 30 attempts processed (rate limit bypassed)  
**Result**: Brute force password in one attempt

**Implementation**:
```python
# ❌ VULNERABLE (Non-Atomic Counter)
def login(username, password):
    count = db.get_login_count(username)  # Step 1: Read
    
    if count >= 5:
        raise Error("Rate limited")
    
    # Step 2: Update (NOT ATOMIC)
    db.increment_login_count(username)
    
    if check_password(username, password):
        return "Login successful"
    raise Error("Invalid password")

# ✅ SECURE (Atomic Counter)
def login_secure(username, password):
    with db.transaction():
        count = db.get_login_count(username)
        
        if count >= 5:
            raise Error("Rate limited")
        
        db.increment_login_count(username)  # Atomic
        
        if check_password(username, password):
            return "Login successful"
        raise Error("Invalid password")
```

---

### Type H: PHP Session Locking Bypass

**Description**: PHP session handler processes one request per session at a time, but bypassed by using different session tokens.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Send parallel requests with different session cookies to bypass sequential processing |
| **Impact** | Race conditions masked by locking, collision attacks enabled |
| **Detection** | Notice sequential processing times, check for PHP session cookies |

#### 🎯 Example: Bypass Session Locking for Race Attack

**Demo Scenario**: PHP session only processes one request per session

**Normal Flow (Sequential)**:
```text
Request 1: POST /reset (session=abc123) → Takes 100ms
Request 2: POST /reset (session=abc123) → Takes 100ms (waits for Request 1)
Result: Sequential processing, NO RACE
```

**Bypass (Different Sessions)**:
```text
Request 1: POST /reset (session=abc123) → Takes 100ms
Request 2: POST /reset (session=xyz789) → Takes 100ms (parallel!)
Result: Concurrent processing, RACE POSSIBLE ✓
```

**Expected Output**: Sequential processing (no race)  
**Actual Output**: Parallel processing (race possible)  
**Result**: Race condition vulnerability exposed

**Implementation**:
```php
# ❌ VULNERABLE (Single Session)
// Request 1: Same session
session_start();  # Locks session
// Process request...
session_write_close();  # Unlocks

// Request 2: Same session (waits for Request 1)
session_start();  # Blocks until Request 1 completes

# ✅ SECURE (Multiple Sessions for Testing)
# Use different session cookies in Burp Repeater
Request 1: Cookie: session=abc123
Request 2: Cookie: session=xyz789
# Both process concurrently
```

---

### Type I: Gift Card Multiple Redeems

**Description**: Gift card balance depleted multiple times by exploiting race window between check and deduction.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Send parallel gift card redemption requests |
| **Impact** | Multiple redemptions, balance overflow, free products |
| **Detection** | Test gift card, promo code, voucher redemption endpoints |

#### 🎯 Example: Gift Card Redeemed Multiple Times

**Demo Scenario**: Gift card with $50 balance

**Normal Flow**:
```text
POST /redeem (card=ABC123, amount=$50)
  1. Check: balance >= $50? → YES ✓
  2. Deduct: balance = $0
  3. Add: $50 to order
```

**Race Attack**:
```text
Request 1: POST /redeem (card=ABC123, amount=$50) [TIME T0]
  1. Check: balance >= $50? → YES ✓ ← BOTH PASS
  2. Deduct: balance = $0 (completes at T+50ms)

Request 2: POST /redeem (card=ABC123, amount=$50) [TIME T+1ms]
  1. Check: balance >= $50? → YES ✓ ← RACE WINDOW!
  2. Deduct: balance = -$50 (completes at T+51ms)

Result: $100 redeemed from $50 gift card ✓
```

**Expected Output**: $50 redeemed (balance = $0)  
**Actual Output**: $100 redeemed (balance = -$50)  
**Result**: $50 free products

---
### Type J: CAPTCHA Solution Reuse

**Description**: Single CAPTCHA solution used multiple times by exploiting race window between validation and mark-as-used.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Send parallel requests with same CAPTCHA token |
| **Impact** | Brute force passwords, bypass anti-brute-force, multiple submissions |
| **Detection** | Test CAPTCHA endpoints (login, registration, form submission) |

#### 🎯 Example: CAPTCHA Reused for Multiple Login Attempts

**Demo Scenario**: Login requires one-time CAPTCHA

**Normal Flow**:
```text
POST /login (captcha=abc123, password=pass1)
  1. Check: CAPTCHA valid? → YES ✓
  2. Mark: CAPTCHA used ✓
  3. Check: Password correct?
```

**Race Attack**:
```text
Request 1: POST /login (captcha=abc123, password=pass1) [TIME T0]
  1. Check: CAPTCHA valid? → YES ✓ ← BOTH PASS
  2. Mark: CAPTCHA used (completes at T+100ms)

Request 2: POST /login (captcha=abc123, password=pass2) [TIME T+1ms]
  1. Check: CAPTCHA valid? → YES ✓ ← RACE WINDOW!
  2. Mark: CAPTCHA used (completes at T+101ms)

Result: Same CAPTCHA used for 2 password attempts ✓
```

**Expected Output**: CAPTCHA used once, then invalid  
**Actual Output**: CAPTCHA used twice (brute force enabled)  
**Result**: Multiple password attempts with one CAPTCHA

---

### Type K: Cash Withdrawal Balance Overflow

**Description**: Withdraw cash exceeding account balance by exploiting race window between check and deduction.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Send parallel withdrawal requests |
| **Impact** | Balance overflow, negative balance, free cash |
| **Detection** | Test withdrawal, transfer, payment endpoints |

#### 🎯 Example: Withdraw $1000 from $500 Account

**Demo Scenario**: Bank account with $500 balance

**Normal Flow**:
```text
POST /withdraw (amount=$500)
  1. Check: balance >= $500? → YES ✓
  2. Deduct: balance = $0
  3. Transfer: $500 to user
```

**Race Attack**:
```text
Request 1: POST /withdraw (amount=$500) [TIME T0]
  1. Check: balance >= $500? → YES ✓ ← BOTH PASS
  2. Deduct: balance = $0 (completes at T+100ms)

Request 2: POST /withdraw (amount=$500) [TIME T+1ms]
  1. Check: balance >= $500? → YES ✓ ← RACE WINDOW!
  2. Deduct: balance = -$500 (completes at T+101ms)

Result: $1000 withdrawn from $500 account ✓
```

**Expected Output**: $500 withdrawn (balance = $0)  
**Actual Output**: $1000 withdrawn (balance = -$500)  
**Result**: $500 free cash

---

### Type L: Product Rating Multiple Submissions

**Description**: Rate product multiple times (spam or manipulate rating) by exploiting race window.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Send parallel rating requests for same product |
| **Impact** | Rating spam, manipulated ratings, fake reviews |
| **Detection** | Test product rating, review submission endpoints |

#### 🎯 Example: Rate Product 10 Times Instead of 1

**Demo Scenario**: Users can rate product once

**Normal Flow**:
```text
POST /rate (product=123, rating=5)
  1. Check: Already rated? → NO ✓
  2. Add: Rating to product
  3. Mark: User rated product ✓
```

**Race Attack**:
```text
Send 10 parallel requests:
for i in range(10):
  POST /rate (product=123, rating=5) [TIME T0]

All 10 requests pass check before any mark completes
Result: 10 ratings instead of 1 ✓
```

**Expected Output**: 1 rating per user  
**Actual Output**: 10 ratings (rating manipulated)  
**Result**: Fake 5-star rating

---

### Type M: Single-Endpoint Race (Email Change Collision)

**Description**: Email change feature stores one pending email at a time, allowing collision when parallel requests change pending email to different values.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Send parallel requests to email change endpoint with different addresses |
| **Impact** | Claim arbitrary email address, inherit admin privileges, account takeover |
| **Detection** | Test email change, account update, profile modification endpoints |

#### 🎯 Example: Claim carlos@ginandjuice.shop for Admin Access

**Demo Scenario**: Email change sends confirmation to pending email, only one pending email stored

**Normal Flow (Sequential)**:
```text
Request 1: POST /change-email (email=test1@exploit.net)
  1. Set pending_email = test1@exploit.net
  2. Generate token = abc123
  3. Send email to test1@exploit.net with token abc123

Request 2: POST /change-email (email=test2@exploit.net)
  1. Set pending_email = test2@exploit.net ← OVERWRITES!
  2. Generate token = xyz789
  3. Send email to test2@exploit.net with token xyz789

Result: Only test2 receives valid confirmation link ✓
```

**Race Attack (Parallel)**:
```text
Request 1: POST /change-email (email=myaddr@exploit.net) [TIME T0]
  1. Set pending_email = myaddr@exploit.net
  2. Generate token = abc123
  3. Send email (background thread) ← NOT YET SENT!

Request 2: POST /change-email (email=carlos@ginandjuice.shop) [TIME T+1ms]
  1. Set pending_email = carlos@ginandjuice.shop ← OVERWRITES!
  2. Generate token = xyz789
  3. Send email (background thread)

Email 1 (sent at T+50ms): Uses pending_email = carlos@ginandjuice.shop ← WRONG EMAIL!
  - Body says: "Confirm change to carlos@ginandjuice.shop"
  - Sent to: myaddr@exploit.net ← RECEIVED BY ATTACKER!

Result: Attacker receives confirmation for carlos@ginandjuice.shop ✓
```

**Expected Output**: Confirmation sent to intended address  
**Actual Output**: Confirmation sent to wrong address (race collision)  
**Result**: Attacker claims carlos@ginandjuice.shop, gets admin access

**Implementation**:
```python
# ❌ VULNERABLE (Email Sent in Background Thread)
def change_email(user_id, new_email):
    # Step 1: Set pending email (only one stored)
    db.set_pending_email(user_id, new_email)
    
    # Step 2: Generate token
    token = generate_token()
    
    # Step 3: Send email in background (NOT ATOMIC)
    Thread(target=send_email, args=[new_email, token]).start()
    
    return "Confirmation sent"

# ✅ SECURE (Email Sent Immediately)
def change_email_secure(user_id, new_email):
    # Create confirmation record with email
    pending_email = db.create_pending_email(user_id, new_email)
    token = generate_token()
    
    # Send email immediately (synchronous)
    send_email(new_email, token, pending_email.id)
    
    return "Confirmation sent"
```

---

### Type N: Partial Construction (Password Bypass)

**Description**: Similar to Type E but with password instead of API key - inject value matching uninitialized hashed password.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Pass empty array/null value matching uninitialized password hash |
| **Impact** | Authentication bypass, account creation without password |
| **Detection** | Test user creation, password setting, authentication endpoints |

---

### Type O: Connection Warming Race Alignment

**Description**: Backend connection delays cause race windows to misalign; solved by warming connection with inconsequential requests first.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Add GET request to homepage before tab group, send in sequence (single connection) |
| **Impact** | Successfully align race windows for multi-endpoint attacks |
| **Detection** | Notice inconsistent response times on single endpoint, even with single-packet technique |

---

### Type P: Rate Limit Abuse for Delay Generation

**Description**: Intentionally trigger rate/resource limits with dummy requests to create server-side delay, making single-packet attack viable.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Send large number of dummy requests to trigger rate limit before main attack |
| **Impact** | Create suitable server-side delay for delayed execution attacks |
| **Detection** | Connection warming doesn't help, need server-side delay |

---

### Type Q: Time-Sensitive Attacks (High-Resolution Timestamps)

**Description**: High-resolution timestamps used instead of cryptographically secure random strings for security tokens, enabling prediction.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Trigger two password resets for different users at same timestamp |
| **Impact** | Token prediction, password reset to wrong user, session hijacking |
| **Detection** | Test token generation with timestamps (password reset, email confirmation) |

---

## 🔧 3. Detection & Exploitation Methodology

### Step 1: Predict Potential Collisions

**Questions to ask**:
- Is this endpoint security critical?
- Is there any collision potential? (2+ requests triggering operations on same record)

### Step 2: Probe for Clues

**Benchmarking**:
1. Send requests in sequence (separate connections)
2. Send requests in parallel (single-packet attack or last-byte sync)
3. Look for deviation from normal behavior (response changes, email content changes, app behavior changes)

**Tools**:
- **Burp Repeater**: Send group in sequence/parallel
- **Turbo Intruder**: Single-packet attack with custom Python
- **Trigger race conditions custom action**: One-click parallel requests (Professional only)

### Step 3: Prove the Concept

- Remove superfluous requests
- Make sure you can still replicate effects
- Think of race condition as structural weakness, not isolated vulnerability

---

## 🛡️ 4. Prevention Strategies

### Eliminate Sub-States from Sensitive Endpoints

1. **Avoid mixing data from different storage places** (sessions + database)
2. **Ensure atomic state changes** using datastore concurrency features:
   - Use single database transaction to check payment matches cart value AND confirm order
3. **Use column uniqueness constraints** for integrity
4. **Don't use one data storage layer to secure another** (sessions not suitable for preventing limit overruns on databases)
5. **Keep sessions internally consistent**:
   - Update session variables in batch, not individually
   - ORMs hide transactions concept but take full responsibility
6. **Avoid server-side state entirely** where appropriate:
   - Use encryption to push state client-side (JWTs)
   - Note: JWTs have own risks (see JWT attacks topic)

---

## 📚 5. Lab Solutions Summary

### Lab 1: Limit Overrun Race Conditions (Apprentice) - SOLVED
**Goal**: Purchase Lightweight L33t Leather Jacket  
**Method**: Apply discount code multiple times in parallel  
**Result**: 20% reduction applied more than once, cheaper order

### Lab 2: Multi-endpoint Race Conditions (Practitioner) - SOLVED
**Goal**: Purchase Lightweight L33t Leather Jacket  
**Method**: Add item to cart during race window between payment validation and order confirmation  
**Result**: Purchased at unintended price

### Lab 3: Bypassing Rate Limits via Race Conditions (Practitioner) - SOLVED
**Goal**: Brute-force password for user carlos  
**Method**: Send 20+ parallel login requests to overflow rate limit before lock triggered  
**Result**: More than 3 login attempts before account lock, found password

### Lab 4: Single-endpoint Race Conditions (Practitioner) - SOLVED
**Goal**: Claim carlos@ginandjuice.shop, get admin, delete carlos  
**Method**: Parallel email change requests cause confirmation sent to wrong address  
**Result**: Received confirmation for carlos@ginandjuice.shop, got admin access

### Lab 5: Partial Construction Race Conditions (Expert) - NOT SOLVED
**Goal**: Bypass email verification, register with arbitrary email, delete carlos  
**Method**: Pass empty array token[]= matching uninitialized NULL token  
**Status**: Requires multiple attempts, complex Turbo Intruder script

---

## 🎯 6. Key Takeaways

### When to Hunt for Race Conditions
- Single-use endpoints (promo codes, gift cards, CAPTCHA)
- Rate-limited endpoints (login, API calls)
- Multi-step workflows (payment → confirmation, login → MFA)
- Email-based operations (password reset, email change, registration)
- Object creation in multiple steps (user registration, API key generation)
- Token generation using timestamps

### Best Tools
- **Burp Repeater 2023.9+**: Single-packet attack (HTTP/2), last-byte sync (HTTP/1)
- **Turbo Intruder**: Custom Python for complex attacks, massive request volumes
- **Trigger race conditions custom action**: One-click testing (Professional)

### Critical Concepts
- **Race window**: Often milliseconds or shorter
- **Network jitter**: Neutralize with single-packet attack
- **Server-side jitter**: Mitigate with many parallel requests (20-50+)
- **Sub-states**: Temporary vulnerable states during request processing
- **TOCTOU**: Classic time-of-check to time-of-use flaw

---

## 📖 7. References & Whitepapers

- **Primary Whitepaper**: [Smashing the state machine: The true potential of web race conditions](https://portswigger.net/research/smashing-the-state-machine) (Black Hat USA 2023)
- **Burp Repeater Docs**: [Sending requests in parallel](https://portswigger.net/burp/documentation/desktop/tools/repeater/send-group#sending-requests-in-parallel)
- **Turbo Intruder Template**: [race-single-packet-attack.py](https://portswigger.net/bappstore/9abaa233088242e8be252cd4ff534988)
- **Custom Action**: [ProbeForRaceCondition.bambda](https://github.com/PortSwigger/bambdas/blob/main/CustomAction/ProbeForRaceCondition.bambda)

---
