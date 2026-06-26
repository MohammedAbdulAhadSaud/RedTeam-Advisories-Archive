# Business Logic Vulnerabilities

**Category**: Application Workflow & State Management Flaws  
**Severity**: High to Critical (Potential for Account Takeover, Financial Fraud & Complete Business Rule Circumvention)  
**CWE Mapping**: CWE-841 (Primary), CWE-1399 (Child)  
**OWASP Top 10**: A01:2021 - Broken Access Control, A03:2021 - Injection

---

##  What are Business Logic Vulnerabilities?

**Business Logic Vulnerabilities** (also known as **Logic Flaws**, **Application Logic Vulnerabilities**, or **Workflow Flaws**) are critical design and implementation flaws that allow attackers to elicit unintended behavior from an application by manipulating legitimate functionality to achieve malicious goals.

Unlike traditional vulnerabilities (SQL injection, XSS, etc.), logic flaws are **invisible to automated scanners** because they exploit the application's intended functionality in unexpected ways.

### Key Characteristics

| Characteristic | Description |
|----------------|-------------|
| **Scanner Invisible** | Automated tools cannot detect logic flaws (they follow expected workflows) |
| **Application Specific** | Each logic flaw is unique to the application's business domain |
| **Human Detection** | Requires domain knowledge and intuition to identify |
| **Workflow Based** | Exploits sequential dependencies and state management |
| **Assumption Driven** | Results from flawed developer assumptions about user behavior |

### Why They Occur

1. **Flawed assumptions** about user behavior during development
2. **Inadequate validation** of user input at server-side
3. **Failure to anticipate** unusual application states
4. **Weak client-side controls** that can be bypassed via intercepting proxies
5. **Overly complicated systems** that even developers don't fully understand

---

##  1. Low-Level Architectural Mechanics

### The Developer Assumption vs. Attacker Reality Gap

```text
[ Developer Assumption ] 
        │ (Users will follow intended workflow)
        ▼
[ Application Workflow Design ] 
        │ (Enforces business rules via client-side + server-side)
        ▼
[ User Interaction ] <── Attacker Bypasses Client-Side via Proxy
        │ (Uses intercepting proxy to modify requests)
        ▼
[ Server-Side Logic ] <── Missing Validation Allows Malicious State
        │ (Accepts unexpected input/sequence)
        ▼
[ Unintended Behavior Executed ]
```

### The Root Cause: Missing Server-Side Validation

Business logic vulnerabilities occur when developers:
- **Trust client-side controls** (JavaScript validation, hidden fields, cookies)
- **Assume linear workflow** (users won't skip steps or repeat actions)
- **Fail to validate state** (don't check if previous steps completed)
- **Ignore edge cases** (negative numbers, integer overflow, exceptional input)
- **Underestimate attacker goals** (don't anticipate privilege escalation, financial fraud)

---

## ⚙️ 2. Comprehensive Logic Flaw Typology Matrix

### Type A: Excessive Trust in Client-Side Controls

**Description**: Application relies on JavaScript, hidden fields, or cookies to validate input instead of server-side checks.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Bypass client-side validation using Burp Suite, modify request parameters directly |
| **Impact** | Purchase items at unintended price, submit invalid data, circumvent restrictions |
| **Detection** | Inspect JavaScript for validation logic, check if server accepts modified parameters |

#### 🎯 Example: Price Manipulation

**Demo Scenario**: Online store validates price in JavaScript before checkout

**Normal Request**:
```http
POST /cart/checkout HTTP/1.1
Host: shop.example.com
Content-Type: application/json

{
  "product_id": "jacket_1337",
  "quantity": 1,
  "price": 133.70
}
```

**Malicious Payload**:
```http
POST /cart/checkout HTTP/1.1
Host: shop.example.com
Content-Type: application/json

{
  "product_id": "jacket_1337",
  "quantity": 1,
  "price": 1.00
}
```

**Expected Output**: Server rejects (price ≠ $133.70)  
**Actual Output**: Server accepts (client-side validation only)  
**Result**: Purchase jacket for $1 instead of $133.70

**Implementation**:
```python
# ❌ VULNERABLE
def checkout(user_input):
    price = user_input['price']  # Trusts client-provided price
    total = price * user_input['quantity']
    return process_order(total)

# ✅ SECURE
def checkout_secure(user_input, user_session):
    product_id = user_input['product_id']
    quantity = user_input['quantity']
    
    # Fetch price from database (NOT from client)
    product = db.get_product(product_id)
    price = product['price']  # Server-controlled price
    total = price * quantity
    
    return process_order(total)
```

---

### Type B: Integer Overflow / Underflow in Financial Calculations

**Description**: Application uses fixed-size integers for price calculations without overflow protection.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Send large quantity values to cause integer overflow (positive → negative) |
| **Impact** | Negative total price, free items, store credit inflation |
| **Detection** | Test with large quantities (99, 999, 9999), monitor price behavior |

#### 🎯 Example: Integer Overflow Purchase

**Demo Scenario**: Store calculates total = price × quantity using 32-bit integer

**Payload**:
```http
POST /cart HTTP/1.1
Host: shop.example.com

product_id=jacket_1337&quantity=99999999
```

**Mathematical Breakdown**:

Jacket price = 133700 cents ($133.70)
Quantity = 99,999,999
Expected total = 133,699,998,333,000 cents

32-bit integer MAX = 2,147,483,647
Overflow occurs: 133,699,998,333,000 > 2,147,483,647

Result loops to: -2,147,483,648 (minimum 32-bit integer)
Final price = Negative → $0 or store credit refund


**Burp Intruder Configuration**:

Payload Type: Null payloads
Payload Configuration: Continue indefinitely
Resource Pool: Maximum concurrent requests = 1
Monitor: Refresh cart page while attack runs


**Expected Output**: Cart shows negative price (-$21,474,836.48)  
**Actual Output**: System processes order with negative total  
**Result**: Free jacket + $21,474,836.48 store credit refund

**Implementation**:
```python
# ❌ VULNERABLE
total = price * quantity  # Can overflow 32-bit integer

# ✅ SECURE
def safe_multiply(a, b, max_value=2147483647):
    result = a * b
    if result > max_value or result < -max_value:
        raise ValueError("Integer overflow detected")
    return result

total = safe_multiply(price, quantity)
```

---

### Type C: Infinite Money / Credit Inflation Loop

**Description**: Application allows repeated redemption of discounted gift cards without limiting frequency.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Automate buy → discount → redeem cycle to accumulate store credit |
| **Impact** | Unlimited store credit, free products, financial fraud |
| **Detection** | Test gift card redemption limits, coupon code reuse, refund loops |

#### 🎯 Example: Gift Card Redemption Loop

**Demo Scenario**: Store offers 30% discount on $10 gift cards via newsletter coupon

**Payload Sequence**:
```bash
# Step 1: Get coupon code
GET /newsletter-signup
Response: coupon_code = SIGNUP30

# Step 2: Buy discounted gift card
POST /cart
{ "product_id": "gift_card_10", "quantity": 1 }

POST /cart/coupon
{ "code": "SIGNUP30" }  # 30% discount applied

POST /cart/checkout
Response: gift_card_code = ABC123

# Step 3: Redeem for store credit
POST /gift-card?gift-card=ABC123
Response: credit_added = $10

# Step 4: Calculate profit
Cost = $7 (after 30% discount)
Credit = $10
Profit per cycle = $3
```

**Mathematical Breakdown**:

Gift card value = $10
Discount = 30% → Pay $7
Redeem = $10 credit
Profit per cycle = $3

Cycles needed for $1000 credit = 334
Total credit gained = 334 × $3 = $1,002


**Burp Session Handling Rule**:

Macro Sequence:

    POST /cart

    POST /cart/coupon

    POST /cart/checkout

    GET /cart/order-confirmation?order-confirmed=true

    POST /gift-card

Parameter Extraction:

    gift-card parameter from response 4 (order-confirmation)

    Inject into request 5 (POST /gift-card)

    
**Expected Output**: One-time gift card redemption ($10 credit)  
**Actual Output**: Unlimited repetitions ($1,002+ credit)  
**Result**: Free products worth $1,002+

**Implementation**:
```python
# ❌ VULNERABLE
def redeem_gift_card(user_session, gift_card_code):
    credit = get_gift_card_value(gift_card_code)
    user_session['credit'] += credit

# ✅ SECURE
def redeem_gift_card_secure(user_session, gift_card_code):
    # Check redemption frequency
    recent_redemptions = db.count_redemptions(user_session['id'], hours=24)
    if recent_redemptions >= 5:
        raise Error("Redemption limit exceeded")
    
    # Check for duplicate codes
    if db.is_already_redeemed(gift_card_code):
        raise Error("Gift card already redeemed")
    
    credit = get_gift_card_value(gift_card_code)
    user_session['credit'] += credit
    db.mark_redeemed(gift_card_code)
```

---

### Type D: Authentication Bypass via Encryption Oracle

**Description**: Application exposes encryption/decryption oracle allowing attackers to forge authenticated cookies.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Use input parameter to encrypt arbitrary data, decrypt via error reflection |
| **Impact** | Admin login, privilege escalation, account takeover |
| **Detection** | Check for encrypted cookies, error messages reflecting input, encryption oracle |

#### 🎯 Example: Cookie Forging via Encryption Oracle

**Demo Scenario**: Application uses encryption oracle in error messages to reflect decrypted data

**Payload Sequence**:
```bash
# Step 1: Encrypt arbitrary data via email parameter
POST /post/comment
email=administrator:1598530205184

# Step 2: Get encrypted ciphertext from cookie
Set-Cookie: notification=ENCRYPTED_CIPHERTEXT

# Step 3: Decrypt via notification cookie (reflects in error)
GET /post?postId=x
Cookie: notification=ENCRYPTED_CIPHERTEXT

# Error response: "Invalid email address: administrator:1598530205184"

# Step 4: Remove prefix (block alignment)
# Prefix = "Invalid email address: " (23 bytes)
# Block size = 16 bytes (AES)
# Padding needed = 9 bytes (to make 32 bytes = 2 × 16)

# Step 5: Encrypt without prefix
POST /post/comment
email=xxxxxxxxxadministrator:1598530205184

# Step 6: Use as stay-logged-in cookie
GET /
Cookie: stay-logged-in=ENCRYPTED_CIPHERTEXT (without prefix)
```

**Expected Output**: Login as regular user (wiener)  
**Actual Output**: Login as administrator  
**Result**: Admin panel access, user deletion, privilege escalation

**Implementation**:
```python
# ❌ VULNERABLE
def submit_comment(email):
    encrypted = encrypt(email)  # Can encrypt arbitrary data
    set_cookie('notification', encrypted)
    
    if not valid_email(email):
        error = decrypt(notification_cookie)  # Can decrypt arbitrary data
        return f"Invalid email: {error}"

# ✅ SECURE
def submit_comment_secure(email):
    # Validate email internally (no reflection)
    if not valid_email(email):
        return "Invalid email address"
    
    # Use secure cookie without decryption reflection
    encrypted_session = encrypt_session(user_id)
    set_cookie('session', encrypted_session)
```

---

### Type E: Inconsistent Security Controls (Admin Panel Exposure)

**Description**: Admin functionality exposed but access control relies on weak client-side checks or error messages.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Browse to `/admin` directly, analyze error messages for access hints |
| **Impact** | Admin panel access, user deletion, privilege escalation |
| **Detection** | Content discovery, directory browsing, error message analysis |

#### 🎯 Example: Direct Admin Access

**Demo Scenario**: Admin panel at `/admin` but access control shows domain requirement in error

**Payload**:
```http
GET /admin HTTP/1.1
Host: vulnerable-app.com
```

**Error Response**:

Access Denied: DontWannaCry employees only


**Attack insight**: Domain-based access control (not authentication-based)

**Bypass Payload**:
```http
POST /register HTTP/1.1
Host: vulnerable-app.com

email=very-long-string@dontwannacry.com.YOUR-EMAIL-ID.domain.net
```

**Expected Output**: Registration blocked (wrong domain)  
**Actual Output**: Registration accepted (domain validation bypassed)  
**Result**: Admin panel access granted

**Implementation**:
```python
# ❌ VULNERABLE
def access_admin(user_session):
    if user_session['is_admin']:  # Client-side flag
        return render_admin_panel()
    return "Access Denied"

# ✅ SECURE
def access_admin_secure(user_session, request):
    # Verify server-side authentication
    if not user_session['authenticated']:
        raise Error("Authentication required")
    
    # Verify server-side role
    user_role = db.get_user_role(user_session['id'])
    if user_role != 'admin':
        raise Error("Admin role required")
    
    return render_admin_panel()
```

---

### Type F: Email Parser Discrepancy (Domain Validation Bypass)

**Description**: Server uses different email parsing libraries for validation vs. email sending, causing domain check mismatch.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Use UTF-7/UTF-8 encoded email to bypass validation while email server interprets differently |
| **Impact** | Register with unauthorized domain, admin access, account takeover |
| **Detection** | Test encoded email formats (UTF-7, UTF-8, ISO-8859-1), compare validation vs. sending |

#### 🎯 Example: UTF-7 Encoding Bypass

**Demo Scenario**: Store restricts registration to `@ginandjuice.shop` domain

**Payload**:
```http
POST /register HTTP/1.1
Host: store.example.com

email=?utf-7?q?attacker&AEA-[EXPLOIT-SERVER-ID]&ACA-?=@ginandjuice.shop
```

**Encoding Breakdown**:

UTF-7 encoding: &AEA- = @, &ACA- = (space)

Validation server sees: @ginandjuice.shop (passes domain check)
Email server sees: attacker@[EXPLOIT-SERVER-ID] (sends confirmation to attacker)


**Expected Output**: Registration blocked (wrong domain)  
**Actual Output**: Registration accepted (validation bypassed)  
**Result**: Confirmation email sent to attacker's server, account activated

**Implementation**:
```python
# ❌ VULNERABLE
def register(email):
    # Validation: Uses Python's email library
    if not email.endswith('@authorized.com'):
        raise Error("Invalid domain")
    
    # Storage: Truncates to 255 chars (different behavior)
    db.save(email=email[:255])

# ✅ SECURE
def register_secure(email):
    # Validate AND store using same library
    validated_email = email_utils.normalize(email)[:255]
    
    if not validated_email.endswith('@authorized.com'):
        raise Error("Invalid domain")
    
    db.save(email=validated_email)
```

---

### Type G: Inconsistent Exceptional Input Handling (Email Truncation)

**Description**: Application truncates long email addresses after validation, allowing domain suffix injection.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Register with 255+ character email ending in `@authorized.com.YOUR-ID.domain.net` |
| **Impact** | Bypass domain validation, admin access, privilege escalation |
| **Detection** | Test maximal length inputs, analyze truncation behavior |

#### 🎯 Example: Email Truncation Bypass

**Demo Scenario**: Company restricts registration to `@dontwannacry.com` domain, truncates emails to 255 chars

**Payload**:
```http
POST /register HTTP/1.1
Host: company.example.com

email=very-long-string-200-chars@dontwannacry.com.YOUR-EMAIL-ID.web-security-academy.net
```

**Truncation Breakdown**:

Validation: Email = ...@dontwannacry.com.YOUR-EMAIL-ID... (passes domain check)
Storage: Email truncated to 255 chars = ...@dontwannacry.com (appears valid)
Result: Admin access granted due to @dontwannacry.com domain match


**Expected Output**: Registration blocked (unauthorized domain)  
**Actual Output**: Registration accepted (truncation bypass)  
**Result**: Admin panel access

**Implementation**:
```python
# ❌ VULNERABLE
def register(email):
    if '@authorized.com' not in email:
        raise Error("Invalid domain")
    db.save(email=email[:255])  # Truncation after validation

# ✅ SECURE
def register_secure(email):
    truncated_email = email[:255]
    if '@authorized.com' not in truncated_email:
        raise Error("Invalid domain")
    db.save(email=truncated_email)  # Validate after truncation
```

---

### Type H: Flawed Enforcement of Business Rules (Workflow Skipping)

**Description**: Application doesn't enforce sequential workflow steps (e.g., skip payment, repeat actions).

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Skip checkout steps, repeat quantity limits, bypass verification |
| **Impact** | Free items, circumvent restrictions, unauthorized access |
| **Detection** | Map workflow, test step skipping, repeat actions |

#### 🎯 Example: Checkout Step Skipping

**Demo Scenario**: E-commerce requires cart → checkout → payment flow

**Normal Flow**:

   1. POST /cart (add items)

   2. POST /checkout (enter shipping)

   3. POST /payment (enter credit card)

   4. GET /order-confirmation


**Malicious Payload (Skip Payment)**:
```http
POST /order-confirmation?order-confirmed=true HTTP/1.1
Host: shop.example.com

product_id=jacket_1337&quantity=1
```

**Expected Output**: Order rejected (payment not completed)  
**Actual Output**: Order processed (payment step skipped)  
**Result**: Free item

**Implementation**:
```python
# ❌ VULNERABLE
def checkout(user_session):
    total = calculate_total()
    process_payment(total)

# ✅ SECURE
def checkout_secure(user_session):
    # Verify all prerequisites completed
    if not user_session['cart_initialized']:
        raise Error("Cart not initialized")
    if not user_session['shipping_selected']:
        raise Error("Shipping not selected")
    if not user_session['payment_info_provided']:
        raise Error("Payment info required")
    
    total = calculate_total()
    process_payment(total)
```

---

### Type I: Race Condition / Timing Attacks

**Description**: Application allows concurrent requests to bypass single-use limits or rate limits.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Send multiple simultaneous requests to bypass coupon limits, gift card redeems |
| **Impact** | Double-spending, coupon reuse, limit bypass |
| **Detection** | Test concurrent requests, monitor for duplicate processing |

#### 🎯 Example: Coupon Code Double-Spending

**Demo Scenario**: Coupon code should be single-use only

**Payload (Concurrent Requests)**:
```bash
# Send 10 identical requests simultaneously
for i in {1..10}; do
  POST /cart/coupon?code=SIGNUP30 &
done

# All requests complete before database updates
```

**Expected Output**: First request succeeds, rest fail (single-use)  
**Actual Output**: All 10 requests succeed (race condition)  
**Result**: 10x discounted purchases

**Implementation**:
```python
# ❌ VULNERABLE
def apply_coupon(user_session, coupon_code):
    coupon = db.get_coupon(coupon_code)
    if coupon['used_by'] == user_session['id']:
        raise Error("Coupon already used")
    
    coupon['used_by'] = user_session['id']  # No atomic lock
    db.update_coupon(coupon)
    return coupon['discount']

# ✅ SECURE
def apply_coupon_secure(user_session, coupon_code):
    # Use database transaction with atomic lock
    with db.transaction():
        coupon = db.get_coupon(coupon_code)
        if coupon['used_by'] == user_session['id']:
            raise Error("Coupon already used")
        
        coupon['used_by'] = user_session['id']
        db.update_coupon(coupon)
    
    return coupon['discount']
```

---

### Type J: Vertical Privilege Escalation via Hidden Parameters

**Description**: Application exposes admin functionality via hidden parameters that aren't properly validated.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Modify user_id, role, is_admin parameters in requests to access admin functions |
| **Impact** | Admin panel access, user management, data breach |
| **Detection** | Check request parameters for hidden fields, test parameter modification |

#### 🎯 Example: User ID Manipulation

**Demo Scenario**: User profile page at `/profile?user_id=123`

**Normal Request**:
```http
GET /profile?user_id=123 HTTP/1.1
Host: app.example.com
Cookie: session=wiener_session
```

**Malicious Payload**:
```http
GET /profile?user_id=1 HTTP/1.1
Host: app.example.com
Cookie: session=wiener_session
```

**Expected Output**: Access denied (user_id ≠ session user)  
**Actual Output**: Admin profile data returned (no validation)  
**Result**: Admin account information disclosed

**Implementation**:
```python
# ❌ VULNERABLE
def get_profile(request):
    user_id = request.params['user_id']
    return db.get_user(user_id)

# ✅ SECURE
def get_profile_secure(request, user_session):
    user_id = request.params['user_id']
    
    # Verify user_id matches session
    if user_id != user_session['user_id']:
        raise Error("Unauthorized")
    
    return db.get_user(user_id)
```

---

### Type K: Horizontal Privilege Escalation via IDOR

**Description**: Application allows accessing other users' data by manipulating resource IDs.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Change order_id, document_id, message_id to access other users' data |
| **Impact** | Data breach, privacy violation, account takeover |
| **Detection** | Test resource ID manipulation, check for authorization validation |

#### 🎯 Example: Order ID Manipulation (IDOR)

**Demo Scenario**: User can view order details at `/order?order_id=456`

**Normal Request**:
```http
GET /order?order_id=456 HTTP/1.1
Host: shop.example.com
Cookie: session=wiener_session
```

**Malicious Payload**:
```http
GET /order?order_id=457 HTTP/1.1
Host: shop.example.com
Cookie: session=wiener_session
```

**Expected Output**: Access denied (order_id belongs to other user)  
**Actual Output**: Other user's order data returned (no validation)  
**Result**: Competitor's order details disclosed (pricing, customer data)

**Implementation**:
```python
# ❌ VULNERABLE
def get_order(request):
    order_id = request.params['order_id']
    return db.get_order(order_id)

# ✅ SECURE
def get_order_secure(request, user_session):
    order_id = request.params['order_id']
    order = db.get_order(order_id)
    
    # Verify order belongs to requesting user
    if order['user_id'] != user_session['user_id']:
        raise Error("Unauthorized")
    
    return order
```

---

### Type L: Mass Assignment via Parameter Pollution

**Description**: Application accepts unexpected parameters and assigns them to object properties.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Add role=admin, is_verified=true, balance=9999 parameters to user updates |
| **Impact** | Privilege escalation, data manipulation, account takeover |
| **Detection** | Test parameter injection, check for unexpected field assignments |

#### 🎯 Example: Role Assignment via Parameter Injection

**Demo Scenario**: User profile update at `/profile/update`

**Normal Request**:
```http
POST /profile/update HTTP/1.1
Host: app.example.com

username=wiener&email=wiener@example.com
```

**Malicious Payload**:
```http
POST /profile/update HTTP/1.1
Host: app.example.com

username=wiener&email=wiener@example.com&role=admin&is_verified=true
```

**Expected Output**: Only username/email updated (role ignored)  
**Actual Output**: Role = admin assigned (mass assignment)  
**Result**: Admin privileges granted

**Implementation**:
```python
# ❌ VULNERABLE
def update_profile(request, user_session):
    user = db.get_user(user_session['user_id'])
    
    # Assign ALL parameters (including role, is_verified)
    for key, value in request.params.items():
        user[key] = value
    
    db.update_user(user)

# ✅ SECURE
def update_profile_secure(request, user_session):
    user = db.get_user(user_session['user_id'])
    
    # Assign ONLY allowed fields
    allowed_fields = ['username', 'email', 'avatar']
    for key in allowed_fields:
        if key in request.params:
            user[key] = request.params[key]
    
    db.update_user(user)
```
### Type M: Coupon/Discount Stacking Abuse

**Description**: Application doesn't prevent multiple discounts from being applied simultaneously when they should be mutually exclusive.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Apply multiple coupon codes, combine seasonal + referral discounts |
| **Impact** | Massive price reduction, financial loss, revenue theft |
| **Detection** | Test coupon code combinations, check discount logic in JavaScript |

#### 🎯 Example: Double Discount Stacking

**Demo Scenario**: Store allows 30% newsletter coupon + 20% first-order discount

**Payload**:
```http
POST /cart/coupon HTTP/1.1
Host: shop.example.com

code=SIGNUP30&code=FIRST20
```

**Alternative Payload**:
```http
POST /cart/checkout HTTP/1.1
Host: shop.example.com

{
  "product_id": "laptop_999",
  "quantity": 1,
  "original_price": 999.00,
  "discounts": ["SIGNUP30", "FIRST20", "LOYALTY10"]
}
```

**Expected Output**: Only one discount applied (max 30%)  
**Actual Output**: All discounts stacked (30% + 20% + 10% = 60%)  
**Result**: Laptop priced at $399 instead of $999

**Implementation**:
```python
# ❌ VULNERABLE
def apply_discounts(price, discount_codes):
    total_discount = 0
    for code in discount_codes:
        discount = db.get_discount(code)
        total_discount += discount['percentage']
    return price * (1 - total_discount / 100)

# ✅ SECURE
def apply_discounts_secure(price, discount_codes):
    # Only allow highest single discount
    max_discount = 0
    for code in discount_codes:
        discount = db.get_discount(code)
        max_discount = max(max_discount, discount['percentage'])
    
    # Or enforce mutual exclusivity
    allowed_categories = ['newsletter', 'first-order']
    used_categories = set()
    total_discount = 0
    
    for code in discount_codes:
        discount = db.get_discount(code)
        if discount['category'] not in used_categories:
            total_discount += discount['percentage']
            used_categories.add(discount['category'])
    
    return price * (1 - total_discount / 100)
```

---

### Type N: Refund/Return Logic Flaws

**Description**: Application allows refund abuse through repeated returns, price manipulation after purchase, or refund-to-different-account attacks.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Request multiple refunds, buy low-price item → return at high price, refund to different account |
| **Impact** | Financial fraud, revenue loss, account takeover |
| **Detection** | Test refund endpoints, check price validation, verify refund destination |

#### 🎯 Example: Price Manipulation Refund

**Demo Scenario**: Store processes refunds based on user-provided price at time of request

**Purchase (Normal)**:
```http
POST /cart/checkout HTTP/1.1
Host: shop.example.com

product_id=jacket&quantity=1&price=100
Response: order_id=12345
```

**Refund (Malicious)**:
```http
POST /refund HTTP/1.1
Host: shop.example.com

order_id=12345&refund_amount=1000
```

**Expected Output**: Refund = $100 (original purchase price)  
**Actual Output**: Refund = $1,000 (user-manipulated price)  
**Result**: $900 profit from single item

**Implementation**:
```python
# ❌ VULNERABLE
def process_refund(order_id, refund_amount):
    order = db.get_order(order_id)
    db.add_credit(order['user_id'], refund_amount)

# ✅ SECURE
def process_refund_secure(order_id, requested_amount):
    order = db.get_order(order_id)
    
    # Verify order exists and is eligible for refund
    if order['status'] != 'completed':
        raise Error("Order not eligible for refund")
    
    if order['refunded']:
        raise Error("Order already refunded")
    
    # Use original purchase price (NOT user-provided)
    actual_refund = min(requested_amount, order['total_price'])
    db.add_credit(order['user_id'], actual_refund)
    order['refunded'] = True
    db.update_order(order)
```

---

### Type O: Waiting Room/Queue Bypass

**Description**: Application doesn't properly validate queue tokens, allowing attackers to skip waiting rooms (ticket sales, product launches).

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Forge queue tokens, manipulate wait time parameters, reuse expired tokens |
| **Impact** | Early access to limited inventory, unfair advantage |
| **Detection** | Inspect queue token generation, test token validation, check wait time logic |

#### 🎯 Example: Queue Token Forgery

**Demo Scenario**: Concert ticket sale requires queue token with wait time

**Normal Queue Entry**:
```http
GET /queue HTTP/1.1
Host: tickets.example.com

Response: queue_token=abc123&wait_time=300
```

**Malicious Payload**:
```http
GET /ticket-purchase HTTP/1.1
Host: tickets.example.com
Cookie: queue_token=abc123

{
  "queue_token": "abc123",
  "wait_time": 0,
  "ticket_id": "VIP_section"
}
```

**Alternative (Token Reuse)**:
```http
# Save valid token from friend who waited
GET /ticket-purchase HTTP/1.1
Cookie: queue_token=FRIEND_TOKEN

# Use friend's token to bypass queue
```

**Expected Output**: Queue enforced (5-minute wait)  
**Actual Output**: Immediate purchase access  
**Result**: VIP tickets purchased before regular users

**Implementation**:
```python
# ❌ VULNERABLE
def purchase_ticket(queue_token, ticket_id):
    token_data = parse_token(queue_token)
    # No validation of wait time or token expiry
    return sell_ticket(ticket_id)

# ✅ SECURE
def purchase_ticket_secure(queue_token, ticket_id, user_session):
    token_data = verify_token(queue_token)
    
    # Validate token exists and belongs to user
    if token_data['user_id'] != user_session['user_id']:
        raise Error("Invalid token")
    
    # Check token not expired
    if token_data['expires_at'] < datetime.now():
        raise Error("Token expired")
    
    # Verify wait time completed
    if token_data['wait_time_completed'] < token_data['required_wait']:
        raise Error("Queue not completed")
    
    return sell_ticket(ticket_id)
```

---

### Type P: Subscription Free-Trial Abuse

**Description**: Application allows unlimited trial resets through email manipulation, cookie clearing, or identity spoofing.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Create multiple accounts with similar emails, clear trial cookies, use different payment methods |
| **Impact** | Free permanent access, revenue loss |
| **Detection** | Test trial reset mechanisms, check email validation, verify payment method uniqueness |

#### 🎯 Example: Trial Email Enumeration

**Demo Scenario**: Service offers 30-day free trial, tracks by email domain

**Payload Sequence**:
```bash
# Trial 1
POST /signup
email=user1@example.com → Trial activated

# Trial 2 (after 29 days)
POST /signup
email=user2@example.com → New trial activated

# Trial 3-100...
email=user3@example.com
email=user4@example.com
...
```

**Alternative (Plus Addressing)**:
```bash
# Gmail plus addressing bypasses email uniqueness
POST /signup
email=user+trial1@gmail.com → Trial 1
POST /signup
email=user+trial2@gmail.com → Trial 2
POST /signup
email=user+trial3@gmail.com → Trial 3
```

**Expected Output**: One trial per user (30 days)  
**Actual Output**: Unlimited trials (permanent free access)  
**Result**: $300/month service used forever without payment

**Implementation**:
```python
# ❌ VULNERABLE
def activate_trial(email):
    if not db.is_trial_used(email):
        db.create_trial(email, days=30)

# ✅ SECURE
def activate_trial_secure(email, payment_method, user_ip):
    # Normalize email (remove plus addressing)
    normalized_email = normalize_email(email)  # user@gmail.com
    
    # Check multiple identifiers
    if db.is_trial_used(normalized_email):
        raise Error("Trial already used")
    
    if db.is_trial_used_by_payment(payment_method):
        raise Error("Trial already used with this payment")
    
    if db.is_trial_used_by_ip(user_ip):
        raise Error("Trial already used from this device")
    
    db.create_trial(normalized_email, days=30)
    db.record_trial_payment(payment_method)
    db.record_trial_ip(user_ip)
```

---

### Type Q: Loyalty Points Manipulation

**Description**: Application allows points accumulation abuse through review spamming, fake purchases, or referral loops.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Spam reviews for points, create fake accounts for referrals, buy-sell-return loops |
| **Impact** | Points inflation, free products, unauthorized discounts |
| **Detection** | Test points attribution logic, check review validation, verify referral uniqueness |

#### 🎯 Example: Referral Loop Abuse

**Demo Scenario**: Store gives 100 points ($10) for each referral

**Payload Sequence**:
```bash
# Step 1: Create main account
POST /signup
email=attacker@example.com
Response: user_id=1001

# Step 2: Create 100 fake accounts
for i in {1..100}; do
  POST /signup
  email=fake$i@example.com
  POST /referral
  referrer_code=attacker_1001
done

# Step 3: Collect points
GET /my-points
Response: 10,000 points ($1000 value)
```

**Expected Output**: 100 points per month (normal usage)  
**Actual Output**: 10,000 points (100 fake referrals)  
**Result**: $1,000 free products

**Implementation**:
```python
# ❌ VULNERABLE
def add_referral_points(referrer_email, new_user_email):
    points = db.get_referral_points()
    db.add_points(referrer_email, points)

# ✅ SECURE
def add_referral_points_secure(referrer_id, new_user_id, new_user_email, payment_method):
    # Verify new user is real (made purchase)
    if not db.has_purchase(new_user_id):
        raise Error("Referral must make purchase")
    
    # Check referral not duplicate
    if db.is_duplicate_referral(referrer_id, new_user_id):
        raise Error("Duplicate referral")
    
    # Limit monthly referrals
    monthly_referrals = db.count_monthly_referrals(referrer_id)
    if monthly_referrals >= 10:
        raise Error("Monthly referral limit exceeded")
    
    # Verify different email domain/payment
    if db.same_domain_referral(referrer_id, new_user_email):
        raise Error("Same domain not allowed")
    
    if db.same_payment_referral(referrer_id, payment_method):
        raise Error("Same payment not allowed")
    
    points = db.get_referral_points()
    db.add_points(referrer_id, points)
    db.record_referral(referrer_id, new_user_id)
```

---

### Type R: Multi-Tenant Data Leakage

**Description**: Application fails to properly isolate data between organizations/users in SaaS platforms.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Manipulate organization_id, company_id, tenant_id parameters to access other organizations' data |
| **Impact** | Corporate data breach, competitive intelligence, privacy violation |
| **Detection** | Test resource IDs across organizations, check tenant validation, verify data isolation |

#### 🎯 Example: Organization ID Manipulation

**Demo Scenario**: SaaS platform at `/documents?org_id=500`

**Normal Request (Company A)**:
```http
GET /documents?org_id=500 HTTP/1.1
Host: saas.example.com
Cookie: session=company_a_token
```

**Malicious Payload**:
```http
GET /documents?org_id=501 HTTP/1.1
Host: saas.example.com
Cookie: session=company_a_token
```

**Expected Output**: Access denied (org_id ≠ session organization)  
**Actual Output**: Company B's documents returned (no validation)  
**Result**: Competitor's confidential documents disclosed

**Implementation**:
```python
# ❌ VULNERABLE
def get_documents(request, user_session):
    org_id = request.params['org_id']
    return db.get_documents(org_id)

# ✅ SECURE
def get_documents_secure(request, user_session):
    org_id = request.params['org_id']
    
    # Verify user belongs to organization
    user_org = db.get_user_organization(user_session['user_id'])
    if user_org['org_id'] != org_id:
        raise Error("Unauthorized")
    
    # Verify organization exists and is active
    org = db.get_organization(org_id)
    if not org or not org['active']:
        raise Error("Organization not found")
    
    return db.get_documents(org_id)
```

---

### Type S: API Rate Limit Bypass

**Description**: Application doesn't rate limit API endpoints properly, allowing brute force or enumeration attacks.

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Rotate IP addresses, use multiple API keys, manipulate rate limit headers |
| **Impact** | Brute force passwords, enumerate user data, exhaust API quotas |
| **Detection** | Test rate limit enforcement, check IP/API key validation, verify header trust |

#### 🎯 Example: Rate Limit Header Manipulation

**Demo Scenario**: API limits 100 requests/minute, trusts client-provided header

**Normal Request**:
```http
GET /api/users HTTP/1.1
Host: api.example.com
Response: X-RateLimit-Remaining: 99
```

**Malicious Payload**:
```http
GET /api/users HTTP/1.1
Host: api.example.com
X-RateLimit-Remaining: 1000

# Repeat 1000 times
```

**Alternative (API Key Rotation)**:
```bash
# Generate 1000 API keys (if registration unlimited)
for i in {1..1000}; do
  POST /api/key-gen
  Response: api_key=key_$i
  
  GET /api/users HTTP/1.1
  api_key=key_$i
done
```

**Expected Output**: 100 requests/minute enforced  
**Actual Output**: Unlimited requests (header manipulation)  
**Result**: 10,000 user records enumerated

**Implementation**:
```python
# ❌ VULNERABLE
def rate_limit_check(request):
    remaining = request.headers['X-RateLimit-Remaining']
    if remaining <= 0:
        raise Error("Rate limit exceeded")
    return True

# ✅ SECURE
def rate_limit_check_secure(user_id, endpoint):
    # Track server-side (NOT client headers)
    key = f"rate_limit:{user_id}:{endpoint}"
    current_count = redis.get(key) or 0
    
    if current_count >= 100:
        raise Error("Rate limit exceeded")
    
    redis.incr(key)
    redis.expire(key, 60)  # 1 minute window
    
    return True
```

---

### Type T: Time-Based Logic Flaws

**Description**: Application doesn't properly validate time-based constraints (auctions, flash sales, limited-time offers).

| Aspect | Details |
|--------|---------|
| **Attack Vector** | Manipulate client timestamps, exploit timezone differences, use server time drift |
| **Impact** | Early access to sales, extended trial periods, auction manipulation |
| **Detection** | Test time validation, check timezone handling, verify server vs. client time |

#### 🎯 Example: Flash Sale Time Manipulation

**Demo Scenario**: Flash sale starts at 12:00 PM EST, validates timestamp client-side

**Normal Request (Before Sale)**:
```http
POST /purchase HTTP/1.1
Host: sale.example.com
Timestamp: 2024-06-20T11:59:00Z

{ "product": "limited_item", "quantity": 1 }
```

**Expected Output**: "Sale not started yet"  
**Actual Output**: Purchase accepted (client timestamp trusted)

**Malicious Payload**:
```http
POST /purchase HTTP/1.1
Host: sale.example.com
Timestamp: 2024-06-20T12:01:00Z  # Fake future time

{ "product": "limited_item", "quantity": 1 }
```

**Result**: Purchase made 1 minute before sale officially started

**Implementation**:
```python
# ❌ VULNERABLE
def purchase_flash_sale(request, product):
    client_timestamp = request.headers['Timestamp']
    sale_start = datetime.parse("2024-06-20T12:00:00Z")
    
    if client_timestamp < sale_start:
        raise Error("Sale not started")
    
    return process_purchase(product)

# ✅ SECURE
def purchase_flash_sale_secure(request, product):
    # Use SERVER time (NOT client timestamp)
    server_timestamp = datetime.now(timezone.utc)
    sale_start = datetime.parse("2024-06-20T12:00:00Z")
    
    if server_timestamp < sale_start:
        raise Error("Sale not started")
    
    # Check sale not ended
    sale_end = datetime.parse("2024-06-20T18:00:00Z")
    if server_timestamp > sale_end:
        raise Error("Sale ended")
    
    return process_purchase(product)
```

---

## 📊 **UPDATED COMPLETE TYPE SUMMARY:**

| Type | Vulnerability Name | Primary Impact |
|------|-------------------|----------------|
| A | Excessive Trust in Client-Side Controls | Price manipulation |
| B | Integer Overflow/Underflow | Free items, credit inflation |
| C | Infinite Money/Credit Loop | Unlimited store credit |
| D | Authentication Bypass via Encryption Oracle | Admin access |
| E | Inconsistent Security Controls | Admin panel exposure |
| F | Email Parser Discrepancy | Domain validation bypass |
| G | Email Truncation | Domain validation bypass |
| H | Workflow Skipping | Free items |
| I | Race Condition/Timing Attacks | Double-spending |
| J | Vertical Privilege Escalation | Admin access |
| K | Horizontal Privilege Escalation (IDOR) | Data breach |
| L | Mass Assignment | Privilege escalation |
| M | Coupon/Discount Stacking | Revenue theft |
| N | Refund/Return Logic Flaws | Financial fraud |
| O | Waiting Room/Queue Bypass | Early access |
| P | Subscription Free-Trial Abuse | Free permanent access |
| Q | Loyalty Points Manipulation | Points inflation |
| R | Multi-Tenant Data Leakage | Corporate data breach |
| S | API Rate Limit Bypass | Brute force/enumeration |
| T | Time-Based Logic Flaws | Early/extended access |

---

**Total: 20 comprehensive business logic vulnerability types**

---

## 🛠️ 3. Testing & Detection Framework

### A. Workflow Mapping (Content Discovery)

```bash
# Step 1: Discover all endpoints
Burp Suite → Target → Site map → Right-click domain
Engagement tools → Discover content

# Step 2: Analyze workflow
1. Registration → Login → Browse → Add to Cart → Checkout → Payment
2. Identify state dependencies (e.g., must login before checkout)
3. Test skipping steps (go directly to /checkout without cart)
```

### B. Parameter Manipulation Testing

| Parameter Type | Test Values |
|----------------|-------------|
| **Quantity** | 0, -1, 99, 999, 99999999, MAX_INT |
| **Price** | 0, -1, 0.01, 999999.99 |
| **IDs** | -1, 0, MAX_INT, non-existent IDs |
| **Strings** | 255+ chars, 1000+ chars, null bytes |
| **Cookies** | Modified values, expired timestamps |

### C. State Manipulation Testing

```bash
# Test 1: Repeat actions
- Add same item to cart multiple times
- Redeem same gift card multiple times
- Apply coupon code multiple times

# Test 2: Skip steps
- POST /checkout without /cart
- POST /payment without /checkout
- Access /admin without login

# Test 3: Reverse steps
- Submit order → Cancel → Resubmit
- Redeem gift card → Refund → Redeem again
```

### D. Exceptional Input Testing

```bash
# Test edge cases
- Empty strings: param=""
- Null values: param=null
- Max length: param=2000-chars
- Special chars: param=<script>&"'/
- Encoding: UTF-7, UTF-8, Base64, URL-encoded
```

---

## 🛡️ 4. Defensive Engineering & Remediation

### ✅ Primary Defense: Server-Side Validation of All Business Rules

```python
# ❌ VULNERABLE: Client-side only validation
def checkout(user_input):
    price = user_input['price']  # Trusts client-provided price
    quantity = user_input['quantity']
    total = price * quantity
    return process_order(total)

# ✅ SECURE: Server validates against database
def checkout_secure(user_input, user_session):
    product_id = user_input['product_id']
    quantity = user_input['quantity']
    
    # Validate quantity server-side
    if quantity <= 0 or quantity > 100:
        raise ValueError("Invalid quantity")
    
    # Fetch price from database (NOT from client)
    product = db.get_product(product_id)
    price = product['price']  # Server-controlled price
    total = price * quantity
    
    # Validate user has sufficient credit
    if user_session['credit'] < total:
        raise ValueError("Insufficient credit")
    
    return process_order(total)
```

---

### ✅ Secondary Defense: Integer Overflow Protection

```python
# ❌ VULNERABLE: No overflow check
total = price * quantity  # Can overflow 32-bit integer

# ✅ SECURE: Overflow protection
def safe_multiply(a, b, max_value=2147483647):
    result = a * b
    if result > max_value or result < -max_value:
        raise ValueError("Integer overflow detected")
    return result

total = safe_multiply(price, quantity)
```

---

### ✅ Third Defense: Workflow State Validation

```python
# ❌ VULNERABLE: No state checking
def checkout(user_session):
    total = calculate_total()
    process_payment(total)

# ✅ SECURE: State validation
def checkout_secure(user_session):
    # Verify all prerequisites completed
    if not user_session['cart_initialized']:
        raise Error("Cart not initialized")
    if not user_session['shipping_selected']:
        raise Error("Shipping not selected")
    if not user_session['payment_info_provided']:
        raise Error("Payment info required")
    
    total = calculate_total()
    process_payment(total)
```

---

### ✅ Fourth Defense: Rate Limiting & Frequency Checks

```python
# ❌ VULNERABLE: No limits on gift card redemption
def redeem_gift_card(user_session, gift_card_code):
    credit = get_gift_card_value(gift_card_code)
    user_session['credit'] += credit

# ✅ SECURE: Rate limiting
def redeem_gift_card_secure(user_session, gift_card_code):
    # Check redemption frequency
    recent_redemptions = db.count_redemptions(user_session['id'], hours=24)
    if recent_redemptions >= 5:
        raise Error("Redemption limit exceeded")
    
    # Check for duplicate codes
    if db.is_already_redeemed(gift_card_code):
        raise Error("Gift card already redeemed")
    
    credit = get_gift_card_value(gift_card_code)
    user_session['credit'] += credit
    db.mark_redeemed(gift_card_code)
```

---

### ✅ Fifth Defense: Consistent Parsing & Truncation

```python
# ❌ VULNERABLE: Different parsing for validation vs. storage
def register(email):
    # Validation: Uses Python's email library
    if not email.endswith('@authorized.com'):
        raise Error("Invalid domain")
    
    # Storage: Truncates to 255 chars (different behavior)
    db.save(email=email[:255])

# ✅ SECURE: Consistent parsing
def register_secure(email):
    # Validate AND store using same library
    validated_email = email_utils.normalize(email)[:255]
    
    if not validated_email.endswith('@authorized.com'):
        raise Error("Invalid domain")
    
    db.save(email=validated_email)
```

---

### ✅ Sixth Defense: Encryption Oracle Protection

```python
# ❌ VULNERABLE: Exposes encryption/decryption oracle
def submit_comment(email):
    encrypted = encrypt(email)  # Can encrypt arbitrary data
    set_cookie('notification', encrypted)
    
    if not valid_email(email):
        error = decrypt(notification_cookie)  # Can decrypt arbitrary data
        return f"Invalid email: {error}"

# ✅ SECURE: No oracle exposure
def submit_comment_secure(email):
    # Validate email internally (no reflection)
    if not valid_email(email):
        return "Invalid email address"
    
    # Use secure cookie without decryption reflection
    encrypted_session = encrypt_session(user_id)
    set_cookie('session', encrypted_session)
```

---

## 📋 5. Business Logic Testing Checklist

### Workflow Testing
- ✅ Map complete application workflow (registration → login → purchase)
- ✅ Test skipping workflow steps (direct POST to checkout)
- ✅ Test repeating actions (add same item multiple times)
- ✅ Test reversing actions (cancel order → resubmit)
- ✅ Test parallel workflows (multiple carts, multiple sessions)

### Parameter Testing
- ✅ Test quantity: 0, -1, 99, 999, MAX_INT
- ✅ Test price: 0, -1, 0.01, MAX_PRICE
- ✅ Test IDs: -1, 0, MAX_INT, non-existent
- ✅ Test strings: 255 chars, 1000 chars, null bytes
- ✅ Test encoding: UTF-7, UTF-8, Base64, URL-encoded

### State Testing
- ✅ Test session state dependencies (must login before checkout)
- ✅ Test cookie manipulation (modify encrypted cookies)
- ✅ Test timestamp manipulation (expired tokens, future dates)
- ✅ Test cached state (bypass cache, force refresh)

### Edge Case Testing
- ✅ Test empty inputs: param=""
- ✅ Test null values: param=null
- ✅ Test special characters: <script>&"'/
- ✅ Test boundary values: MIN_INT, MAX_INT
- ✅ Test exceptional input: Unicode, emojis, binary data

### Business Rule Testing
- ✅ Test purchase limits (quantity caps, daily limits)
- ✅ Test discount rules (coupon reuse, stacking discounts)
- ✅ Test refund policies (duplicate refunds, refund loops)
- ✅ Test access controls (admin panels, restricted features)
- ✅ Test domain validations (email registration, whitelist checks)

---

## 🎓 6. Key Takeaways

| Principle | Description |
|-----------|-------------|
| **Server-Side Validation** | Never trust client-provided data; validate all business rules server-side |
| **No Implicit Assumptions** | Don't assume users follow intended workflows; enforce state dependencies |
| **Overflow Protection** | Use arbitrary-precision integers or validate against MAX_INT |
| **Rate Limiting** | Limit frequency of sensitive actions (redemptions, purchases, registrations) |
| **Consistent Parsing** | Use same library for validation and storage (no truncation mismatches) |
| **No Oracle Exposure** | Don't expose encryption/decryption functions that reflect input |
| **Domain Knowledge** | Understand business domain to anticipate attacker goals |
| **Human Testing** | Logic flaws require manual testing; scanners won't detect them |

---

## 🔗 7. References & Resources

- **OWASP**: [Business Logic Vulnerabilities](https://owasp.org/www-project-web-security-testing-guide/)
- **CWE-841**: [Improper Enforcement of Business Logic](https://cwe.mitre.org/data/definitions/841.html)
- **PortSwigger**: [Business Logic Vulnerabilities Academy](https://portswigger.net/web-security/logic-flaws)
- **Gareth Heyes**: [Splitting the Email Atom Whitepaper](https://portswigger.net/research)
- **OWASP ASVS**: [V4.0.3 Business Rule Verification](https://owasp.org/www-project-application-security-verification-standard/)
- **NIST**: [Software Flaws Manual](https://www.nist.gov/)

---
