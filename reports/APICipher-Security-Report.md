# APICipher Security Assessment

**Scan ID:** `APICIPHER-20260823-121204`  
**Target:** APICipher Security Tests  
**Generated:** 2026-08-23T12:12:04.491803+00:00

---

## Executive Summary

**Overall risk rating: CRITICAL**

An automated security assessment of `APICipher Security Tests` executed 14 security controls, of which 11 failed and 3 passed.

| Severity | Count |
| --- | --- |
| Critical | 2 |
| High | 3 |
| Medium | 3 |
| Low | 3 |
| **Total** | **11** |

The highest-rated issue is **APC-004 - Broken Authentication** (10.0/10) on `GET /users`. 5 finding(s) are rated High or above and should be remediated before this API is exposed to untrusted networks.

## Top Risks

| Rank | ID | Vulnerability | Endpoint | Severity | Score |
| --- | --- | --- | --- | --- | --- |
| 1 | APC-004 | Broken Authentication | `GET /users` | CRITICAL | 10.0 |
| 2 | APC-005 | Broken Authentication | `GET /users` | CRITICAL | 10.0 |
| 3 | APC-001 | Broken Object Level Authorization | `GET /users/{user_id}` | HIGH | 8.0 |
| 4 | APC-002 | Broken Object Level Authorization | `GET /transactions/{id}` | HIGH | 8.0 |
| 5 | APC-003 | Broken Object Level Authorization | `GET /transactions/{id}` | HIGH | 8.0 |

## Findings

### APC-004 - Broken Authentication

[CRITICAL] **CRITICAL** | Risk score **10.0/10** `####################`

| | |
| --- | --- |
| Endpoint | `GET /users` |
| Expectation | Must require authentication |
| OWASP | API2:2023 Broken Authentication |
| CWE | CWE-287 Improper Authentication |
| Status | OPEN |

**Risk calculation**

Likelihood 5/5 x Impact 5/5 x Exposure 5/5 = 125/125 -> **10.0/10**

**Evidence**

```http
GET http://127.0.0.1:8000/users

HTTP 200
[{"role":"user","password":"$argon2id$[REDACTED]","username":"apc_user_a","email":"[EMAIL_REDACTED]","id":7},{"role":"user","password":"$argon2id$[REDACTED]","username":"apc_user_b","email":"[EMAIL_REDACTED]","id":8},{"role":"admin","password":"$argon2id$[REDACTED]","username":"apc_admin","email":"[
... [truncated]
```

Assertion failure: `expected 200 to be one of [ 401, 403 ]`

**Remediation**

Require a valid credential on every non-public endpoint by adding the authentication dependency. Issue short-lived tokens with an 'exp' claim and reject expired ones.

---

### APC-005 - Broken Authentication

[CRITICAL] **CRITICAL** | Risk score **10.0/10** `####################`

| | |
| --- | --- |
| Endpoint | `GET /users` |
| Expectation | Anonymous response must not contain password hashes |
| OWASP | API2:2023 Broken Authentication |
| CWE | CWE-287 Improper Authentication |
| Status | OPEN |

**Risk calculation**

Likelihood 5/5 x Impact 5/5 x Exposure 5/5 = 125/125 -> **10.0/10**

**Evidence**

```http
GET http://127.0.0.1:8000/users

HTTP 200
[{"role":"user","password":"$argon2id$[REDACTED]","username":"apc_user_a","email":"[EMAIL_REDACTED]","id":7},{"role":"user","password":"$argon2id$[REDACTED]","username":"apc_user_b","email":"[EMAIL_REDACTED]","id":8},{"role":"admin","password":"$argon2id$[REDACTED]","username":"apc_admin","email":"[
... [truncated]
```

Assertion failure: `expected '[{"role":"user","password":"$argon2id…' to not include 'argon2'`

**Remediation**

Require a valid credential on every non-public endpoint by adding the authentication dependency. Issue short-lived tokens with an 'exp' claim and reject expired ones.

---

### APC-001 - Broken Object Level Authorization

[HIGH] **HIGH** | Risk score **8.0/10** `################....`

| | |
| --- | --- |
| Endpoint | `GET /users/{user_id}` |
| Expectation | Must deny cross-user object access |
| OWASP | API1:2023 Broken Object Level Authorization |
| CWE | CWE-639 Authorization Bypass Through User-Controlled Key |
| Status | OPEN |

**Risk calculation**

Likelihood 5/5 x Impact 5/5 x Exposure 4/5 = 100/125 -> **8.0/10**

**Evidence**

```http
GET http://127.0.0.1:8000/users/8

HTTP 200
{"role":"user","password":"$argon2id$[REDACTED]","username":"apc_user_b","email":"[EMAIL_REDACTED]","id":8}
```

Assertion failure: `expected 200 to be one of [ 403, 404 ]`

**Remediation**

Verify object ownership on every request. After loading the resource, compare its owner id against the authenticated user id from the JWT and return 403 on mismatch. Do not rely on the client to send only its own ids.

---

### APC-002 - Broken Object Level Authorization

[HIGH] **HIGH** | Risk score **8.0/10** `################....`

| | |
| --- | --- |
| Endpoint | `GET /transactions/{id}` |
| Expectation | Must deny access to another user's transaction |
| OWASP | API1:2023 Broken Object Level Authorization |
| CWE | CWE-639 Authorization Bypass Through User-Controlled Key |
| Status | OPEN |

**Risk calculation**

Likelihood 5/5 x Impact 5/5 x Exposure 4/5 = 100/125 -> **8.0/10**

**Evidence**

```http
GET http://127.0.0.1:8000/transactions/13

HTTP 200
{"id":13,"user_id":8,"amount":9900.0,"description":"user_b CONFIDENTIAL salary"}
```

Assertion failure: `expected 200 to be one of [ 403, 404 ]`

**Remediation**

Verify object ownership on every request. After loading the resource, compare its owner id against the authenticated user id from the JWT and return 403 on mismatch. Do not rely on the client to send only its own ids.

---

### APC-003 - Broken Object Level Authorization

[HIGH] **HIGH** | Risk score **8.0/10** `################....`

| | |
| --- | --- |
| Endpoint | `GET /transactions/{id}` |
| Expectation | Must not leak another user's transaction data |
| OWASP | API1:2023 Broken Object Level Authorization |
| CWE | CWE-639 Authorization Bypass Through User-Controlled Key |
| Status | OPEN |

**Risk calculation**

Likelihood 5/5 x Impact 5/5 x Exposure 4/5 = 100/125 -> **8.0/10**

**Evidence**

```http
GET http://127.0.0.1:8000/transactions/13

HTTP 200
{"id":13,"user_id":8,"amount":9900.0,"description":"user_b CONFIDENTIAL salary"}
```

Assertion failure: `expected '{"id":13,"user_id":8,"amount":9900.0,…' to not include 'CONFIDENTIAL'`

**Remediation**

Verify object ownership on every request. After loading the resource, compare its owner id against the authenticated user id from the JWT and return 403 on mismatch. Do not rely on the client to send only its own ids.

---

### APC-007 - Broken Authentication

[MEDIUM] **MEDIUM** | Risk score **6.0/10** `############........`

| | |
| --- | --- |
| Endpoint | `POST /login` |
| Expectation | Issued JWT must carry an exp claim |
| OWASP | API2:2023 Broken Authentication |
| CWE | CWE-287 Improper Authentication |
| Status | OPEN |

**Risk calculation**

Likelihood 3/5 x Impact 5/5 x Exposure 5/5 = 75/125 -> **6.0/10**

**Evidence**

```http
GET http://127.0.0.1:8000/health

HTTP 200
{"status":"healthy","secure_mode":false}
```

Assertion failure: `expected { user_id: 7 } to have property 'exp'`

**Remediation**

Require a valid credential on every non-public endpoint by adding the authentication dependency. Issue short-lived tokens with an 'exp' claim and reject expired ones.

---

### APC-010 - Missing Rate Limiting

[MEDIUM] **MEDIUM** | Risk score **4.8/10** `##########..........`

| | |
| --- | --- |
| Endpoint | `POST /login` |
| Expectation | Must throttle repeated failed logins |
| OWASP | API4:2023 Unrestricted Resource Consumption |
| CWE | CWE-307 Improper Restriction of Excessive Authentication Attempts |
| Status | OPEN |

**Risk calculation**

Likelihood 4/5 x Impact 3/5 x Exposure 5/5 = 60/125 -> **4.8/10**

**Evidence**

```http
POST http://127.0.0.1:8000/login

HTTP 401
{"detail":"Invalid username or password"}
```

Assertion failure: `expected 'false' to deeply equal 'true'`

**Remediation**

Throttle authentication endpoints per IP and per account. Return 429 once the threshold is exceeded and apply progressive backoff or lockout.

---

### APC-011 - Sensitive Data Exposure

[MEDIUM] **MEDIUM** | Risk score **4.0/10** `########............`

| | |
| --- | --- |
| Endpoint | `GET /admin/users` |
| Expectation | Admin view must not expose password hashes |
| OWASP | API3:2023 Broken Object Property Level Authorization |
| CWE | CWE-200 Exposure of Sensitive Information |
| Status | OPEN |

**Risk calculation**

Likelihood 5/5 x Impact 5/5 x Exposure 2/5 = 50/125 -> **4.0/10**

**Evidence**

```http
GET http://127.0.0.1:8000/admin/users

HTTP 200
[{"role":"user","password":"$argon2id$[REDACTED]","username":"apc_user_a","email":"[EMAIL_REDACTED]","id":7},{"role":"user","password":"$argon2id$[REDACTED]","username":"apc_user_b","email":"[EMAIL_REDACTED]","id":8},{"role":"admin","password":"$argon2id$[REDACTED]","username":"apc_admin","email":"[
... [truncated]
```

Assertion failure: `expected '[{"role":"user","password":"$argon2id…' to not include 'argon2'`

**Remediation**

Never serialise ORM models directly. Define explicit response schemas that list only the fields a caller may see, so new columns cannot leak by default.

---

### APC-012 - Security Misconfiguration

[LOW] **LOW** | Risk score **2.4/10** `#####...............`

| | |
| --- | --- |
| Endpoint | `GET /docs` |
| Expectation | Interactive API docs must not be publicly exposed |
| OWASP | API8:2023 Security Misconfiguration |
| CWE | CWE-16 Configuration |
| Status | OPEN |

**Risk calculation**

Likelihood 3/5 x Impact 2/5 x Exposure 5/5 = 30/125 -> **2.4/10**

**Evidence**

```http
GET http://127.0.0.1:8000/docs

HTTP 200

    <!DOCTYPE html>
    <html>
    <head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link type="text/css" rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
    <link rel="shortcut icon" href="https://fastapi.tiangolo.com/img/
... [truncated]
```

Assertion failure: `expected 200 to be one of [ 401, 403, 404 ]`

**Remediation**

Disable interactive API documentation in production and send hardening headers (X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security) via middleware.

---

### APC-013 - Security Misconfiguration

[LOW] **LOW** | Risk score **2.4/10** `#####...............`

| | |
| --- | --- |
| Endpoint | `GET /` |
| Expectation | Must send X-Content-Type-Options header |
| OWASP | API8:2023 Security Misconfiguration |
| CWE | CWE-16 Configuration |
| Status | OPEN |

**Risk calculation**

Likelihood 3/5 x Impact 2/5 x Exposure 5/5 = 30/125 -> **2.4/10**

**Evidence**

```http
GET http://127.0.0.1:8000/

HTTP 200
{"message":"APICipher API is running","status":"online"}
```

Assertion failure: `expected response to have header with key 'X-Content-Type-Options'`

**Remediation**

Disable interactive API documentation in production and send hardening headers (X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security) via middleware.

---

### APC-014 - Security Misconfiguration

[LOW] **LOW** | Risk score **2.4/10** `#####...............`

| | |
| --- | --- |
| Endpoint | `GET /` |
| Expectation | Must send X-Frame-Options header |
| OWASP | API8:2023 Security Misconfiguration |
| CWE | CWE-16 Configuration |
| Status | OPEN |

**Risk calculation**

Likelihood 3/5 x Impact 2/5 x Exposure 5/5 = 30/125 -> **2.4/10**

**Evidence**

```http
GET http://127.0.0.1:8000/

HTTP 200
{"message":"APICipher API is running","status":"online"}
```

Assertion failure: `expected response to have header with key 'X-Frame-Options'`

**Remediation**

Disable interactive API documentation in production and send hardening headers (X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security) via middleware.

---

## Controls Passed

The following controls were tested and found to be correctly implemented. They are listed to demonstrate that the test suite distinguishes secure behaviour from insecure behaviour rather than reporting every check as a failure.

- `APC-006`
- `APC-008`
- `APC-009`


## Methodology

Each security control is expressed as a test asserting *secure* behaviour, so a failing assertion is a detected vulnerability. Findings are scored on three axes, each rated 1-5:

- **Likelihood** - how easily the weakness can be exploited
- **Impact** - the consequence of successful exploitation
- **Exposure** - who can reach the affected endpoint (5 = unauthenticated, 4 = any authenticated user, 2 = administrators only)

```
Risk Score = (Likelihood x Impact x Exposure) / 125 x 10
```

The axes are multiplied rather than averaged so that an unreachable weakness collapses toward zero regardless of its theoretical severity. This is why identical data exposure scores 10.0 when anonymous and 4.0 when it requires an administrator account.

| Band | Range |
| --- | --- |
| CRITICAL | >= 9.0 |
| HIGH | 7.0 - 8.9 |
| MEDIUM | 4.0 - 6.9 |
| LOW | < 4.0 |
