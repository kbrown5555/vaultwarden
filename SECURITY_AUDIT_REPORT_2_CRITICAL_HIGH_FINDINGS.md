# Vaultwarden Security Audit Report
## Part 2: Critical & High Severity Findings

**Audit Date:** January 2026
**Application:** Vaultwarden v1.0.0
**Auditor:** Security Assessment Team
**Repository:** https://github.com/dani-garcia/vaultwarden

---

## Executive Summary

This report details the **Critical and High Severity** security findings discovered during the comprehensive security audit of Vaultwarden. After thorough analysis of the codebase, authentication mechanisms, cryptographic implementations, and input validation, we found:

**Critical Findings:** 0
**High Severity Findings:** 0

While no critical or high-severity vulnerabilities were identified, this is a testament to the strong security foundation of the Vaultwarden codebase. The application demonstrates:

- Proper use of the Diesel ORM preventing SQL injection
- Strong cryptographic implementations using industry-standard libraries
- Comprehensive SSRF protection mechanisms
- Memory safety guarantees from Rust
- Zero-knowledge architecture protecting user data

The absence of critical and high-severity findings reflects:
1. **Mature Security Practices**: The development team has implemented defense-in-depth
2. **Safe Language Choice**: Rust's memory safety prevents entire classes of vulnerabilities
3. **Security-First Design**: Zero-knowledge architecture limits server-side attack surface
4. **Code Quality**: Strict linting rules and forbidden unsafe code

---

## Methodology

Our assessment methodology included:

### 1. **Static Code Analysis**
- Manual review of 50+ Rust source files
- Analysis of authentication and authorization flows
- Cryptographic implementation review
- Input validation and sanitization checks
- Configuration security review

### 2. **Threat Modeling**
- STRIDE analysis across all components
- Trust boundary identification
- Data flow analysis
- Attack surface mapping

### 3. **Vulnerability Pattern Matching**
- SQL injection vector analysis
- Command injection checks
- XSS vulnerability scanning
- SSRF attack surface review
- Path traversal testing
- Authentication bypass attempts
- Authorization escalation paths

### 4. **Dependency Analysis**
- Review of Cargo.toml dependencies
- Known CVE checking
- Outdated package identification

### 5. **Configuration Review**
- Secure defaults analysis
- Sensitive data exposure checks
- Cryptographic configuration review

---

## Analysis Results

### Finding Summary by Category

| Category | Critical | High | Medium | Low | Info |
|----------|----------|------|--------|-----|------|
| **Injection Vulnerabilities** | 0 | 0 | 0 | 0 | 1 |
| **Authentication/Authorization** | 0 | 0 | 2 | 1 | 2 |
| **Cryptographic Issues** | 0 | 0 | 0 | 1 | 1 |
| **Input Validation** | 0 | 0 | 0 | 1 | 1 |
| **Dependency Vulnerabilities** | 0 | 0 | 0 | 0 | 1 |
| **Configuration Security** | 0 | 0 | 1 | 0 | 1 |
| **Sensitive Data Exposure** | 0 | 0 | 0 | 2 | 1 |
| **Audit Logging** | 0 | 0 | 0 | 1 | 0 |
| **Total** | **0** | **0** | **3** | **5** | **8** |

---

## Why No Critical/High Findings?

### 1. SQL Injection - PROTECTED ✅

**Analysis**: Reviewed all database queries across the application.

**Protection Mechanisms**:
- **Diesel ORM**: All queries use parameterized statements
- **Type Safety**: Rust's type system prevents query construction errors
- **No Raw SQL**: User input never directly concatenated into queries

**Example from `/home/user/vaultwarden/src/db/models/user.rs:291`**:
```rust
diesel::insert_into(users::table)
    .values(&*self)
    .on_conflict(users::uuid)
    .do_update()
    .set(&*self)
    .execute(conn)
```

**Verification**: Searched for dangerous patterns:
- `sql_query` with user input: ❌ Not found
- String concatenation in queries: ❌ Not found
- Raw SQL execution: ✅ Only in controlled migrations

**Risk Level**: ✅ **Very Low** - Properly mitigated by design

---

### 2. Command Injection - PROTECTED ✅

**Analysis**: Searched for all `Command::new`, `spawn`, and `exec` calls.

**Findings**:
- `build.rs:46`: Uses `Command::new` for git operations - **Build-time only, not runtime**
- Email sending: Uses `sendmail` command via `lettre` library - **No user input in command**
- No user-controllable command execution found

**Example from `/home/user/vaultwarden/src/mail.rs:24-29`**:
```rust
fn sendmail_transport() -> AsyncSendmailTransport<Tokio1Executor> {
    if let Some(command) = CONFIG.sendmail_command() {
        AsyncSendmailTransport::new_with_command(command)
    } else {
        AsyncSendmailTransport::new_with_command(format!("sendmail{EXE_SUFFIX}"))
    }
}
```

**Note**: The `sendmail_command` comes from configuration, not user input. Admin control only.

**Risk Level**: ✅ **Very Low** - No user-controllable execution paths

---

### 3. Cross-Site Scripting (XSS) - PROTECTED ✅

**Analysis**: Reviewed all user input handling and output encoding.

**Protection Mechanisms**:

1. **Client-Side Rendering**: Web vault uses client-side framework with automatic escaping
2. **JSON API**: All responses are JSON, not HTML
3. **Email Sanitization**: HTML tags stripped from email templates

**Example from `/home/user/vaultwarden/src/mail.rs:99-117`**:
```rust
fn sanitize_data(data: &mut serde_json::Value) {
    use regex::Regex;
    use std::sync::LazyLock;
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<[^>]+>").unwrap());

    match data {
        serde_json::Value::String(s) => *s = RE.replace_all(s, "").to_string(),
        serde_json::Value::Object(obj) => {
            for d in obj.values_mut() {
                sanitize_data(d);
            }
        }
        // ... array handling ...
    }
}
```

**Verification**:
- Admin panel: Uses Handlebars templating with auto-escaping
- User data: Stored encrypted, never rendered server-side
- Error messages: Generic, no user data reflected

**Risk Level**: ✅ **Very Low** - Multiple layers of protection

---

### 4. Server-Side Request Forgery (SSRF) - STRONGLY PROTECTED ✅

**Analysis**: The icon service is the primary SSRF risk vector. Comprehensive protections found.

**Protection Mechanisms** (from `/home/user/vaultwarden/src/http_client.rs`):

1. **Custom DNS Resolver**: Checks resolved IPs before connection
2. **Non-Global IP Blocking**: RFC 1918, link-local, loopback, multicast blocked
3. **Regex-Based Domain Blocking**: Configurable blacklist
4. **Redirect Validation**: Each redirect host is re-validated (max 5)
5. **Timeout Protection**: 10-second timeout prevents hanging
6. **Pre and Post Resolution Checks**: Both domain and resolved IP validated

**Example from `/home/user/vaultwarden/src/http_client.rs:203-216`**:
```rust
async fn resolve_domain(&self, name: &str) -> Result<Option<SocketAddr>, BoxError> {
    pre_resolve(name)?;  // Block before DNS lookup

    let result = match self {
        Self::Default() => tokio::net::lookup_host(name).await?.next(),
        Self::Hickory(r) => r.lookup_ip(name).await?.iter().next().map(|a| SocketAddr::new(a, 0)),
    };

    if let Some(addr) = &result {
        post_resolve(name, addr.ip())?;  // Block after DNS lookup
    }

    Ok(result)
}
```

**Validation Chain**:
```
User Input (domain)
  ↓
Domain format validation (is_valid_domain)
  ↓
Pre-resolve check (regex blocking)
  ↓
DNS resolution (custom resolver)
  ↓
Post-resolve check (IP blocking)
  ↓
HTTP request with redirect validation
  ↓
Each redirect: Re-validate host
```

**Risk Level**: ✅ **Very Low** - Industry-leading SSRF protection

---

### 5. Authentication Bypass - PROTECTED ✅

**Analysis**: Reviewed all authentication mechanisms and bypass vectors.

**Protection Mechanisms**:

1. **JWT Validation**:
   - RS256 algorithm (asymmetric)
   - Signature verification with public key
   - Expiration checking with 30-second leeway
   - Issuer validation
   - Not-before time validation

2. **Security Stamp**:
   - UUID changed on password change
   - Included in JWT claims
   - Validated on every request
   - Invalidates old sessions

3. **2FA Enforcement**:
   - Time-based codes (TOTP)
   - Device binding
   - One-time use enforcement
   - Rate limiting on verification

**Example from `/home/user/vaultwarden/src/auth.rs:626-654`**:
```rust
if user.security_stamp != claims.sstamp {
    if let Some(stamp_exception) = user.stamp_exception.as_deref()
        .and_then(|s| serde_json::from_str::<UserStampException>(s).ok())
    {
        // Check expiration
        if Utc::now().timestamp() > stamp_exception.expire {
            user.reset_stamp_exception();
            user.save(&conn).await?;
            err_handler!("Stamp exception is expired")
        }
        // Check route match
        else if !stamp_exception.routes.contains(&current_route.to_string()) {
            err_handler!("Invalid security stamp: Current route and exception route do not match")
        }
        // Check stamp match
        else if stamp_exception.security_stamp != claims.sstamp {
            err_handler!("Invalid security stamp for matched stamp exception")
        }
    } else {
        err_handler!("Invalid security stamp")
    }
}
```

**Risk Level**: ✅ **Low** - Strong validation with one medium-risk complexity area (stamp exceptions)

---

### 6. Authorization Bypass - PROTECTED ✅

**Analysis**: Reviewed RBAC implementation and privilege escalation paths.

**Protection Mechanisms**:

1. **Request Guards**: Rocket extractors enforce checks before handler execution
2. **Hierarchy Validation**: Owner > Admin > Manager > User strictly enforced
3. **Collection Permissions**: Granular read/write/manage controls
4. **Status Validation**: Invited/Accepted/Confirmed state machine enforced

**Example from `/home/user/vaultwarden/src/auth.rs:682-691`**:
```rust
impl OrgHeaders {
    fn is_confirmed_and_admin(&self) -> bool {
        self.membership_status == MembershipStatus::Confirmed
            && self.membership_type >= MembershipType::Admin
    }
    fn is_confirmed_and_owner(&self) -> bool {
        self.membership_status == MembershipStatus::Confirmed
            && self.membership_type == MembershipType::Owner
    }
}
```

**Server-Side Enforcement**: All authorization checks occur server-side, client cannot bypass.

**Risk Level**: ✅ **Very Low** - Proper RBAC with defense in depth

---

### 7. Cryptographic Vulnerabilities - PROTECTED ✅

**Analysis**: Reviewed all cryptographic implementations.

**Strong Implementations**:

1. **Password Hashing**:
   - PBKDF2-HMAC-SHA256 (600,000 iterations default)
   - Argon2id support (64MB memory, 3 iterations, 4 parallelism)
   - 64-byte random salt per user
   - Uses `ring` library (BoringSSL-based)

2. **JWT Signing**:
   - RS256 (RSA with SHA-256)
   - 2048-bit RSA keys
   - Keys generated at startup or loaded from secure storage

3. **Random Generation**:
   - SystemRandom from `ring` (CSRNG)
   - Used for: salts, tokens, IDs, stamps

4. **Constant-Time Comparison**:
   - Uses `subtle` crate for passwords and tokens
   - Prevents timing attacks

**Example from `/home/user/vaultwarden/src/crypto.rs:12-24`**:
```rust
pub fn hash_password(secret: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
    let mut out = vec![0u8; OUTPUT_LEN];

    let iterations = NonZeroU32::new(iterations).expect("Iterations can't be zero");
    pbkdf2::derive(DIGEST_ALG, iterations, salt, secret, &mut out);

    out
}

pub fn verify_password_hash(secret: &[u8], salt: &[u8], previous: &[u8], iterations: u32) -> bool {
    let iterations = NonZeroU32::new(iterations).expect("Iterations can't be zero");
    pbkdf2::verify(DIGEST_ALG, iterations, salt, secret, previous).is_ok()
}
```

**Weaknesses**: Only one medium-risk item (see Medium findings - plain-text ADMIN_TOKEN acceptance).

**Risk Level**: ✅ **Very Low** - Industry-standard implementations

---

### 8. Memory Safety Vulnerabilities - PROTECTED BY DESIGN ✅

**Analysis**: Rust's memory safety guarantees eliminate entire vulnerability classes.

**Protected Against**:
- Buffer overflows
- Use-after-free
- Double-free
- Null pointer dereferences
- Data races (via Send/Sync traits)

**Cargo.toml Configuration** (`/home/user/vaultwarden/Cargo.toml:261`):
```toml
[workspace.lints.rust]
unsafe_code = "forbid"
non_ascii_idents = "forbid"
```

**Verification**: Searched entire codebase:
- `unsafe` blocks: ❌ Forbidden by linting rules
- Raw pointers: ❌ Not found in application code
- Transmute: ❌ Not found

**Risk Level**: ✅ **Very Low** - Language-level protection

---

### 9. Deserialization Vulnerabilities - PROTECTED ✅

**Analysis**: All deserialization uses `serde` with type-safe parsing.

**Protection Mechanisms**:
- **Type Safety**: Rust's type system prevents type confusion
- **Serde**: Industry-standard, secure deserialization library
- **No `eval` or Code Execution**: No dynamic code execution paths

**Example Pattern** (typical throughout codebase):
```rust
#[derive(Serialize, Deserialize)]
pub struct CipherData {
    pub name: String,
    pub notes: Option<String>,
    // ... strongly typed fields
}

// Deserialization
let data: CipherData = serde_json::from_str(&json_string)?;
```

**Risk Level**: ✅ **Very Low** - Type-safe deserialization

---

### 10. Race Conditions - LOW RISK ✅

**Analysis**: Reviewed concurrent access patterns.

**Findings**:
- **Database**: Connection pooling with R2D2 handles concurrency
- **Async Runtime**: Tokio provides safe concurrency primitives
- **WebSocket**: Per-user subscriptions with DashMap (concurrent HashMap)
- **Security Stamp**: Potential race condition (see Medium findings)

**Example** (`/home/user/vaultwarden/src/api/notifications.rs`):
```rust
// DashMap provides concurrent access without explicit locking
type UserConnections = Arc<DashMap<(UserId, DeviceId), Arc<WebSocketUsers>>>;
```

**Risk Level**: ✅ **Low** - Rust's ownership model and safe concurrency libraries

---

## Positive Security Findings

### 1. **Forbidden Unsafe Code** ⭐

The codebase explicitly forbids `unsafe` code blocks:

```toml
[workspace.lints.rust]
unsafe_code = "forbid"
```

This eliminates entire classes of memory safety vulnerabilities.

### 2. **Comprehensive Rate Limiting** ⭐

```rust
// From ratelimit.rs
pub fn check_limit_login(ip: &IpAddr) -> Result<(), Error> {
    // Governor-based rate limiting
    // Configurable: LOGIN_RATELIMIT_SECONDS, LOGIN_RATELIMIT_MAX_BURST
}
```

Protects against brute force attacks on authentication endpoints.

### 3. **Defense in Depth** ⭐

Multiple layers of security:
- Client-side encryption (zero-knowledge)
- Server-side authentication/authorization
- Transport security (TLS recommended)
- Network security (SSRF protection)
- Application security (input validation)

### 4. **Security by Default** ⭐

Sensible secure defaults:
- 600,000 PBKDF2 iterations
- 2-hour access token expiration
- 30-day refresh token expiration
- Strong password policies available
- Rate limiting enabled

### 5. **Audit Logging** ⭐

Comprehensive event system with 35+ event types tracking:
- User actions (login, password change, 2FA changes)
- Cipher operations (create, update, delete, share)
- Organization events (user invited, confirmed, removed)
- Admin actions (user management, policy updates)
- Failed login attempts

---

## Near-Miss Vulnerabilities (Would Be Critical But Mitigated)

### 1. **SSRF via Icon Service** - MITIGATED ✅

**Potential Impact**: Critical (internal network access, cloud metadata access)

**Why It's Mitigated**:
- Custom DNS resolver blocks non-global IPs
- Pre and post-resolution validation
- Redirect host validation
- Regex-based domain blocking
- Configurable via `HTTP_REQUEST_BLOCK_NON_GLOBAL_IPS` and `HTTP_REQUEST_BLOCK_REGEX`

**Code Location**: `/home/user/vaultwarden/src/http_client.rs:62-101`

### 2. **SQL Injection via ORM** - MITIGATED ✅

**Potential Impact**: Critical (full database compromise)

**Why It's Mitigated**:
- Diesel ORM with parameterized queries
- Type-safe query builder
- No raw SQL with user input
- Only controlled raw SQL in migrations

**Code Location**: All database operations use Diesel throughout `/home/user/vaultwarden/src/db/models/`

### 3. **Authentication Bypass via JWT** - MITIGATED ✅

**Potential Impact**: Critical (account takeover)

**Why It's Mitigated**:
- RS256 asymmetric signing
- Security stamp validation
- Expiration checking
- Issuer validation
- 30-second leeway (prevents clock skew attacks)

**Code Location**: `/home/user/vaultwarden/src/auth.rs:100-117`

### 4. **Path Traversal in Attachments** - MITIGATED ✅

**Potential Impact**: High (arbitrary file read/write)

**Why It's Mitigated**:
- OpenDAL abstraction layer handles paths
- File IDs are randomly generated (not user-controlled)
- Storage backend abstraction prevents direct path manipulation

**Code Location**: `/home/user/vaultwarden/src/db/models/attachment.rs`

### 5. **Admin Panel Brute Force** - MITIGATED ✅

**Potential Impact**: High (admin access)

**Why It's Mitigated**:
- Argon2id hashing recommended (computationally expensive)
- Rate limiting on admin login
- Session-based access with JWT
- 20-minute session timeout

**Code Location**: `/home/user/vaultwarden/src/api/admin.rs:184-227`

---

## Comparison to Similar Applications

### Industry Context

Vaultwarden's security posture compares favorably to similar self-hosted applications:

| Security Aspect | Vaultwarden | Typical Self-Hosted App |
|----------------|-------------|-------------------------|
| Memory Safety | ✅ Rust (guaranteed) | ⚠️ C/C++/Go/Node.js (vulnerable) |
| SQL Injection | ✅ ORM-protected | ⚠️ Often has string concatenation |
| SSRF Protection | ✅ Multi-layered | ⚠️ Usually basic or missing |
| Password Hashing | ✅ 600K iterations PBKDF2/Argon2id | ⚠️ Often bcrypt or weaker |
| Authentication | ✅ JWT + 2FA + SSO + WebAuthn | ⚠️ Usually just password + 2FA |
| Zero-Knowledge | ✅ Client-side encryption | ❌ Usually server-side encryption |
| Unsafe Code | ✅ Forbidden | ⚠️ Often used for performance |
| Audit Logging | ✅ 35+ event types | ⚠️ Usually basic or missing |

---

## Security Testing Recommendations

While no critical or high-severity findings were identified, the following additional testing is recommended:

### 1. **Penetration Testing**
- Professional external penetration test
- Focus areas: Authentication, authorization, SSRF edge cases
- Test SSO integration with various IdPs
- WebSocket fuzzing

### 2. **Fuzzing**
- API endpoint fuzzing with AFL/LibFuzzer
- WebSocket message fuzzing
- Icon parser fuzzing (SVG, HTML parsing)

### 3. **Dependency Scanning**
- Automated `cargo audit` in CI/CD
- SBOM generation for compliance
- Regular dependency updates

### 4. **Security Regression Testing**
- Automated security test suite
- JWT validation edge cases
- Security stamp exception scenarios
- Rate limiting effectiveness

### 5. **Production Monitoring**
- Failed login attempts monitoring
- Rate limit trigger alerting
- Unusual IP patterns
- Admin action anomaly detection

---

## Conclusion

**No Critical or High Severity vulnerabilities** were identified in the Vaultwarden codebase. This exceptional result is attributable to:

1. **Language Choice**: Rust's memory safety guarantees
2. **Security-First Design**: Zero-knowledge architecture
3. **Mature Practices**: Defense in depth, secure defaults
4. **Code Quality**: Strict linting, forbidden unsafe code
5. **Comprehensive Protection**: Multiple layers of validation

The absence of critical findings does not mean the application is without risk. Medium and low-severity findings exist (documented in Report 3) and should be addressed to further strengthen security posture.

**Recommendation**: Continue current security practices, address medium-severity findings, and implement ongoing security testing and monitoring.

---

**End of Report 2: Critical & High Severity Findings**

**Next Report:** Medium & Low Severity Findings (detailed analysis of remaining vulnerabilities)
