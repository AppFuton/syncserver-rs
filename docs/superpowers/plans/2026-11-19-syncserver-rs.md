# syncserver-rs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a zero-knowledge sync server in Rust for the Futon manga reader app, supporting dual SQLite and PostgreSQL databases via SQLx, anti-enumeration fake salts, Argon2id auth, consolidated zstd+AEAD vault syncing, and granular item syncing.

**Architecture:** Axum web service with clean asynchronous repository abstractions for SQLite and PostgreSQL. Cryptographic layer handles Argon2id password hashing, constant-time verification with timing side-channel mitigation, and deterministic HMAC-SHA256 fake salts. Sync endpoints support optimistic concurrency via HTTP ETags/If-Match for binary archives and monotonic server timestamps for item deltas.

**Tech Stack:** Rust 2021/2024, Axum 0.8, Tokio 1.40, SQLx 0.8 (SQLite & Postgres), Argon2, HMAC-SHA256, JsonWebToken, Serde, Tower-HTTP.

**Spec:** `docs/superpowers/specs/2026-11-19-syncserver-rs-design.md`

## Global Constraints

- Never add `Co-Authored-By: Claude Code` or any Claude/AI attribution lines to git commits or pull requests.
- All email inputs must be canonicalized using `email.trim().to_lowercase()` before lookups, hashing, or salt computations.
- Database migrations must use `BLOB` for SQLite and `BYTEA` for PostgreSQL for binary snapshot storage (`vault_snapshots.encrypted_blob`).
- Password verification must be constant-time; invalid email lookups during login must execute a dummy Argon2id verification against a precomputed hash to prevent response latency timing side-channels.
- Server timestamps (`updated_at`) for item deltas must be produced using the server's monotonic UTC clock (`chrono::Utc::now().timestamp_millis()`).
- Request body limits must be enforced: 25 MB for `/api/vault/sync` binary snapshots, 2 MB for JSON endpoints.

## Review Focus

1. **Email normalization mismatch:** A user registering with `User@Example.Com` and requesting parameters with `user@example.com` receives the exact same real salt.
2. **Timing side-channel on login:** An invalid email login executes Argon2id verification against a dummy hash, producing response times indistinguishable from a valid email with a bad password.
3. **Database migration dialect differences:** Binary snapshot operations succeed without SQL syntax or type errors on both SQLite (`BLOB`) and PostgreSQL (`BYTEA`).
4. **Optimistic concurrency collision on vault archive sync:** Uploading a snapshot with an outdated `If-Match: "<version>"` returns `412 Precondition Failed` and does not overwrite newer data.
5. **Item delta sync clock skew:** Rapid consecutive item updates receive monotonically advancing server timestamps, preventing missed records when clients query `GET /api/items?since=...`.

---

### Task 1: Project Scaffolding, Configuration, and Unified Error Handling

**Files:**
- Create: `Cargo.toml`
- Create: `.gitignore`
- Create: `src/config.rs`
- Create: `src/error.rs`
- Create: `src/main.rs`
- Test: `tests/config_tests.rs`

**Interfaces:**
- Produces: `Config` struct (`database_url`, `server_secret`, `jwt_secret`, `port`, `host`).
- Produces: `AppError` enum implementing `IntoResponse` with standardized JSON error bodies `{"error": "<msg>"}` and appropriate HTTP status codes.

- [ ] **Step 1: Write failing test for configuration parsing**

`tests/config_tests.rs`:
```rust
use std::env;

#[test]
fn test_config_from_env_defaults() {
    env::remove_var("DATABASE_URL");
    env::set_var("SERVER_SECRET", "test_secret_32_bytes_long_minimum_val");
    env::set_var("JWT_SECRET", "test_jwt_secret_32_bytes_minimum_val");
    // Verify default port 8080 and default sqlite database_url
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test config_tests`
Expected: FAIL (missing files/dependencies).

- [ ] **Step 3: Create `Cargo.toml`, `.gitignore`, `src/config.rs`, `src/error.rs`, and initial `src/main.rs`**

Add dependencies: `axum = "0.8"`, `tokio = { version = "1.40", features = ["full"] }`, `sqlx = { version = "0.8", features = ["runtime-tokio", "tls-rustls", "sqlite", "postgres", "macros"] }`, `argon2 = "0.5"`, `hmac = "0.12"`, `sha2 = "0.10"`, `subtle = "2.6"`, `rand = "0.8"`, `jsonwebtoken = "9.3"`, `serde = { version = "1.0", features = ["derive"] }`, `serde_json = "1.0"`, `base64 = "0.22"`, `uuid = { version = "1.10", features = ["v4", "serde"] }`, `chrono = { version = "0.4", features = ["serde"] }`, `tower-http = { version = "0.6", features = ["cors", "trace", "limit"] }`, `dotenvy = "0.15"`, `tracing = "0.1"`, `tracing-subscriber = { version = "0.3", features = ["env-filter"] }`.

Implement `AppError` with variants: `NotFound`, `Unauthorized(String)`, `Conflict(String)`, `PreconditionFailed(String)`, `BadRequest(String)`, `Internal(String)`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --test config_tests`
Expected: PASS.

- [ ] **Step 5: Commit changes**

```bash
git add Cargo.toml .gitignore src/ tests/
git commit -m "chore: scaffold project, configuration, and unified error handling"
```

---

### Task 2: Cryptographic Primitives (Argon2id, Dummy Verification, Fake Salt HMAC)

**Files:**
- Create: `src/crypto/mod.rs`
- Create: `src/crypto/argon.rs`
- Create: `src/crypto/fake_salt.rs`
- Test: `tests/crypto_tests.rs`

**Interfaces:**
- Consumes: `AppError`.
- Produces: `hash_password(auth_key: &str) -> Result<String, AppError>`.
- Produces: `verify_password(auth_key: &str, password_hash: &str) -> Result<bool, AppError>`.
- Produces: `verify_dummy_password(auth_key: &str) -> Result<(), AppError>` (runs Argon2id against a precomputed dummy hash to mitigate login latency timing side-channels).
- Produces: `generate_fake_salt(server_secret: &[u8], normalized_email: &str) -> String` (returns 16-byte base64 salt).
- Produces: `normalize_email(email: &str) -> String` (`email.trim().to_lowercase()`).

- [ ] **Step 1: Write failing tests for crypto primitives**

`tests/crypto_tests.rs`:
```rust
#[test]
fn test_email_normalization() {
    assert_eq!(normalize_email("  User@Example.Com "), "user@example.com");
}

#[test]
fn test_fake_salt_deterministic_and_unique() {
    let secret = b"super_secret_server_hmac_key_12345";
    let salt1 = generate_fake_salt(secret, "user@example.com");
    let salt2 = generate_fake_salt(secret, "user@example.com");
    let salt3 = generate_fake_salt(secret, "other@example.com");
    assert_eq!(salt1, salt2);
    assert_ne!(salt1, salt3);
    assert_eq!(base64::prelude::BASE64_STANDARD.decode(&salt1).unwrap().len(), 16);
}

#[test]
fn test_argon2_hash_and_verify() {
    let key = "client_auth_key_sample_base64_string";
    let hash = hash_password(key).unwrap();
    assert!(verify_password(key, &hash).unwrap());
    assert!(!verify_password("wrong_key", &hash).unwrap());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test crypto_tests`
Expected: FAIL (modules not implemented).

- [ ] **Step 3: Implement `normalize_email`, `generate_fake_salt`, `hash_password`, `verify_password`, and `verify_dummy_password`**

In `src/crypto/argon.rs`, store a static `PRECOMPUTED_DUMMY_HASH` created via Argon2id. `verify_dummy_password` calls `verify_password(auth_key, PRECOMPUTED_DUMMY_HASH)` and discards the boolean, spending the exact same CPU time as a valid user check.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --test crypto_tests`
Expected: PASS.

- [ ] **Step 5: Commit changes**

```bash
git add src/crypto/ tests/crypto_tests.rs
git commit -m "feat(crypto): implement argon2id hashing, dummy verification, and anti-enumeration fake salt"
```

---

### Task 3: Dual Database Migrations & Repository Abstraction (SQLite & PostgreSQL)

**Files:**
- Create: `migrations/sqlite/0001_init.sql`
- Create: `migrations/postgres/0001_init.sql`
- Create: `src/db/mod.rs`
- Create: `src/db/models.rs`
- Create: `src/db/sqlite.rs`
- Create: `src/db/postgres.rs`
- Test: `tests/db_sqlite_tests.rs`

**Interfaces:**
- Produces: `trait Repository: Send + Sync`:
  - `get_user_by_email(&self, email: &str) -> Result<Option<User>, AppError>`
  - `get_user_by_id(&self, user_id: &str) -> Result<Option<User>, AppError>`
  - `create_user(&self, user: &NewUser) -> Result<User, AppError>`
  - `rotate_password(&self, user_id: &str, old_auth_key: &str, rotation: &PasswordRotation) -> Result<(), AppError>`
  - `get_vault_snapshot(&self, user_id: &str) -> Result<Option<VaultSnapshot>, AppError>`
  - `put_vault_snapshot(&self, user_id: &str, blob: Vec<u8>, expected_version: Option<i64>) -> Result<VaultSnapshotMeta, AppError>`
  - `get_vault_items(&self, user_id: &str, since: Option<i64>) -> Result<Vec<VaultItem>, AppError>`
  - `upsert_vault_items(&self, user_id: &str, items: &[VaultItemUpsert], now_ms: i64) -> Result<Vec<VaultItemSyncResult>, AppError>`
- Produces: `SqliteRepository` and `PostgresRepository`.

- [ ] **Step 1: Write failing SQLite repository integration test**

`tests/db_sqlite_tests.rs`:
```rust
#[tokio::test]
async fn test_sqlite_user_lifecycle_and_rotation() {
    let repo = SqliteRepository::new_in_memory().await.unwrap();
    // Test creating user, querying user by email, and atomic password rotation
}

#[tokio::test]
async fn test_sqlite_snapshot_concurrency() {
    let repo = SqliteRepository::new_in_memory().await.unwrap();
    // Test snapshot put, get, and If-Match version conflict (PreconditionFailed)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test db_sqlite_tests`
Expected: FAIL.

- [ ] **Step 3: Implement migrations and repository implementations**

Create `migrations/sqlite/0001_init.sql` with `encrypted_blob BLOB NOT NULL`.
Create `migrations/postgres/0001_init.sql` with `encrypted_blob BYTEA NOT NULL`.
Implement `SqliteRepository` and `PostgresRepository` handling all queries and transactions.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --test db_sqlite_tests`
Expected: PASS.

- [ ] **Step 5: Commit changes**

```bash
git add migrations/ src/db/ tests/db_sqlite_tests.rs
git commit -m "feat(db): implement sqlite and postgres migrations and repository abstraction"
```

---

### Task 4: JWT Token Handling and Authentication Middleware

**Files:**
- Create: `src/auth/mod.rs`
- Create: `src/auth/jwt.rs`
- Create: `src/auth/middleware.rs`
- Test: `tests/auth_token_tests.rs`

**Interfaces:**
- Consumes: `AppError`, `Config`.
- Produces: `create_token(user_id: &str, secret: &str, expiration_seconds: i64) -> Result<String, AppError>`.
- Produces: `verify_token(token: &str, secret: &str) -> Result<Claims, AppError>`.
- Produces: `struct AuthUser { pub user_id: String }` as an Axum `FromRequestParts` extractor requiring valid `Authorization: Bearer <token>`.

- [ ] **Step 1: Write failing test for JWT creation, extraction, and validation**

`tests/auth_token_tests.rs`:
```rust
#[test]
fn test_jwt_encode_decode_roundtrip() {
    let secret = "test_jwt_secret_must_be_long_enough_12345";
    let token = create_token("user-uuid-123", secret, 3600).unwrap();
    let claims = verify_token(&token, secret).unwrap();
    assert_eq!(claims.sub, "user-uuid-123");
}

#[test]
fn test_expired_jwt_fails() {
    let secret = "test_jwt_secret_must_be_long_enough_12345";
    let token = create_token("user-uuid-123", secret, -10).unwrap();
    assert!(verify_token(&token, secret).is_err());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test auth_token_tests`
Expected: FAIL.

- [ ] **Step 3: Implement `src/auth/jwt.rs` and `src/auth/middleware.rs`**

Use `jsonwebtoken` to encode/decode claims (`sub`, `exp`, `iat`).
Implement `FromRequestParts` for `AuthUser`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --test auth_token_tests`
Expected: PASS.

- [ ] **Step 5: Commit changes**

```bash
git add src/auth/ tests/auth_token_tests.rs
git commit -m "feat(auth): implement jwt token generation, claims verification, and axum auth extractor"
```

---

### Task 5: Authentication Routes (`/api/auth/*`) & Timing Defense

**Files:**
- Create: `src/routes/mod.rs`
- Create: `src/routes/auth.rs`
- Modify: `src/main.rs`
- Test: `tests/routes_auth_tests.rs`

**Interfaces:**
- Produces Axum Router with:
  - `GET /api/auth/params?email=...`
  - `POST /api/auth/register`
  - `POST /api/auth/login`
  - `GET /api/auth/me` (Protected)
  - `POST /api/auth/rotate-password` (Protected)

- [ ] **Step 1: Write failing integration test for auth routes**

`tests/routes_auth_tests.rs`:
```rust
#[tokio::test]
async fn test_auth_params_returns_fake_salt_for_non_existent_email() {
    // Call GET /api/auth/params?email=unknown@example.com
    // Verify 200 OK and deterministic 16-byte base64 salt
}

#[tokio::test]
async fn test_register_login_and_rotate_password_flow() {
    // Register user -> Login -> Me -> Rotate Password -> Login with new password succeeds -> Login with old password fails (401)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test routes_auth_tests`
Expected: FAIL.

- [ ] **Step 3: Implement `src/routes/auth.rs`**

Implement handlers. In `login_handler`: if user is not found, call `verify_dummy_password(&payload.client_auth_key)` before returning `AppError::Unauthorized("Invalid credentials")`.
Ensure `rotate_password` executes atomically in the repository.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --test routes_auth_tests`
Expected: PASS.

- [ ] **Step 5: Commit changes**

```bash
git add src/routes/ tests/routes_auth_tests.rs src/main.rs
git commit -m "feat(routes): implement auth routes with timing defense and password rotation"
```

---

### Task 6: Consolidated Vault Backup & Sync Routes (`/api/vault/sync`)

**Files:**
- Create: `src/routes/vault.rs`
- Modify: `src/routes/mod.rs`
- Test: `tests/routes_vault_tests.rs`

**Interfaces:**
- Produces:
  - `GET /api/vault/sync`: Returns binary blob, `Content-Type: application/octet-stream`, `ETag: "<version>"`. Supports `If-None-Match`.
  - `POST /api/vault/sync`: Accepts binary body (capped at 25 MB). Supports `If-Match: "<version>"`. Returns `{"version": N, "updated_at": T, "size_bytes": S}` or `412 Precondition Failed`.
  - `GET /api/vault/sync/meta`: Returns JSON metadata.

- [ ] **Step 1: Write failing test for vault sync routes**

`tests/routes_vault_tests.rs`:
```rust
#[tokio::test]
async fn test_vault_snapshot_etag_and_concurrency() {
    // 1. Initial GET -> 404
    // 2. POST binary blob -> 200, version 1
    // 3. GET with If-None-Match: "1" -> 304 Not Modified
    // 4. POST with If-Match: "1" -> 200, version 2
    // 5. POST with stale If-Match: "1" -> 412 Precondition Failed
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test routes_vault_tests`
Expected: FAIL.

- [ ] **Step 3: Implement `src/routes/vault.rs` and apply 25 MB body limit**

Implement streaming / raw bytes handlers with `DefaultBodyLimit::max(25 * 1024 * 1024)`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --test routes_vault_tests`
Expected: PASS.

- [ ] **Step 5: Commit changes**

```bash
git add src/routes/vault.rs src/routes/mod.rs tests/routes_vault_tests.rs
git commit -m "feat(vault): implement consolidated vault archive sync with etag concurrency control"
```

---

### Task 7: Granular Items Sync Routes (`/api/items`) & Server Monotonic Clock

**Files:**
- Create: `src/routes/items.rs`
- Modify: `src/routes/mod.rs`
- Test: `tests/routes_items_tests.rs`

**Interfaces:**
- Produces:
  - `GET /api/items?since={timestamp_ms}`: Returns `{ "items": [...], "server_timestamp": now_ms }`.
  - `POST /api/items`: Accepts `{ "items": [...] }` (capped at 2 MB), persists records with server UTC timestamp, returns `{ "synced": [...], "server_timestamp": now_ms }`.

- [ ] **Step 1: Write failing test for granular items sync**

`tests/routes_items_tests.rs`:
```rust
#[tokio::test]
async fn test_items_sync_and_delta_retrieval() {
    // 1. POST two items -> 200 OK
    // 2. GET /api/items?since=0 -> returns both items
    // 3. POST tombstone (deleted_at: now) for one item
    // 4. GET /api/items?since=T1 -> returns only the tombstoned item
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test routes_items_tests`
Expected: FAIL.

- [ ] **Step 3: Implement `src/routes/items.rs` using `chrono::Utc::now().timestamp_millis()`**

Implement item handlers and wire into router.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --test routes_items_tests`
Expected: PASS.

- [ ] **Step 5: Commit changes**

```bash
git add src/routes/items.rs src/routes/mod.rs tests/routes_items_tests.rs
git commit -m "feat(items): implement granular items sync with server monotonic timestamping"
```

---

### Task 8: Server Bootstrap, Health Endpoint, and Full End-to-End Test Suite

**Files:**
- Modify: `src/main.rs`
- Create: `tests/e2e_full_sync_test.rs`
- Create: `README.md`

**Interfaces:**
- Server CLI supports configuring `DATABASE_URL` (sqlite or postgres), `PORT`, `SERVER_SECRET`, `JWT_SECRET`.
- End-to-end integration test simulating an entire Futon client lifecycle.

- [ ] **Step 1: Write comprehensive end-to-end integration test**

`tests/e2e_full_sync_test.rs`:
Simulate:
1. `GET /api/health` -> verify status healthy.
2. `GET /api/auth/params` for non-existent email -> verify fake salt.
3. `POST /api/auth/register` with wrapped vault key.
4. `POST /api/auth/login` -> receive JWT and wrapped vault key.
5. `POST /api/vault/sync` with compressed and encrypted backup blob.
6. `GET /api/vault/sync` with ETag validation.
7. `POST /api/items` with 10 granular encrypted records.
8. `GET /api/items?since=...` -> verify incremental sync.
9. `POST /api/auth/rotate-password` -> rotate credentials.
10. Login with new credentials and verify all vault data and items are intact.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test e2e_full_sync_test`
Expected: FAIL (or PASS once wiring is finalized).

- [ ] **Step 3: Finalize `src/main.rs` CLI runtime and documentation**

Complete server initialization, automatic DB migration running at boot, signal handling (Ctrl+C), and write clear README with configuration instructions.

- [ ] **Step 4: Run complete test suite**

Run: `cargo test`
Expected: ALL PASS.

- [ ] **Step 5: Commit changes**

```bash
git add src/main.rs README.md tests/e2e_full_sync_test.rs
git commit -m "feat: complete server bootstrap, documentation, and end-to-end test suite"
```
