# Zero-Knowledge Sync Server Design for Futon (`syncserver-rs`)

## 1. Overview & Objective
`syncserver-rs` is a high-performance, zero-knowledge synchronization backend built in Rust for the Futon manga reader application. It is designed to store user accounts, authentication metadata, and encrypted application state without ever exposing sensitive reader data or plaintexts to the server.

The server supports dual database engines via SQLx (**SQLite** for lightweight, single-binary embedded self-hosting and **PostgreSQL** for multi-user high-concurrency production setups) and provides both consolidated archive backup/syncing (`/api/vault/sync`) and granular item-level syncing (`/api/items`).

---

## 2. Cryptographic Architecture

### 2.1 Key Hierarchy
1. **User Input**: `Email` + `Master Password`.
2. **Email Canonicalization**: Both client and server execute `email.trim().to_lowercase()` prior to hashing, lookups, or salt calculations.
3. **Master Key Derivation (Client RAM only)**:
   - `Master Key (256-bit) = Argon2id(Password, Salt = kdf_salt, m = kdf_memory_kb, t = kdf_iterations, p = kdf_parallelism)`
   - Defaults: `m = 65536 KB` (64 MB), `t = 3`, `p = 1`.
4. **Key Stretching (HKDF-SHA256)**:
   - `Client Auth Key = HKDF-Expand(Master Key, info = "auth", len = 32 bytes)` (Base64-encoded, sent to server as the authentication token).
   - `Wrapping Key = HKDF-Expand(Master Key, info = "enc", len = 32 bytes)` (Never leaves client RAM, used to encrypt/decrypt the Vault Key).
5. **Vault Key**:
   - Random 256-bit symmetric key generated via CSPRNG on the client once upon registration.
   - Encrypted with `Wrapping Key` via AES-256-GCM producing `wrapped_vault_key`.
   - `wrapped_vault_key` is stored on the server.
6. **Data Encryption Envelope**:
   - All encrypted payloads use the format: `v1.<base64_iv>.<base64_ciphertext_with_auth_tag>`.
   - Nonce (IV): 12-byte CSPRNG random IV generated on every single encryption operation (never reused).

### 2.2 Canonical AAD (Authenticated Associated Data) Specification
To prevent ciphertext substitution and row-swapping attacks:
- `wrapped_vault_key`: AAD = `auth:vault_key:<user_uuid>`
- `vault_items` (granular): AAD = `item:<user_uuid>:<item_uuid>`
- `vault_snapshots` (consolidated archive): AAD = `snapshot:v1:<user_uuid>`

### 2.3 Server-Side Password Security & Anti-Enumeration
1. **Server Hash**:
   - The server never stores the raw `Client Auth Key`.
   - Upon receiving `client_auth_key`, the server hashes it using Argon2id (`m = 65536 KB`, `t = 3`, `p = 1`) to produce `server_password_hash`.
2. **Anti-Enumeration Fake Salt (`GET /api/auth/params?email=...`)**:
   - If the requested normalized email exists: return the stored `kdf_salt`, `kdf_memory_kb`, `kdf_iterations`, and `kdf_parallelism`.
   - If the email does NOT exist: deterministically compute a synthetic salt:
     `fake_salt = Base64(HMAC-SHA256(SERVER_SECRET, normalized_email)[0..16])`
     Return HTTP 200 with standard defaults (`m = 65536`, `t = 3`, `p = 1`). Attackers cannot determine whether an account exists prior to authentication.

---

## 3. Data Storage & Schema

The storage abstraction defines a `Repository` trait with dual implementations: `SqliteRepository` and `PostgresRepository`. Tables and indices are created automatically at server startup.

### 3.1 Database Tables

#### Table: `users`
| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | `TEXT` | PRIMARY KEY | UUID string (v4) |
| `email` | `TEXT` | UNIQUE NOT NULL | Normalized email (`trim() + lowercase()`) |
| `server_password_hash` | `TEXT` | NOT NULL | Argon2id hash of `client_auth_key` |
| `kdf_salt` | `TEXT` | NOT NULL | 16-byte base64 salt |
| `kdf_memory_kb` | `INTEGER` | NOT NULL DEFAULT 65536 | Argon2id memory cost |
| `kdf_iterations` | `INTEGER` | NOT NULL DEFAULT 3 | Argon2id iteration count |
| `kdf_parallelism` | `INTEGER` | NOT NULL DEFAULT 1 | Argon2id lanes |
| `wrapped_vault_key` | `TEXT` | NOT NULL | AES-256-GCM envelope (`v1.<iv>.<cipher>`) |
| `created_at` | `BIGINT` | NOT NULL | Unix epoch timestamp (ms) |
| `updated_at` | `BIGINT` | NOT NULL | Unix epoch timestamp (ms) |

#### Table: `vault_items`
| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | `TEXT` | NOT NULL | Item UUID string |
| `user_id` | `TEXT` | NOT NULL, REFERENCES `users(id)` ON DELETE CASCADE | Owner user UUID |
| `encrypted_payload` | `TEXT` | NOT NULL | AES-256-GCM envelope (`v1.<iv>.<cipher>`) |
| `version` | `BIGINT` | NOT NULL DEFAULT 1 | Incremental item update version |
| `deleted_at` | `BIGINT` | NULLABLE | Soft-deletion timestamp (tombstone) |
| `created_at` | `BIGINT` | NOT NULL | Unix epoch timestamp (ms) |
| `updated_at` | `BIGINT` | NOT NULL | Unix epoch timestamp (ms) |
*Primary Key*: `(user_id, id)`.  
*Index*: `idx_vault_items_user_updated (user_id, updated_at)`.

#### Table: `vault_snapshots`
| Column | Type | Constraints | Description |
|---|---|---|---|
| `user_id` | `TEXT` | PRIMARY KEY, REFERENCES `users(id)` ON DELETE CASCADE | Owner user UUID |
| `encrypted_blob` | `BLOB` | NOT NULL | Raw binary ciphertext (Zstd-compressed, then AES-256-GCM encrypted) |
| `version` | `BIGINT` | NOT NULL DEFAULT 1 | Monotonic snapshot version counter |
| `updated_at` | `BIGINT` | NOT NULL | Unix epoch timestamp (ms) |

---

## 4. API Endpoints

### 4.1 Unauthenticated Endpoints

#### `GET /api/health`
- **Purpose**: System health check.
- **Response `200 OK`**:
  ```json
  {
    "status": "healthy",
    "version": "0.1.0",
    "timestamp": 1700000000000
  }
  ```

#### `GET /api/auth/params?email={email}`
- **Purpose**: Retrieve KDF parameters without leaking email existence.
- **Query Params**: `email` (string, required).
- **Response `200 OK`**:
  ```json
  {
    "kdf_salt": "b64_salt...",
    "kdf_memory_kb": 65536,
    "kdf_iterations": 3,
    "kdf_parallelism": 1
  }
  ```

#### `POST /api/auth/register`
- **Purpose**: Create a new account with wrapped vault key and KDF salt.
- **Request Body**:
  ```json
  {
    "email": "user@example.com",
    "client_auth_key": "b64_key...",
    "kdf_salt": "b64_salt...",
    "kdf_memory_kb": 65536,
    "kdf_iterations": 3,
    "kdf_parallelism": 1,
    "wrapped_vault_key": "v1.<iv>.<cipher>"
  }
  ```
- **Responses**:
  - `201 Created`:
    ```json
    {
      "token": "jwt_token...",
      "user_id": "uuid...",
      "email": "user@example.com"
    }
    ```
  - `409 Conflict`: Email already registered.
  - `400 Bad Request`: Malformed payload or validation error.

#### `POST /api/auth/login`
- **Purpose**: Authenticate user and retrieve wrapped vault key.
- **Request Body**:
  ```json
  {
    "email": "user@example.com",
    "client_auth_key": "b64_key..."
  }
  ```
- **Responses**:
  - `200 OK`:
    ```json
    {
      "token": "jwt_token...",
      "user_id": "uuid...",
      "wrapped_vault_key": "v1.<iv>.<cipher>",
      "kdf_salt": "b64_salt...",
      "kdf_memory_kb": 65536,
      "kdf_iterations": 3,
      "kdf_parallelism": 1
    }
    ```
  - `401 Unauthorized`: Invalid credentials.

---

### 4.2 Authenticated Endpoints (`Authorization: Bearer <jwt>`)

#### `GET /api/auth/me`
- **Response `200 OK`**:
  ```json
  {
    "user_id": "uuid...",
    "email": "user@example.com",
    "wrapped_vault_key": "v1.<iv>.<cipher>",
    "kdf_salt": "b64_salt...",
    "kdf_memory_kb": 65536,
    "kdf_iterations": 3,
    "kdf_parallelism": 1,
    "created_at": 1700000000000,
    "updated_at": 1700000000000
  }
  ```

#### `POST /api/auth/rotate-password`
- **Purpose**: Atomically update server credentials, KDF parameters, and re-wrapped vault key.
- **Request Body**:
  ```json
  {
    "old_client_auth_key": "b64_old...",
    "new_client_auth_key": "b64_new...",
    "new_kdf_salt": "b64_new_salt...",
    "new_kdf_memory_kb": 65536,
    "new_kdf_iterations": 3,
    "new_kdf_parallelism": 1,
    "new_wrapped_vault_key": "v1.<iv>.<cipher>"
  }
  ```
- **Responses**:
  - `200 OK`: `{"status": "password_rotated"}`
  - `401 Unauthorized`: `old_client_auth_key` verification failed.

#### `GET /api/vault/sync`
- **Purpose**: Download consolidated encrypted backup binary archive.
- **Headers**:
  - Optional `If-None-Match: "<version>"`
- **Responses**:
  - `200 OK`:
    - Headers: `Content-Type: application/octet-stream`, `ETag: "<version>"`
    - Body: raw binary bytes.
  - `304 Not Modified`: ETag matches current version.
  - `404 Not Found`: No snapshot uploaded yet.

#### `POST /api/vault/sync`
- **Purpose**: Upload new consolidated encrypted backup binary archive.
- **Headers**:
  - `Content-Type: application/octet-stream`
  - Optional `If-Match: "<expected_version>"`
- **Body**: raw binary bytes.
- **Responses**:
  - `200 OK`:
    ```json
    {
      "version": 2,
      "updated_at": 1700000005000,
      "size_bytes": 1048576
    }
    ```
  - `412 Precondition Failed`: `If-Match` does not match the current server version (concurrent update conflict).

#### `GET /api/vault/sync/meta`
- **Purpose**: Check snapshot status without downloading the blob.
- **Response `200 OK`**:
  ```json
  {
    "exists": true,
    "version": 2,
    "updated_at": 1700000005000,
    "size_bytes": 1048576
  }
  ```

#### `GET /api/items?since={timestamp_ms}`
- **Purpose**: Incremental delta synchronization for granular items.
- **Query Params**: `since` (optional i64 ms timestamp).
- **Response `200 OK`**:
  ```json
  {
    "items": [
      {
        "id": "uuid...",
        "encrypted_payload": "v1.<iv>.<cipher>",
        "version": 1,
        "deleted_at": null,
        "created_at": 1700000000000,
        "updated_at": 1700000002000
      }
    ],
    "server_timestamp": 1700000005000
  }
  ```

#### `POST /api/items`
- **Purpose**: Upsert or tombstone granular items.
- **Request Body**:
  ```json
  {
    "items": [
      {
        "id": "uuid...",
        "encrypted_payload": "v1.<iv>.<cipher>",
        "deleted_at": null
      }
    ]
  }
  ```
- **Response `200 OK`**:
  ```json
  {
    "synced": [
      {
        "id": "uuid...",
        "version": 2,
        "updated_at": 1700000005000
      }
    ],
    "server_timestamp": 1700000005000
  }
  ```

---

## 5. Rust Project Architecture & Crates

### 5.1 Project Directory Structure
```
syncserver-rs/
├── Cargo.toml
├── src/
│   ├── main.rs               # CLI entrypoint, configuration parsing, DB init, server launch
│   ├── config.rs             # Environment / config struct (DATABASE_URL, SERVER_SECRET, JWT_SECRET, PORT)
│   ├── error.rs              # Unified AppError enum & IntoResponse mapping
│   ├── crypto/
│   │   ├── mod.rs
│   │   ├── argon.rs          # Server-side Argon2id hash & verify
│   │   └── fake_salt.rs      # Deterministic HMAC-SHA256 fake salt generation
│   ├── auth/
│   │   ├── mod.rs
│   │   ├── jwt.rs            # JWT claims encoding/decoding & extractor
│   │   └── middleware.rs     # Axum AuthUser extractor for protected routes
│   ├── db/
│   │   ├── mod.rs            # Repository trait definition
│   │   ├── sqlite.rs         # SQLite implementation using sqlx::SqlitePool
│   │   ├── postgres.rs       # PostgreSQL implementation using sqlx::PgPool
│   │   └── models.rs         # Database record structures
│   ├── routes/
│   │   ├── mod.rs            # Router assembly & middleware
│   │   ├── auth.rs           # /api/auth routes
│   │   ├── vault.rs          # /api/vault/sync routes
│   │   └── items.rs          # /api/items routes
│   └── tests/
│       ├── auth_tests.rs     # Integration tests for auth & fake salts
│       ├── vault_tests.rs    # Integration tests for /api/vault/sync
│       └── item_tests.rs     # Integration tests for /api/items
└── migrations/
    ├── sqlite/
    │   └── 0001_init.sql
    └── postgres/
        └── 0001_init.sql
```

### 5.2 Key Dependencies (`Cargo.toml`)
- **Web Framework**: `axum = "0.8"`, `tokio = { version = "1.40", features = ["full"] }`, `tower = "0.5"`, `tower-http = { version = "0.6", features = ["cors", "trace", "limit"] }`
- **Database**: `sqlx = { version = "0.8", features = ["runtime-tokio", "tls-rustls", "sqlite", "postgres", "macros"] }`
- **Cryptography**: `argon2 = "0.5"`, `hmac = "0.12"`, `sha2 = "0.10"`, `subtle = "2.6"`, `rand = "0.8"`
- **Authentication**: `jsonwebtoken = "9.3"`
- **Serialization & Formats**: `serde = { version = "1.0", features = ["derive"] }`, `serde_json = "1.0"`, `base64 = "0.22"`
- **Utilities**: `uuid = { version = "1.10", features = ["v4", "serde"] }`, `tracing = "0.1"`, `tracing-subscriber = { version = "0.3", features = ["env-filter"] }`, `dotenvy = "0.15"`

---

## 6. Testing & Verification Strategy
1. **Unit Tests**:
   - Password hashing and constant-time verification using Argon2id.
   - Deterministic fake salt generation: verify that same email yields same fake salt, different emails yield different salts, and salt output is exactly 16 bytes base64.
   - Normalization: verify case and whitespace canonicalization.
2. **Integration Tests (SQLite in-memory)**:
   - Full user registration, login, and retrieval of wrapped vault key.
   - Password rotation: verify that old credentials fail after rotation and new credentials succeed, while vault items remain accessible.
   - Consolidated sync: verify binary upload, ETag match/mismatch, and precondition conflict handling (HTTP 412).
   - Granular sync: verify batch upsert, timestamp filtering, and tombstoning.
3. **Continuous Integration**:
   - Automated tests against both SQLite and PostgreSQL containers.
