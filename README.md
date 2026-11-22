# syncserver-rs

A high-performance, zero-knowledge synchronization backend for encrypted vault storage and granular record synchronization, built with Rust, Axum, and SQLx.

`syncserver-rs` provides a secure, self-hostable synchronization server designed to support both full vault archive backups and low-latency incremental item-level sync while ensuring that the server never learns plaintext data or master passwords.

---

## Features

- **Zero-Knowledge Architecture:** All sensitive data is client-side encrypted using AES-GCM or ChaCha20-Poly1305 before transmission. The server operates solely as an untrusted blind storage repository.
- **Account Enumeration Defense:** The server generates deterministic pseudorandom fake salts via HMAC-SHA256 using an internal `SERVER_SECRET` for non-existent users, mitigating user enumeration attacks.
- **Timing Defense:** Failed login attempts invoke dummy Argon2id password verification against a fixed internal hash to prevent side-channel timing analysis.
- **Dual Sync Mechanisms:**
  - **Consolidated Vault Archive Sync:** Bulk binary snapshot synchronization with HTTP `ETag` / `If-None-Match` 304 caching and `If-Match` optimistic concurrency control (up to 25 MB).
  - **Granular Items Sync:** Fast batch upsert and delta synchronization with server-assigned monotonic millisecond timestamps and soft-delete tombstone support (up to 2 MB).
- **Atomic Password Rotation:** Seamless credential rotation allowing clients to rotate master passwords, re-wrap vault keys, and update Argon2 parameters in a single atomic transaction.
- **Pluggable Database Engines:** Native support for both **SQLite** (with WAL mode, 5s busy timeouts, and deterministic sorting) and **PostgreSQL** with automatic embedded migrations.
- **Graceful Shutdown:** Clean socket shutdown on OS signals (`SIGINT` / `SIGTERM`).

---

## Security Model & Cryptography

### 1. Key Derivation & Client-Side Separation

```
Master Password + Salt
         │
         ▼
Argon2id (m=65536, t=3, p=1)
         │
         ├─────────────────────────────────────────┐
         ▼                                         ▼
   Client Auth Key                        Vault Encryption Key
         │                                         │
         ▼                                         ▼
  Sent to Server                         Used locally to encrypt:
  (never stored plaintext;                - Vault archive snapshots
   hashed with Argon2id)                  - Granular vault items
                                          - Wrapped Vault Key
```

1. **Client Auth Key:** Derived on the client device. Sent over TLS to authenticate. The server never sees the master password.
2. **Server Password Hash:** The server stores an Argon2id hash of `Client Auth Key` in the database.
3. **Vault Encryption Key:** Stays strictly in client memory. The server receives only `wrapped_vault_key` (the symmetric vault key encrypted under the key derived from the master password).

### 2. User Enumeration Protection

When an unauthenticated client requests pre-login KDF parameters via `GET /api/auth/params?email=...`:
- If the user exists: the server returns their stored `kdf_salt` and KDF parameters.
- If the user does not exist: the server returns a deterministic pseudorandom salt generated using `HMAC-SHA256(SERVER_SECRET, normalized_email)`. The response is indistinguishable from a registered user's response.

### 3. Timing Defense

When a login request targets a non-existent email, the server runs a full Argon2id verification cycle against a precomputed dummy hash, ensuring response latency remains identical between existing and non-existing accounts.

---

## Configuration Reference

Server parameters can be configured via environment variables or a `.env` file located in the working directory:

| Variable | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `HOST` | String | `127.0.0.1` | Network interface to bind. |
| `PORT` | u16 | `8080` | Port to listen on. |
| `DATABASE_URL` | String | `sqlite:syncserver.db` | Connection string (`sqlite:...`, `postgres://...`, or `postgresql://...`). |
| `SERVER_SECRET` | String | *(Required)* | Secret key (minimum 32 characters) for HMAC fake salt derivation. |
| `JWT_SECRET` | String | *(Required)* | Secret key (minimum 32 characters) for JWT authentication token signing. |

### Example `.env`

```ini
HOST=0.0.0.0
PORT=8080
DATABASE_URL=sqlite:data/syncserver.db
SERVER_SECRET=change_this_to_a_cryptographically_secure_random_server_secret_at_least_32_chars
JWT_SECRET=change_this_to_a_cryptographically_secure_random_jwt_secret_at_least_32_chars
RUST_LOG=syncserver_rs=info,tower_http=info
```

---

## API Reference

### Health Check

#### `GET /api/health` (or `GET /health`)
Returns current server operational status, version, and server timestamp.

**Response `200 OK`**:
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "timestamp": 1700000000000
}
```

---

### Authentication

#### `GET /api/auth/params?email={email}`
Returns KDF salt and parameters required for the client to compute the `client_auth_key`.

**Response `200 OK`**:
```json
{
  "kdf_salt": "c2FsdF9leGFtcGxlXzE2Ynl0ZXM=",
  "kdf_memory_kb": 65536,
  "kdf_iterations": 3,
  "kdf_parallelism": 1
}
```

#### `POST /api/auth/register`
Creates a new account with the client-derived auth key and wrapped vault key.

**Request Body**:
```json
{
  "email": "user@example.com",
  "client_auth_key": "client_derived_key_string",
  "kdf_salt": "c2FsdF9leGFtcGxlXzE2Ynl0ZXM=",
  "kdf_memory_kb": 65536,
  "kdf_iterations": 3,
  "kdf_parallelism": 1,
  "wrapped_vault_key": "v1.iv.ciphertext"
}
```

**Response `201 Created`**:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsIn...",
  "user_id": "96472064-a1db-4963-b8bc-a89c93397394",
  "email": "user@example.com"
}
```

#### `POST /api/auth/login`
Authenticates client auth key and returns a 30-day JWT along with the encrypted wrapped vault key.

**Request Body**:
```json
{
  "email": "user@example.com",
  "client_auth_key": "client_derived_key_string"
}
```

**Response `200 OK`**:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsIn...",
  "user_id": "96472064-a1db-4963-b8bc-a89c93397394",
  "wrapped_vault_key": "v1.iv.ciphertext",
  "kdf_salt": "c2FsdF9leGFtcGxlXzE2Ynl0ZXM=",
  "kdf_memory_kb": 65536,
  "kdf_iterations": 3,
  "kdf_parallelism": 1
}
```

#### `POST /api/auth/rotate-password`
Requires Bearer authentication. Verifies `old_client_auth_key` and atomically updates password hash, salt, parameters, and re-wrapped vault key.

**Headers**:
`Authorization: Bearer <token>`

**Request Body**:
```json
{
  "old_client_auth_key": "old_auth_key",
  "new_client_auth_key": "new_auth_key",
  "new_kdf_salt": "bmV3X3NhbHRfZXhhbXBsZQ==",
  "new_kdf_memory_kb": 65536,
  "new_kdf_iterations": 3,
  "new_kdf_parallelism": 1,
  "new_wrapped_vault_key": "v2.new_iv.new_ciphertext"
}
```

**Response `200 OK`**:
```json
{
  "status": "password_rotated"
}
```

---

### Consolidated Vault Archive Sync

Bulk compressed and encrypted snapshot storage with HTTP caching and concurrency control.

#### `GET /api/vault/sync`
Downloads the user's latest encrypted vault snapshot.

**Headers**:
- `Authorization: Bearer <token>`
- `If-None-Match: "<version>"` *(optional)*

**Response `200 OK`**:
- `Content-Type: application/octet-stream`
- `ETag: "<version>"`
- Body: raw encrypted binary blob.

**Response `304 Not Modified`**:
Returned if `If-None-Match` matches current server version. Body is empty.

#### `POST /api/vault/sync`
Uploads a new encrypted vault snapshot (max 25 MB).

**Headers**:
- `Authorization: Bearer <token>`
- `Content-Type: application/octet-stream`
- `If-Match: "<expected_version>"` *(optional for optimistic concurrency control)*

**Response `200 OK`**:
```json
{
  "version": 2,
  "updated_at": 1700000005000,
  "size_bytes": 1048576
}
```
*Note: Returns `412 Precondition Failed` if `If-Match` does not match the current server version.*

#### `GET /api/vault/sync/meta`
Retrieves metadata about current vault snapshot without downloading the payload.

**Response `200 OK`**:
```json
{
  "exists": true,
  "version": 2,
  "updated_at": 1700000005000,
  "size_bytes": 1048576
}
```

---

### Granular Items Sync

Fast, record-level synchronization for individual encrypted vault items.

#### `GET /api/items?since={timestamp_ms}`
Fetches items updated at or after `since`. Omit `since` to retrieve all items.

**Headers**:
- `Authorization: Bearer <token>`

**Response `200 OK`**:
```json
{
  "items": [
    {
      "id": "item-uuid-001",
      "user_id": "96472064-a1db-4963-b8bc-a89c93397394",
      "encrypted_payload": "ciphertext_base64_or_string",
      "version": 1,
      "deleted_at": null,
      "created_at": 1700000001000,
      "updated_at": 1700000001000
    }
  ],
  "server_timestamp": 1700000005000
}
```

#### `POST /api/items`
Batch upsert of encrypted records (max 2 MB). Supports soft deletes via `deleted_at`.

**Headers**:
- `Authorization: Bearer <token>`
- `Content-Type: application/json`

**Request Body**:
```json
{
  "items": [
    {
      "id": "item-uuid-001",
      "encrypted_payload": "ciphertext_base64_or_string",
      "deleted_at": null
    },
    {
      "id": "item-uuid-002",
      "encrypted_payload": "ciphertext_base64_or_string",
      "deleted_at": 1700000005000
    }
  ]
}
```

**Response `200 OK`**:
```json
{
  "synced": [
    {
      "id": "item-uuid-001",
      "version": 1,
      "updated_at": 1700000005000
    },
    {
      "id": "item-uuid-002",
      "version": 2,
      "updated_at": 1700000005001
    }
  ],
  "server_timestamp": 1700000005001
}
```

---

## Self-Hosting Guide

### Running with SQLite

SQLite is the default and recommended for single-node deployments. The server automatically activates WAL mode, busy timeout, and foreign key constraints on startup.

```bash
# Build binary
cargo build --release

# Run with local SQLite database file
DATABASE_URL="sqlite:syncserver.db" \
SERVER_SECRET="replace_with_64_character_hex_or_random_bytes_server_secret" \
JWT_SECRET="replace_with_64_character_hex_or_random_bytes_jwt_secret" \
./target/release/syncserver-rs
```

### Running with PostgreSQL

PostgreSQL is recommended for high-concurrency or clustered multi-instance setups. Embedded SQLx migrations execute automatically on server boot.

```bash
# Run with PostgreSQL connection URI
DATABASE_URL="postgres://user:password@localhost:5432/syncserver" \
SERVER_SECRET="replace_with_64_character_hex_or_random_bytes_server_secret" \
JWT_SECRET="replace_with_64_character_hex_or_random_bytes_jwt_secret" \
./target/release/syncserver-rs
```

### Systemd Service Example

```ini
[Unit]
Description=syncserver-rs zero-knowledge sync server
After=network.target

[Service]
Type=simple
User=syncserver
WorkingDirectory=/var/lib/syncserver
EnvironmentFile=/etc/syncserver.env
ExecStart=/usr/local/bin/syncserver-rs
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

---

## Testing

Run the full suite of integration and unit tests:

```bash
cargo test
```

Run only the full end-to-end client lifecycle test:

```bash
cargo test --test e2e_full_sync_test
```

---

## License

MIT OR Apache-2.0
