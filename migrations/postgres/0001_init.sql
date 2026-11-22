CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    server_password_hash TEXT NOT NULL,
    kdf_salt TEXT NOT NULL,
    kdf_memory_kb INTEGER NOT NULL DEFAULT 65536,
    kdf_iterations INTEGER NOT NULL DEFAULT 3,
    kdf_parallelism INTEGER NOT NULL DEFAULT 1,
    wrapped_vault_key TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS vault_items (
    id TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_payload TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1,
    deleted_at BIGINT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (user_id, id)
);

CREATE INDEX IF NOT EXISTS idx_vault_items_user_updated ON vault_items (user_id, updated_at);

CREATE TABLE IF NOT EXISTS vault_snapshots (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    encrypted_blob BYTEA NOT NULL,
    version BIGINT NOT NULL DEFAULT 1,
    updated_at BIGINT NOT NULL
);
