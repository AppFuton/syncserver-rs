use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, PartialEq, Eq)]
pub struct User {
    pub id: String,
    pub email: String,
    pub server_password_hash: String,
    pub kdf_salt: String,
    pub kdf_memory_kb: i32,
    pub kdf_iterations: i32,
    pub kdf_parallelism: i32,
    pub wrapped_vault_key: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NewUser {
    pub id: Option<String>,
    pub email: String,
    pub server_password_hash: String,
    pub kdf_salt: String,
    pub kdf_memory_kb: i32,
    pub kdf_iterations: i32,
    pub kdf_parallelism: i32,
    pub wrapped_vault_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasswordRotation {
    pub new_client_auth_key: String,
    pub new_kdf_salt: String,
    pub new_kdf_memory_kb: i32,
    pub new_kdf_iterations: i32,
    pub new_kdf_parallelism: i32,
    pub new_wrapped_vault_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, PartialEq, Eq)]
pub struct VaultItem {
    pub id: String,
    pub user_id: String,
    pub encrypted_payload: String,
    pub version: i64,
    pub deleted_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultItemUpsert {
    pub id: String,
    pub encrypted_payload: String,
    #[serde(default)]
    pub deleted_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultItemSyncResult {
    pub id: String,
    pub version: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, PartialEq, Eq)]
pub struct VaultSnapshot {
    pub user_id: String,
    pub encrypted_blob: Vec<u8>,
    pub version: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultSnapshotMeta {
    pub version: i64,
    pub updated_at: i64,
    pub size_bytes: i64,
}
