use async_trait::async_trait;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};

use crate::crypto::normalize_email;
use crate::db::models::{
    NewUser, PasswordRotation, User, VaultItem, VaultItemSyncResult, VaultItemUpsert, VaultSnapshot,
    VaultSnapshotMeta,
};
use crate::db::Repository;
use crate::error::AppError;

#[derive(Clone)]
pub struct PostgresRepository {
    pool: PgPool,
}

impl PostgresRepository {
    pub async fn new(database_url: &str) -> Result<Self, AppError> {
        let pool = PgPoolOptions::new()
            .connect(database_url)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to connect to PostgreSQL: {e}")))?;

        sqlx::migrate!("migrations/postgres")
            .run(&pool)
            .await
            .map_err(|e| AppError::Internal(format!("Postgres migration failed: {e}")))?;

        Ok(Self { pool })
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

#[async_trait]
impl Repository for PostgresRepository {
    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, AppError> {
        let normalized = normalize_email(email);
        let user = sqlx::query_as::<_, User>(
            "SELECT id, email, server_password_hash, kdf_salt, kdf_memory_kb, kdf_iterations, kdf_parallelism, wrapped_vault_key, created_at, updated_at FROM users WHERE email = $1"
        )
        .bind(&normalized)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get user by email: {e}")))?;

        Ok(user)
    }

    async fn get_user_by_id(&self, user_id: &str) -> Result<Option<User>, AppError> {
        let user = sqlx::query_as::<_, User>(
            "SELECT id, email, server_password_hash, kdf_salt, kdf_memory_kb, kdf_iterations, kdf_parallelism, wrapped_vault_key, created_at, updated_at FROM users WHERE id = $1"
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get user by id: {e}")))?;

        Ok(user)
    }

    async fn create_user(&self, user: &NewUser) -> Result<User, AppError> {
        let normalized_email = normalize_email(&user.email);
        let id = user
            .id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let now = chrono::Utc::now().timestamp_millis();

        let result = sqlx::query(
            "INSERT INTO users (id, email, server_password_hash, kdf_salt, kdf_memory_kb, kdf_iterations, kdf_parallelism, wrapped_vault_key, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"
        )
        .bind(&id)
        .bind(&normalized_email)
        .bind(&user.server_password_hash)
        .bind(&user.kdf_salt)
        .bind(user.kdf_memory_kb)
        .bind(user.kdf_iterations)
        .bind(user.kdf_parallelism)
        .bind(&user.wrapped_vault_key)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => Ok(User {
                id,
                email: normalized_email,
                server_password_hash: user.server_password_hash.clone(),
                kdf_salt: user.kdf_salt.clone(),
                kdf_memory_kb: user.kdf_memory_kb,
                kdf_iterations: user.kdf_iterations,
                kdf_parallelism: user.kdf_parallelism,
                wrapped_vault_key: user.wrapped_vault_key.clone(),
                created_at: now,
                updated_at: now,
            }),
            Err(sqlx::Error::Database(ref db_err)) if db_err.is_unique_violation() => {
                Err(AppError::Conflict("Email already registered".to_string()))
            }
            Err(e) => Err(AppError::Internal(format!("Failed to create user: {e}"))),
        }
    }

    async fn rotate_password(
        &self,
        user_id: &str,
        old_auth_key: &str,
        rotation: &PasswordRotation,
    ) -> Result<(), AppError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to start transaction: {e}")))?;

        let user = sqlx::query_as::<_, User>(
            "SELECT id, email, server_password_hash, kdf_salt, kdf_memory_kb, kdf_iterations, kdf_parallelism, wrapped_vault_key, created_at, updated_at FROM users WHERE id = $1 FOR UPDATE"
        )
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to fetch user during rotation: {e}")))?;

        let user = match user {
            Some(u) => u,
            None => return Err(AppError::NotFound),
        };

        let valid = crate::crypto::verify_password(old_auth_key, &user.server_password_hash)?;
        if !valid {
            return Err(AppError::Unauthorized("Invalid old credentials".to_string()));
        }

        let new_server_password_hash =
            crate::crypto::hash_password(&rotation.new_client_auth_key)?;
        let now = chrono::Utc::now().timestamp_millis();

        sqlx::query(
            "UPDATE users SET server_password_hash = $1, kdf_salt = $2, kdf_memory_kb = $3, kdf_iterations = $4, kdf_parallelism = $5, wrapped_vault_key = $6, updated_at = $7 WHERE id = $8"
        )
        .bind(&new_server_password_hash)
        .bind(&rotation.new_kdf_salt)
        .bind(rotation.new_kdf_memory_kb)
        .bind(rotation.new_kdf_iterations)
        .bind(rotation.new_kdf_parallelism)
        .bind(&rotation.new_wrapped_vault_key)
        .bind(now)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to update user during rotation: {e}")))?;

        tx.commit()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to commit rotation transaction: {e}")))?;

        Ok(())
    }

    async fn get_vault_snapshot(&self, user_id: &str) -> Result<Option<VaultSnapshot>, AppError> {
        let snapshot = sqlx::query_as::<_, VaultSnapshot>(
            "SELECT user_id, encrypted_blob, version, updated_at FROM vault_snapshots WHERE user_id = $1"
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get vault snapshot: {e}")))?;

        Ok(snapshot)
    }

    async fn get_vault_snapshot_meta(
        &self,
        user_id: &str,
    ) -> Result<Option<VaultSnapshotMeta>, AppError> {
        let row = sqlx::query(
            "SELECT user_id, octet_length(encrypted_blob), version, updated_at FROM vault_snapshots WHERE user_id = $1"
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get vault snapshot meta: {e}")))?;

        Ok(row.map(|r| {
            let size_bytes: i64 = r
                .try_get::<i64, _>(1)
                .or_else(|_| r.try_get::<i32, _>(1).map(|v| v as i64))
                .unwrap_or(0);
            let version: i64 = r.get(2);
            let updated_at: i64 = r.get(3);
            VaultSnapshotMeta {
                version,
                updated_at,
                size_bytes,
            }
        }))
    }

    async fn put_vault_snapshot(
        &self,
        user_id: &str,
        blob: Vec<u8>,
        expected_version: Option<i64>,
    ) -> Result<VaultSnapshotMeta, AppError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to start transaction: {e}")))?;

        let current: Option<(i64,)> = sqlx::query_as(
            "SELECT version FROM vault_snapshots WHERE user_id = $1 FOR UPDATE"
        )
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to check current snapshot version: {e}")))?;

        let current_version = current.map(|(v,)| v).unwrap_or(0);

        if let Some(expected) = expected_version {
            if current_version != expected {
                return Err(AppError::PreconditionFailed("Version mismatch".to_string()));
            }
        }

        let new_version = current_version + 1;
        let now_ms = chrono::Utc::now().timestamp_millis();
        let size_bytes = blob.len() as i64;

        if current.is_some() {
            sqlx::query(
                "UPDATE vault_snapshots SET encrypted_blob = $1, version = $2, updated_at = $3 WHERE user_id = $4"
            )
            .bind(&blob)
            .bind(new_version)
            .bind(now_ms)
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to update vault snapshot: {e}")))?;
        } else {
            sqlx::query(
                "INSERT INTO vault_snapshots (user_id, encrypted_blob, version, updated_at) VALUES ($1, $2, $3, $4)"
            )
            .bind(user_id)
            .bind(&blob)
            .bind(new_version)
            .bind(now_ms)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to insert vault snapshot: {e}")))?;
        }

        tx.commit()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to commit snapshot transaction: {e}")))?;

        Ok(VaultSnapshotMeta {
            version: new_version,
            updated_at: now_ms,
            size_bytes,
        })
    }

    async fn get_vault_items(
        &self,
        user_id: &str,
        since: Option<i64>,
    ) -> Result<Vec<VaultItem>, AppError> {
        let items = match since {
            Some(since_ms) => {
                sqlx::query_as::<_, VaultItem>(
                    "SELECT id, user_id, encrypted_payload, version, deleted_at, created_at, updated_at FROM vault_items WHERE user_id = $1 AND updated_at > $2 ORDER BY updated_at ASC, id ASC"
                )
                .bind(user_id)
                .bind(since_ms)
                .fetch_all(&self.pool)
                .await
            }
            None => {
                sqlx::query_as::<_, VaultItem>(
                    "SELECT id, user_id, encrypted_payload, version, deleted_at, created_at, updated_at FROM vault_items WHERE user_id = $1 ORDER BY updated_at ASC, id ASC"
                )
                .bind(user_id)
                .fetch_all(&self.pool)
                .await
            }
        }
        .map_err(|e| AppError::Internal(format!("Failed to get vault items: {e}")))?;

        Ok(items)
    }

    async fn upsert_vault_items(
        &self,
        user_id: &str,
        items: &[VaultItemUpsert],
        now_ms: i64,
    ) -> Result<Vec<VaultItemSyncResult>, AppError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to start transaction: {e}")))?;

        let mut results = Vec::with_capacity(items.len());

        for item in items {
            let existing: Option<(i64,)> = sqlx::query_as(
                "SELECT version FROM vault_items WHERE user_id = $1 AND id = $2 FOR UPDATE"
            )
            .bind(user_id)
            .bind(&item.id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to query vault item: {e}")))?;

            let version = match existing {
                Some((curr_version,)) => {
                    let next_version = curr_version + 1;
                    sqlx::query(
                        "UPDATE vault_items SET encrypted_payload = $1, version = $2, deleted_at = $3, updated_at = $4 WHERE user_id = $5 AND id = $6"
                    )
                    .bind(&item.encrypted_payload)
                    .bind(next_version)
                    .bind(item.deleted_at)
                    .bind(now_ms)
                    .bind(user_id)
                    .bind(&item.id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| AppError::Internal(format!("Failed to update vault item: {e}")))?;

                    next_version
                }
                None => {
                    sqlx::query(
                        "INSERT INTO vault_items (id, user_id, encrypted_payload, version, deleted_at, created_at, updated_at) VALUES ($1, $2, $3, 1, $4, $5, $6)"
                    )
                    .bind(&item.id)
                    .bind(user_id)
                    .bind(&item.encrypted_payload)
                    .bind(item.deleted_at)
                    .bind(now_ms)
                    .bind(now_ms)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| AppError::Internal(format!("Failed to insert vault item: {e}")))?;

                    1
                }
            };

            results.push(VaultItemSyncResult {
                id: item.id.clone(),
                version,
                updated_at: now_ms,
            });
        }

        tx.commit()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to commit vault items transaction: {e}")))?;

        Ok(results)
    }
}
