use std::sync::Arc;
use async_trait::async_trait;

pub mod models;
pub mod postgres;
pub mod sqlite;

pub use models::*;
pub use postgres::PostgresRepository;
pub use sqlite::SqliteRepository;

use crate::error::AppError;

#[async_trait]
pub trait Repository: Send + Sync {
    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, AppError>;
    async fn get_user_by_id(&self, user_id: &str) -> Result<Option<User>, AppError>;
    async fn create_user(&self, user: &NewUser) -> Result<User, AppError>;
    async fn rotate_password(
        &self,
        user_id: &str,
        old_auth_key: &str,
        rotation: &PasswordRotation,
    ) -> Result<(), AppError>;
    async fn get_vault_snapshot(&self, user_id: &str) -> Result<Option<VaultSnapshot>, AppError>;
    async fn get_vault_snapshot_meta(
        &self,
        user_id: &str,
    ) -> Result<Option<VaultSnapshotMeta>, AppError>;
    async fn put_vault_snapshot(
        &self,
        user_id: &str,
        blob: Vec<u8>,
        expected_version: Option<i64>,
    ) -> Result<VaultSnapshotMeta, AppError>;
    async fn get_vault_items(
        &self,
        user_id: &str,
        since: Option<i64>,
    ) -> Result<Vec<VaultItem>, AppError>;
    async fn upsert_vault_items(
        &self,
        user_id: &str,
        items: &[VaultItemUpsert],
        now_ms: i64,
    ) -> Result<Vec<VaultItemSyncResult>, AppError>;
}

pub async fn init_repository(database_url: &str) -> Result<Arc<dyn Repository>, AppError> {
    if database_url.starts_with("postgres://") || database_url.starts_with("postgresql://") {
        let repo = PostgresRepository::new(database_url).await?;
        Ok(Arc::new(repo))
    } else {
        let repo = SqliteRepository::new(database_url).await?;
        Ok(Arc::new(repo))
    }
}

pub async fn create_repository(database_url: &str) -> Result<Arc<dyn Repository>, AppError> {
    init_repository(database_url).await
}
