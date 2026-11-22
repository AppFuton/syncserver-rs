use axum::{
    extract::{DefaultBodyLimit, Query, State},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::auth::AuthUser;
use crate::db::models::{VaultItem, VaultItemSyncResult, VaultItemUpsert};
use crate::error::AppError;
use crate::state::AppState;

const ITEMS_MAX_BODY_LIMIT_BYTES: usize = 2 * 1024 * 1024; // 2 MB

#[derive(Debug, Deserialize)]
pub struct GetItemsParams {
    pub since: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GetItemsResponse {
    pub items: Vec<VaultItem>,
    pub server_timestamp: i64,
}

#[derive(Debug, Deserialize)]
pub struct PostItemsRequest {
    pub items: Vec<VaultItemUpsert>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PostItemsResponse {
    pub synced: Vec<VaultItemSyncResult>,
    pub server_timestamp: i64,
}

pub fn items_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/",
            get(get_items_handler).post(post_items_handler),
        )
        .layer(DefaultBodyLimit::max(ITEMS_MAX_BODY_LIMIT_BYTES))
}

pub async fn get_items_handler(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Query(params): Query<GetItemsParams>,
) -> Result<Json<GetItemsResponse>, AppError> {
    let server_timestamp = chrono::Utc::now().timestamp_millis();
    let items = state
        .repo
        .get_vault_items(&auth_user.user_id, params.since)
        .await?;

    Ok(Json(GetItemsResponse {
        items,
        server_timestamp,
    }))
}

pub async fn post_items_handler(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Json(payload): Json<PostItemsRequest>,
) -> Result<Json<PostItemsResponse>, AppError> {
    for item in &payload.items {
        if item.id.trim().is_empty() {
            return Err(AppError::BadRequest("Item id cannot be empty".to_string()));
        }
    }

    let now_ms = state.next_timestamp();
    let synced = state
        .repo
        .upsert_vault_items(&auth_user.user_id, &payload.items, now_ms)
        .await?;

    Ok(Json(PostItemsResponse {
        synced,
        server_timestamp: now_ms,
    }))
}
