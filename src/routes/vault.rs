use axum::{
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, State},
    http::{header, HeaderMap, StatusCode},
    response::Response,
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::auth::AuthUser;
use crate::error::AppError;
use crate::state::AppState;

const VAULT_MAX_BODY_LIMIT_BYTES: usize = 25 * 1024 * 1024; // 25 MB

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultSnapshotResponse {
    pub version: i64,
    pub updated_at: i64,
    pub size_bytes: i64,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultSyncMetaResponse {
    pub exists: bool,
    pub version: Option<i64>,
    pub updated_at: Option<i64>,
    pub size_bytes: usize,
}

pub fn vault_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/sync",
            get(get_vault_sync_handler).post(post_vault_sync_handler),
        )
        .route("/sync/meta", get(get_vault_sync_meta_handler))
        .layer(DefaultBodyLimit::max(VAULT_MAX_BODY_LIMIT_BYTES))
}

fn matches_etag(header_val: &str, current_version: i64) -> bool {
    let current_str = current_version.to_string();
    for part in header_val.split(',') {
        let part = part.trim();
        let part = part.strip_prefix("W/").unwrap_or(part).trim();
        let part = part.trim_matches('"').trim();
        if part == "*" || part == current_str {
            return true;
        }
    }
    false
}

fn parse_if_match_header(headers: &HeaderMap) -> Result<Option<i64>, AppError> {
    if let Some(val) = headers.get(header::IF_MATCH) {
        let s = val
            .to_str()
            .map_err(|_| AppError::BadRequest("Invalid If-Match header encoding".to_string()))?;
        let s = s.trim();
        let s = s.trim_matches('"').trim();
        if s.is_empty() {
            Ok(None)
        } else {
            let version = s
                .parse::<i64>()
                .map_err(|_| AppError::BadRequest("Invalid If-Match version integer".to_string()))?;
            Ok(Some(version))
        }
    } else {
        Ok(None)
    }
}

pub async fn get_vault_sync_handler(
    State(state): State<AppState>,
    auth_user: AuthUser,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let meta = state
        .repo
        .get_vault_snapshot_meta(&auth_user.user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let etag_value = format!("\"{}\"", meta.version);

    if let Some(if_none_match) = headers.get(header::IF_NONE_MATCH) {
        if let Ok(val) = if_none_match.to_str() {
            if matches_etag(val, meta.version) {
                return Response::builder()
                    .status(StatusCode::NOT_MODIFIED)
                    .header(header::ETAG, etag_value)
                    .body(Body::empty())
                    .map_err(|e| AppError::Internal(e.to_string()));
            }
        }
    }

    let snapshot = state
        .repo
        .get_vault_snapshot(&auth_user.user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::ETAG, etag_value)
        .body(Body::from(snapshot.encrypted_blob))
        .map_err(|e| AppError::Internal(e.to_string()))
}

pub async fn post_vault_sync_handler(
    State(state): State<AppState>,
    auth_user: AuthUser,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Json<VaultSnapshotResponse>, AppError> {
    let expected_version = parse_if_match_header(&headers)?;

    let meta = state
        .repo
        .put_vault_snapshot(&auth_user.user_id, bytes.to_vec(), expected_version)
        .await?;

    Ok(Json(VaultSnapshotResponse {
        version: meta.version,
        updated_at: meta.updated_at,
        size_bytes: meta.size_bytes,
    }))
}

pub async fn get_vault_sync_meta_handler(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> Result<Json<VaultSyncMetaResponse>, AppError> {
    let meta = state
        .repo
        .get_vault_snapshot_meta(&auth_user.user_id)
        .await?;

    match meta {
        Some(m) => Ok(Json(VaultSyncMetaResponse {
            exists: true,
            version: Some(m.version),
            updated_at: Some(m.updated_at),
            size_bytes: m.size_bytes as usize,
        })),
        None => Ok(Json(VaultSyncMetaResponse {
            exists: false,
            version: None,
            updated_at: None,
            size_bytes: 0,
        })),
    }
}
