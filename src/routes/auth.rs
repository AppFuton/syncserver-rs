use axum::{
    extract::{Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::auth::{create_token, AuthUser};
use crate::crypto::{
    generate_fake_salt, hash_password, normalize_email, verify_dummy_password, verify_password,
};
use crate::db::{NewUser, PasswordRotation};
use crate::error::AppError;
use crate::state::AppState;

const DEFAULT_JWT_EXPIRATION_SECONDS: i64 = 30 * 24 * 3600; // 30 days
const DEFAULT_KDF_MEMORY_KB: i32 = 65536;
const DEFAULT_KDF_ITERATIONS: i32 = 3;
const DEFAULT_KDF_PARALLELISM: i32 = 1;

fn default_kdf_memory_kb() -> i32 {
    DEFAULT_KDF_MEMORY_KB
}

fn default_kdf_iterations() -> i32 {
    DEFAULT_KDF_ITERATIONS
}

fn default_kdf_parallelism() -> i32 {
    DEFAULT_KDF_PARALLELISM
}

#[derive(Debug, Deserialize)]
pub struct AuthParamsQuery {
    pub email: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthParamsResponse {
    pub kdf_salt: String,
    pub kdf_memory_kb: i32,
    pub kdf_iterations: i32,
    pub kdf_parallelism: i32,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub client_auth_key: String,
    pub kdf_salt: String,
    #[serde(default = "default_kdf_memory_kb")]
    pub kdf_memory_kb: i32,
    #[serde(default = "default_kdf_iterations")]
    pub kdf_iterations: i32,
    #[serde(default = "default_kdf_parallelism")]
    pub kdf_parallelism: i32,
    pub wrapped_vault_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub token: String,
    pub user_id: String,
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub client_auth_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub user_id: String,
    pub wrapped_vault_key: String,
    pub kdf_salt: String,
    pub kdf_memory_kb: i32,
    pub kdf_iterations: i32,
    pub kdf_parallelism: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserResponse {
    pub user_id: String,
    pub email: String,
    pub wrapped_vault_key: String,
    pub kdf_salt: String,
    pub kdf_memory_kb: i32,
    pub kdf_iterations: i32,
    pub kdf_parallelism: i32,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct RotatePasswordRequest {
    pub old_client_auth_key: String,
    pub new_client_auth_key: String,
    pub new_kdf_salt: String,
    #[serde(default = "default_kdf_memory_kb")]
    pub new_kdf_memory_kb: i32,
    #[serde(default = "default_kdf_iterations")]
    pub new_kdf_iterations: i32,
    #[serde(default = "default_kdf_parallelism")]
    pub new_kdf_parallelism: i32,
    pub new_wrapped_vault_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RotatePasswordResponse {
    pub status: String,
}

pub fn auth_routes() -> Router<AppState> {
    Router::new()
        .route("/params", get(auth_params_handler))
        .route("/register", post(register_handler))
        .route("/login", post(login_handler))
        .route("/me", get(me_handler))
        .route("/rotate-password", post(rotate_password_handler))
}

pub async fn auth_params_handler(
    State(state): State<AppState>,
    Query(query): Query<AuthParamsQuery>,
) -> Result<Json<AuthParamsResponse>, AppError> {
    let normalized = normalize_email(&query.email);
    if normalized.is_empty() {
        return Err(AppError::BadRequest(
            "email parameter is required".to_string(),
        ));
    }

    if let Some(user) = state.repo.get_user_by_email(&normalized).await? {
        Ok(Json(AuthParamsResponse {
            kdf_salt: user.kdf_salt,
            kdf_memory_kb: user.kdf_memory_kb,
            kdf_iterations: user.kdf_iterations,
            kdf_parallelism: user.kdf_parallelism,
        }))
    } else {
        let fake_salt = generate_fake_salt(state.config.server_secret.as_bytes(), &normalized);
        Ok(Json(AuthParamsResponse {
            kdf_salt: fake_salt,
            kdf_memory_kb: DEFAULT_KDF_MEMORY_KB,
            kdf_iterations: DEFAULT_KDF_ITERATIONS,
            kdf_parallelism: DEFAULT_KDF_PARALLELISM,
        }))
    }
}

pub async fn register_handler(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), AppError> {
    let normalized_email = normalize_email(&payload.email);
    if normalized_email.is_empty() {
        return Err(AppError::BadRequest("email cannot be empty".to_string()));
    }
    if payload.client_auth_key.trim().is_empty() {
        return Err(AppError::BadRequest(
            "client_auth_key cannot be empty".to_string(),
        ));
    }
    if payload.kdf_salt.trim().is_empty() {
        return Err(AppError::BadRequest("kdf_salt cannot be empty".to_string()));
    }
    if payload.wrapped_vault_key.trim().is_empty() {
        return Err(AppError::BadRequest(
            "wrapped_vault_key cannot be empty".to_string(),
        ));
    }

    let server_password_hash = hash_password(&payload.client_auth_key)?;
    let new_user = NewUser {
        id: None,
        email: normalized_email.clone(),
        server_password_hash,
        kdf_salt: payload.kdf_salt,
        kdf_memory_kb: payload.kdf_memory_kb,
        kdf_iterations: payload.kdf_iterations,
        kdf_parallelism: payload.kdf_parallelism,
        wrapped_vault_key: payload.wrapped_vault_key,
    };

    let user = state.repo.create_user(&new_user).await?;
    let token = create_token(
        &user.id,
        &state.config.jwt_secret,
        DEFAULT_JWT_EXPIRATION_SECONDS,
    )?;

    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            token,
            user_id: user.id,
            email: user.email,
        }),
    ))
}

pub async fn login_handler(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    let normalized_email = normalize_email(&payload.email);
    if normalized_email.is_empty() || payload.client_auth_key.is_empty() {
        return Err(AppError::BadRequest("Invalid credentials".to_string()));
    }

    let user_opt = state.repo.get_user_by_email(&normalized_email).await?;
    match user_opt {
        None => {
            // Timing defense: simulate verification cost against precomputed dummy hash
            verify_dummy_password(&payload.client_auth_key)?;
            Err(AppError::Unauthorized("Invalid credentials".to_string()))
        }
        Some(user) => {
            let valid = verify_password(&payload.client_auth_key, &user.server_password_hash)?;
            if !valid {
                return Err(AppError::Unauthorized("Invalid credentials".to_string()));
            }

            let token = create_token(
                &user.id,
                &state.config.jwt_secret,
                DEFAULT_JWT_EXPIRATION_SECONDS,
            )?;

            Ok(Json(LoginResponse {
                token,
                user_id: user.id,
                wrapped_vault_key: user.wrapped_vault_key,
                kdf_salt: user.kdf_salt,
                kdf_memory_kb: user.kdf_memory_kb,
                kdf_iterations: user.kdf_iterations,
                kdf_parallelism: user.kdf_parallelism,
            }))
        }
    }
}

pub async fn me_handler(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> Result<Json<UserResponse>, AppError> {
    let user = state
        .repo
        .get_user_by_id(&auth_user.user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    Ok(Json(UserResponse {
        user_id: user.id,
        email: user.email,
        wrapped_vault_key: user.wrapped_vault_key,
        kdf_salt: user.kdf_salt,
        kdf_memory_kb: user.kdf_memory_kb,
        kdf_iterations: user.kdf_iterations,
        kdf_parallelism: user.kdf_parallelism,
        created_at: user.created_at,
        updated_at: user.updated_at,
    }))
}

pub async fn rotate_password_handler(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Json(payload): Json<RotatePasswordRequest>,
) -> Result<Json<RotatePasswordResponse>, AppError> {
    if payload.old_client_auth_key.is_empty()
        || payload.new_client_auth_key.is_empty()
        || payload.new_kdf_salt.trim().is_empty()
        || payload.new_wrapped_vault_key.trim().is_empty()
    {
        return Err(AppError::BadRequest(
            "Required fields cannot be empty".to_string(),
        ));
    }

    let rotation = PasswordRotation {
        new_client_auth_key: payload.new_client_auth_key,
        new_kdf_salt: payload.new_kdf_salt,
        new_kdf_memory_kb: payload.new_kdf_memory_kb,
        new_kdf_iterations: payload.new_kdf_iterations,
        new_kdf_parallelism: payload.new_kdf_parallelism,
        new_wrapped_vault_key: payload.new_wrapped_vault_key,
    };

    state
        .repo
        .rotate_password(&auth_user.user_id, &payload.old_client_auth_key, &rotation)
        .await?;

    Ok(Json(RotatePasswordResponse {
        status: "password_rotated".to_string(),
    }))
}
