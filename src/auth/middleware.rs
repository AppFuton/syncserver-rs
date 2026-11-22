use axum::{
    extract::FromRequestParts,
    http::{header::AUTHORIZATION, request::Parts},
};
use std::sync::Arc;

use crate::auth::jwt::verify_token;
use crate::config::Config;
use crate::error::AppError;
use crate::state::AppState;

pub trait AuthState: Send + Sync {
    fn jwt_secret(&self) -> &str;
}

impl AuthState for AppState {
    fn jwt_secret(&self) -> &str {
        &self.config.jwt_secret
    }
}

impl AuthState for Config {
    fn jwt_secret(&self) -> &str {
        &self.jwt_secret
    }
}

impl AuthState for String {
    fn jwt_secret(&self) -> &str {
        self.as_str()
    }
}

impl AuthState for &str {
    fn jwt_secret(&self) -> &str {
        self
    }
}

impl<T: AuthState + ?Sized> AuthState for Arc<T> {
    fn jwt_secret(&self) -> &str {
        (**self).jwt_secret()
    }
}

impl<T: AuthState + ?Sized> AuthState for &T {
    fn jwt_secret(&self) -> &str {
        (**self).jwt_secret()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthUser {
    pub user_id: String,
}

impl<S> FromRequestParts<S> for AuthUser
where
    S: AuthState + Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(AUTHORIZATION)
            .ok_or_else(|| AppError::Unauthorized("Missing Authorization header".to_string()))?
            .to_str()
            .map_err(|_| AppError::Unauthorized("Invalid Authorization header".to_string()))?;

        let (scheme, token) = auth_header
            .split_once(' ')
            .ok_or_else(|| AppError::Unauthorized("Invalid Authorization header format".to_string()))?;

        if !scheme.eq_ignore_ascii_case("bearer") {
            return Err(AppError::Unauthorized(
                "Invalid Authorization header format".to_string(),
            ));
        }

        let token = token.trim();

        if token.is_empty() {
            return Err(AppError::Unauthorized("Empty Bearer token".to_string()));
        }

        let claims = verify_token(token, state.jwt_secret())?;

        Ok(AuthUser {
            user_id: claims.sub,
        })
    }
}
