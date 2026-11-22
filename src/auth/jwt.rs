use chrono::Utc;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::error::AppError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claims {
    pub sub: String,
    pub exp: i64,
    pub iat: i64,
}

pub fn create_token(
    user_id: &str,
    secret: &str,
    expiration_seconds: i64,
) -> Result<String, AppError> {
    let now = Utc::now().timestamp();
    let claims = Claims {
        sub: user_id.to_string(),
        exp: now.saturating_add(expiration_seconds),
        iat: now,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|err| AppError::Internal(format!("Failed to create token: {err}")))
}

pub fn verify_token(token: &str, secret: &str) -> Result<Claims, AppError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.leeway = 0;

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map_err(|err| {
        use jsonwebtoken::errors::ErrorKind;
        match err.kind() {
            ErrorKind::ExpiredSignature => AppError::Unauthorized("Token has expired".to_string()),
            ErrorKind::InvalidSignature => {
                AppError::Unauthorized("Invalid token signature".to_string())
            }
            _ => AppError::Unauthorized(format!("Invalid token: {err}")),
        }
    })?;

    Ok(token_data.claims)
}
