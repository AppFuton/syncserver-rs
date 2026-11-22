use crate::error::AppError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub database_url: String,
    pub server_secret: String,
    pub jwt_secret: String,
    pub port: u16,
    pub host: String,
}

impl Config {
    pub fn from_env() -> Result<Self, AppError> {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "sqlite://syncserver.db".to_string());

        let server_secret = match std::env::var("SERVER_SECRET") {
            Ok(val) if !val.trim().is_empty() => val,
            _ => {
                return Err(AppError::Internal(
                    "SERVER_SECRET environment variable is required and cannot be empty".to_string(),
                ))
            }
        };

        let jwt_secret = match std::env::var("JWT_SECRET") {
            Ok(val) if !val.trim().is_empty() => val,
            _ => {
                return Err(AppError::Internal(
                    "JWT_SECRET environment variable is required and cannot be empty".to_string(),
                ))
            }
        };

        let port = match std::env::var("PORT") {
            Ok(val) => val.parse::<u16>().map_err(|_| {
                AppError::Internal("PORT must be a valid u16 integer".to_string())
            })?,
            Err(_) => 8080,
        };

        let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());

        Ok(Config {
            database_url,
            server_secret,
            jwt_secret,
            port,
            host,
        })
    }
}
