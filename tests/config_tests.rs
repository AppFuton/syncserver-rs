use axum::http::StatusCode;
use axum::response::IntoResponse;
use std::env;
use std::sync::Mutex;
use syncserver_rs::config::Config;
use syncserver_rs::error::AppError;

static ENV_MUTEX: Mutex<()> = Mutex::new(());

#[test]
fn test_config_from_env_defaults() {
    let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    env::remove_var("DATABASE_URL");
    env::remove_var("PORT");
    env::remove_var("HOST");
    env::set_var("SERVER_SECRET", "test_secret_32_bytes_long_minimum_val");
    env::set_var("JWT_SECRET", "test_jwt_secret_32_bytes_minimum_val");

    let config = Config::from_env().expect("Config::from_env should succeed with valid secrets");

    assert_eq!(config.port, 8080);
    assert_eq!(config.host, "0.0.0.0");
    assert_eq!(config.database_url, "sqlite://syncserver.db");
    assert_eq!(config.server_secret, "test_secret_32_bytes_long_minimum_val");
    assert_eq!(config.jwt_secret, "test_jwt_secret_32_bytes_minimum_val");
}

#[test]
fn test_config_custom_values() {
    let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    env::set_var("DATABASE_URL", "postgres://postgres:secret@localhost:5432/sync");
    env::set_var("PORT", "9090");
    env::set_var("HOST", "127.0.0.1");
    env::set_var("SERVER_SECRET", "custom_server_secret_1234567890_32bytes");
    env::set_var("JWT_SECRET", "custom_jwt_secret_1234567890_32bytes");

    let config = Config::from_env().expect("Config::from_env should succeed with custom vars");

    assert_eq!(config.port, 9090);
    assert_eq!(config.host, "127.0.0.1");
    assert_eq!(config.database_url, "postgres://postgres:secret@localhost:5432/sync");
    assert_eq!(config.server_secret, "custom_server_secret_1234567890_32bytes");
    assert_eq!(config.jwt_secret, "custom_jwt_secret_1234567890_32bytes");
}

#[test]
fn test_config_missing_server_secret() {
    let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    env::remove_var("SERVER_SECRET");
    env::set_var("JWT_SECRET", "test_jwt_secret_32_bytes_minimum_val");

    let result = Config::from_env();
    assert!(result.is_err(), "Config should fail without SERVER_SECRET");
}

#[test]
fn test_config_missing_jwt_secret() {
    let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    env::set_var("SERVER_SECRET", "test_secret_32_bytes_long_minimum_val");
    env::remove_var("JWT_SECRET");

    let result = Config::from_env();
    assert!(result.is_err(), "Config should fail without JWT_SECRET");
}

#[test]
fn test_config_empty_secrets() {
    let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    env::set_var("SERVER_SECRET", "");
    env::set_var("JWT_SECRET", "test_jwt_secret_32_bytes_minimum_val");
    assert!(
        Config::from_env().is_err(),
        "Config should fail with empty SERVER_SECRET"
    );

    env::set_var("SERVER_SECRET", "   ");
    assert!(
        Config::from_env().is_err(),
        "Config should fail with whitespace SERVER_SECRET"
    );

    env::set_var("SERVER_SECRET", "test_secret_32_bytes_long_minimum_val");
    env::set_var("JWT_SECRET", "");
    assert!(
        Config::from_env().is_err(),
        "Config should fail with empty JWT_SECRET"
    );

    env::set_var("JWT_SECRET", "   ");
    assert!(
        Config::from_env().is_err(),
        "Config should fail with whitespace JWT_SECRET"
    );
}

#[test]
fn test_config_short_secrets() {
    let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    // SERVER_SECRET shorter than 32 characters
    env::set_var("SERVER_SECRET", "short_secret_under_32");
    env::set_var("JWT_SECRET", "test_jwt_secret_32_bytes_minimum_val");
    let res = Config::from_env();
    assert!(res.is_err());
    assert_eq!(
        res.unwrap_err(),
        AppError::Internal("SERVER_SECRET must be at least 32 characters".to_string())
    );

    // JWT_SECRET shorter than 32 characters
    env::set_var("SERVER_SECRET", "test_secret_32_bytes_long_minimum_val");
    env::set_var("JWT_SECRET", "short_jwt_secret_under_32");
    let res2 = Config::from_env();
    assert!(res2.is_err());
    assert_eq!(
        res2.unwrap_err(),
        AppError::Internal("JWT_SECRET must be at least 32 characters".to_string())
    );
}

#[test]
fn test_config_invalid_port() {
    let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    env::set_var("SERVER_SECRET", "test_secret_32_bytes_long_minimum_val");
    env::set_var("JWT_SECRET", "test_jwt_secret_32_bytes_minimum_val");
    env::set_var("PORT", "not_a_number");

    let result = Config::from_env();
    assert!(result.is_err(), "Config should fail with invalid PORT");
}

#[tokio::test]
async fn test_app_error_into_response() {
    let test_cases = vec![
        (AppError::NotFound, StatusCode::NOT_FOUND, "Not Found"),
        (
            AppError::Unauthorized("Invalid credentials".to_string()),
            StatusCode::UNAUTHORIZED,
            "Invalid credentials",
        ),
        (
            AppError::Conflict("Email already registered".to_string()),
            StatusCode::CONFLICT,
            "Email already registered",
        ),
        (
            AppError::PreconditionFailed("Version mismatch".to_string()),
            StatusCode::PRECONDITION_FAILED,
            "Version mismatch",
        ),
        (
            AppError::BadRequest("Invalid payload".to_string()),
            StatusCode::BAD_REQUEST,
            "Invalid payload",
        ),
        (
            AppError::Internal("Database connection failed".to_string()),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal server error",
        ),
    ];

    for (error, expected_status, expected_msg) in test_cases {
        let response = error.into_response();
        assert_eq!(response.status(), expected_status);

        let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("read response body");
        let json: serde_json::Value =
            serde_json::from_slice(&body_bytes).expect("parse response body as json");

        assert_eq!(
            json.get("error").and_then(|v| v.as_str()),
            Some(expected_msg),
            "Expected error message: {}",
            expected_msg
        );
    }
}

#[test]
fn test_sqlx_error_conversion() {
    let sqlx_err = sqlx::Error::RowNotFound;
    let app_err = AppError::from(sqlx_err);
    assert_eq!(
        app_err,
        AppError::Internal("Internal database error".to_string())
    );
}
