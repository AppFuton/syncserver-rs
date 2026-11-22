use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    routing::get,
    Router,
};
use std::sync::Arc;
use syncserver_rs::{
    auth::{create_token, verify_token, AuthUser},
    config::Config,
    db::create_repository,
    error::AppError,
    AppState,
};
use tower::ServiceExt;

#[test]
fn test_jwt_encode_decode_roundtrip() {
    let secret = "test_jwt_secret_must_be_long_enough_12345";
    let token = create_token("user-uuid-123", secret, 3600).unwrap();
    let claims = verify_token(&token, secret).unwrap();
    assert_eq!(claims.sub, "user-uuid-123");
    assert!(claims.exp > claims.iat);
}

#[test]
fn test_expired_jwt_fails() {
    let secret = "test_jwt_secret_must_be_long_enough_12345";
    let token = create_token("user-uuid-123", secret, -10).unwrap();
    let result = verify_token(&token, secret);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AppError::Unauthorized(_)));
}

#[test]
fn test_invalid_signature_fails() {
    let secret = "test_jwt_secret_must_be_long_enough_12345";
    let wrong_secret = "wrong_jwt_secret_that_does_not_match";
    let token = create_token("user-uuid-123", secret, 3600).unwrap();
    let result = verify_token(&token, wrong_secret);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AppError::Unauthorized(_)));
}

#[test]
fn test_malformed_token_fails() {
    let secret = "test_jwt_secret_must_be_long_enough_12345";
    assert!(verify_token("not-a-token", secret).is_err());
    assert!(verify_token("", secret).is_err());
    assert!(verify_token("header.payload", secret).is_err());
}

#[tokio::test]
async fn test_auth_user_extractor_success() {
    let secret = "test_jwt_secret_must_be_long_enough_12345";
    let token = create_token("user-uuid-123", secret, 3600).unwrap();

    let app = Router::new()
        .route(
            "/protected",
            get(|auth: AuthUser| async move { auth.user_id }),
        )
        .with_state(secret.to_string());

    let req = Request::builder()
        .uri("/protected")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(body, "user-uuid-123");
}

#[tokio::test]
async fn test_auth_user_extractor_missing_header() {
    let secret = "test_jwt_secret_must_be_long_enough_12345";

    let app = Router::new()
        .route(
            "/protected",
            get(|auth: AuthUser| async move { auth.user_id }),
        )
        .with_state(secret.to_string());

    let req = Request::builder()
        .uri("/protected")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_auth_user_extractor_case_insensitive_scheme() {
    let secret = "test_jwt_secret_must_be_long_enough_12345";
    let token = create_token("user-uuid-123", secret, 3600).unwrap();

    let app = Router::new()
        .route(
            "/protected",
            get(|auth: AuthUser| async move { auth.user_id }),
        )
        .with_state(secret.to_string());

    for prefix in &["bearer", "BEARER", "Bearer", "BeArEr"] {
        let req = Request::builder()
            .uri("/protected")
            .header(header::AUTHORIZATION, format!("{prefix} {token}"))
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "Failed for prefix: {prefix}");
    }
}

#[tokio::test]
async fn test_auth_user_extractor_invalid_scheme() {
    let secret = "test_jwt_secret_must_be_long_enough_12345";

    let app = Router::new()
        .route(
            "/protected",
            get(|auth: AuthUser| async move { auth.user_id }),
        )
        .with_state(secret.to_string());

    let req = Request::builder()
        .uri("/protected")
        .header(header::AUTHORIZATION, "Basic dXNlcjpwYXNz")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_auth_user_extractor_expired_token() {
    let secret = "test_jwt_secret_must_be_long_enough_12345";
    let token = create_token("user-uuid-123", secret, -10).unwrap();

    let app = Router::new()
        .route(
            "/protected",
            get(|auth: AuthUser| async move { auth.user_id }),
        )
        .with_state(secret.to_string());

    let req = Request::builder()
        .uri("/protected")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_auth_user_extractor_with_app_state() {
    let config = Arc::new(Config {
        database_url: "sqlite::memory:".to_string(),
        server_secret: "test_server_secret_must_be_32_bytes_long_123".to_string(),
        jwt_secret: "test_jwt_secret_must_be_long_enough_12345".to_string(),
        port: 8080,
        host: "127.0.0.1".to_string(),
    });
    let repo = create_repository(&config.database_url).await.unwrap();
    let state = AppState::new(config.clone(), repo);

    let token = create_token("user-uuid-456", &config.jwt_secret, 3600).unwrap();

    let app = Router::new()
        .route(
            "/protected",
            get(|auth: AuthUser| async move { auth.user_id }),
        )
        .with_state(state);

    let req = Request::builder()
        .uri("/protected")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(body, "user-uuid-456");
}
