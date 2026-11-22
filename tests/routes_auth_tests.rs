use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    Router,
};
use base64::prelude::*;
use serde_json::{json, Value};
use std::sync::Arc;
use syncserver_rs::{
    config::Config,
    db::create_repository,
    routes::create_router,
    AppState,
};
use tower::ServiceExt;

async fn setup_test_app() -> Router {
    let config = Config {
        host: "127.0.0.1".to_string(),
        port: 8080,
        database_url: "sqlite::memory:".to_string(),
        server_secret: "test_server_secret_for_hmac_sha256_fake_salt_32bytes".to_string(),
        jwt_secret: "test_jwt_secret_must_be_long_enough_12345".to_string(),
    };
    let repo = create_repository(&config.database_url).await.unwrap();
    let state = AppState::new(Arc::new(config), repo);
    create_router(state)
}

async fn parse_json_response(response: axum::response::Response) -> Value {
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&body_bytes).expect("response should be valid json")
}

#[tokio::test]
async fn test_auth_params_returns_fake_salt_for_non_existent_email() {
    let app = setup_test_app().await;

    // Call GET /api/auth/params?email=unknown@example.com
    let req = Request::builder()
        .uri("/api/auth/params?email=unknown@example.com")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let json = parse_json_response(response).await;
    let salt = json["kdf_salt"].as_str().expect("kdf_salt must be string");
    assert_eq!(json["kdf_memory_kb"], 65536);
    assert_eq!(json["kdf_iterations"], 3);
    assert_eq!(json["kdf_parallelism"], 1);

    // Verify deterministic 16-byte base64 salt
    let decoded = BASE64_STANDARD.decode(salt).expect("valid base64 salt");
    assert_eq!(decoded.len(), 16);

    // Call again with same email -> identical fake salt
    let req2 = Request::builder()
        .uri("/api/auth/params?email=unknown@example.com")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let response2 = app.clone().oneshot(req2).await.unwrap();
    let json2 = parse_json_response(response2).await;
    assert_eq!(json2["kdf_salt"], salt);

    // Call with differently-cased email with whitespace -> canonicalized, identical fake salt
    let req3 = Request::builder()
        .uri("/api/auth/params?email=%20UNKNOWN@EXAMPLE.COM%20")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let response3 = app.clone().oneshot(req3).await.unwrap();
    let json3 = parse_json_response(response3).await;
    assert_eq!(json3["kdf_salt"], salt);

    // Call with different email -> different fake salt
    let req4 = Request::builder()
        .uri("/api/auth/params?email=different@example.com")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let response4 = app.oneshot(req4).await.unwrap();
    let json4 = parse_json_response(response4).await;
    assert_ne!(json4["kdf_salt"], salt);
}

#[tokio::test]
async fn test_register_login_and_rotate_password_flow() {
    let app = setup_test_app().await;

    // 1. Register a user
    let register_payload = json!({
        "email": "user@example.com",
        "client_auth_key": "auth_key_initial_123",
        "kdf_salt": "c2FsdF9pbml0aWFsXzE2Yg==",
        "kdf_memory_kb": 65536,
        "kdf_iterations": 3,
        "kdf_parallelism": 1,
        "wrapped_vault_key": "v1.iv1234567890.cipher1234567890"
    });

    let req = Request::builder()
        .uri("/api/auth/register")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&register_payload).unwrap()))
        .unwrap();

    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let reg_json = parse_json_response(response).await;
    let token = reg_json["token"].as_str().expect("token must be string");
    let user_id = reg_json["user_id"].as_str().expect("user_id must be string");
    assert_eq!(reg_json["email"], "user@example.com");
    assert!(!token.is_empty());
    assert!(!user_id.is_empty());

    // 2. Registering same email again fails with 409 Conflict
    let req_conflict = Request::builder()
        .uri("/api/auth/register")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&register_payload).unwrap()))
        .unwrap();
    let res_conflict = app.clone().oneshot(req_conflict).await.unwrap();
    assert_eq!(res_conflict.status(), StatusCode::CONFLICT);

    // 3. /api/auth/params for registered user returns actual salt
    let req_params = Request::builder()
        .uri("/api/auth/params?email=USER@EXAMPLE.COM")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_params = app.clone().oneshot(req_params).await.unwrap();
    assert_eq!(res_params.status(), StatusCode::OK);
    let params_json = parse_json_response(res_params).await;
    assert_eq!(params_json["kdf_salt"], "c2FsdF9pbml0aWFsXzE2Yg==");

    // 4. Login with wrong password returns 401 Unauthorized
    let wrong_login_payload = json!({
        "email": "user@example.com",
        "client_auth_key": "wrong_password"
    });
    let req_wrong = Request::builder()
        .uri("/api/auth/login")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&wrong_login_payload).unwrap()))
        .unwrap();
    let res_wrong = app.clone().oneshot(req_wrong).await.unwrap();
    assert_eq!(res_wrong.status(), StatusCode::UNAUTHORIZED);

    // 5. Login with non-existent user returns 401 Unauthorized (timing defense path)
    let non_existent_login = json!({
        "email": "ghost@example.com",
        "client_auth_key": "some_auth_key"
    });
    let req_ghost = Request::builder()
        .uri("/api/auth/login")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&non_existent_login).unwrap()))
        .unwrap();
    let res_ghost = app.clone().oneshot(req_ghost).await.unwrap();
    assert_eq!(res_ghost.status(), StatusCode::UNAUTHORIZED);

    // 6. Login with correct password returns 200 OK + JWT + vault key info
    let login_payload = json!({
        "email": " USER@example.com ",
        "client_auth_key": "auth_key_initial_123"
    });
    let req_login = Request::builder()
        .uri("/api/auth/login")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&login_payload).unwrap()))
        .unwrap();
    let res_login = app.clone().oneshot(req_login).await.unwrap();
    assert_eq!(res_login.status(), StatusCode::OK);
    let login_json = parse_json_response(res_login).await;
    let login_token = login_json["token"].as_str().unwrap();
    assert_eq!(login_json["user_id"], user_id);
    assert_eq!(login_json["wrapped_vault_key"], "v1.iv1234567890.cipher1234567890");
    assert_eq!(login_json["kdf_salt"], "c2FsdF9pbml0aWFsXzE2Yg==");
    assert_eq!(login_json["kdf_memory_kb"], 65536);
    assert_eq!(login_json["kdf_iterations"], 3);
    assert_eq!(login_json["kdf_parallelism"], 1);

    // 7. GET /api/auth/me returns user profile
    let req_me = Request::builder()
        .uri("/api/auth/me")
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {login_token}"))
        .body(Body::empty())
        .unwrap();
    let res_me = app.clone().oneshot(req_me).await.unwrap();
    assert_eq!(res_me.status(), StatusCode::OK);
    let me_json = parse_json_response(res_me).await;
    assert_eq!(me_json["user_id"], user_id);
    assert_eq!(me_json["email"], "user@example.com");
    assert_eq!(me_json["wrapped_vault_key"], "v1.iv1234567890.cipher1234567890");
    assert_eq!(me_json["kdf_salt"], "c2FsdF9pbml0aWFsXzE2Yg==");

    // 8. GET /api/auth/me without token returns 401 Unauthorized
    let req_me_unauth = Request::builder()
        .uri("/api/auth/me")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_me_unauth = app.clone().oneshot(req_me_unauth).await.unwrap();
    assert_eq!(res_me_unauth.status(), StatusCode::UNAUTHORIZED);

    // 9. Rotate password with invalid old credentials fails (401)
    let bad_rotate_payload = json!({
        "old_client_auth_key": "wrong_old_key",
        "new_client_auth_key": "auth_key_new_456",
        "new_kdf_salt": "bmV3X3NhbHRfbmV3XzE2Yg==",
        "new_kdf_memory_kb": 65536,
        "new_kdf_iterations": 3,
        "new_kdf_parallelism": 1,
        "new_wrapped_vault_key": "v1.iv_new.cipher_new"
    });
    let req_bad_rotate = Request::builder()
        .uri("/api/auth/rotate-password")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {login_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&bad_rotate_payload).unwrap()))
        .unwrap();
    let res_bad_rotate = app.clone().oneshot(req_bad_rotate).await.unwrap();
    assert_eq!(res_bad_rotate.status(), StatusCode::UNAUTHORIZED);

    // 10. Rotate password with correct old credentials succeeds (200 OK)
    let rotate_payload = json!({
        "old_client_auth_key": "auth_key_initial_123",
        "new_client_auth_key": "auth_key_new_456",
        "new_kdf_salt": "bmV3X3NhbHRfbmV3XzE2Yg==",
        "new_kdf_memory_kb": 65536,
        "new_kdf_iterations": 3,
        "new_kdf_parallelism": 1,
        "new_wrapped_vault_key": "v1.iv_new.cipher_new"
    });
    let req_rotate = Request::builder()
        .uri("/api/auth/rotate-password")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {login_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&rotate_payload).unwrap()))
        .unwrap();
    let res_rotate = app.clone().oneshot(req_rotate).await.unwrap();
    assert_eq!(res_rotate.status(), StatusCode::OK);
    let rotate_json = parse_json_response(res_rotate).await;
    assert_eq!(rotate_json["status"], "password_rotated");

    // 11. Login with old password now fails with 401 Unauthorized
    let old_login_payload = json!({
        "email": "user@example.com",
        "client_auth_key": "auth_key_initial_123"
    });
    let req_old_login = Request::builder()
        .uri("/api/auth/login")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&old_login_payload).unwrap()))
        .unwrap();
    let res_old_login = app.clone().oneshot(req_old_login).await.unwrap();
    assert_eq!(res_old_login.status(), StatusCode::UNAUTHORIZED);

    // 12. Login with new password succeeds with 200 OK and returns new vault metadata
    let new_login_payload = json!({
        "email": "user@example.com",
        "client_auth_key": "auth_key_new_456"
    });
    let req_new_login = Request::builder()
        .uri("/api/auth/login")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&new_login_payload).unwrap()))
        .unwrap();
    let res_new_login = app.clone().oneshot(req_new_login).await.unwrap();
    assert_eq!(res_new_login.status(), StatusCode::OK);
    let new_login_json = parse_json_response(res_new_login).await;
    assert_eq!(new_login_json["wrapped_vault_key"], "v1.iv_new.cipher_new");
    assert_eq!(new_login_json["kdf_salt"], "bmV3X3NhbHRfbmV3XzE2Yg==");
}

#[tokio::test]
async fn test_auth_params_missing_or_empty_email() {
    let app = setup_test_app().await;

    // Missing email query param
    let req = Request::builder()
        .uri("/api/auth/params")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // Empty email query param
    let req2 = Request::builder()
        .uri("/api/auth/params?email=%20%20")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res2 = app.oneshot(req2).await.unwrap();
    assert_eq!(res2.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_register_invalid_payload() {
    let app = setup_test_app().await;

    // Empty email
    let payload = json!({
        "email": "",
        "client_auth_key": "some_key",
        "kdf_salt": "c2FsdA==",
        "wrapped_vault_key": "v1.iv.cipher"
    });
    let req = Request::builder()
        .uri("/api/auth/register")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // Empty auth key
    let payload2 = json!({
        "email": "test@example.com",
        "client_auth_key": "   ",
        "kdf_salt": "c2FsdA==",
        "wrapped_vault_key": "v1.iv.cipher"
    });
    let req2 = Request::builder()
        .uri("/api/auth/register")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&payload2).unwrap()))
        .unwrap();
    let res2 = app.clone().oneshot(req2).await.unwrap();
    assert_eq!(res2.status(), StatusCode::BAD_REQUEST);

    // KDF validation: memory < 1024
    let payload_low_mem = json!({
        "email": "test@example.com",
        "client_auth_key": "valid_key",
        "kdf_salt": "c2FsdA==",
        "wrapped_vault_key": "v1.iv.cipher",
        "kdf_memory_kb": 512
    });
    let req3 = Request::builder()
        .uri("/api/auth/register")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&payload_low_mem).unwrap()))
        .unwrap();
    let res3 = app.clone().oneshot(req3).await.unwrap();
    assert_eq!(res3.status(), StatusCode::BAD_REQUEST);
    let json3 = parse_json_response(res3).await;
    assert_eq!(json3["error"], "Invalid KDF parameters");

    // KDF validation: iterations < 1
    let payload_low_iter = json!({
        "email": "test@example.com",
        "client_auth_key": "valid_key",
        "kdf_salt": "c2FsdA==",
        "wrapped_vault_key": "v1.iv.cipher",
        "kdf_iterations": 0
    });
    let req4 = Request::builder()
        .uri("/api/auth/register")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&payload_low_iter).unwrap()))
        .unwrap();
    let res4 = app.clone().oneshot(req4).await.unwrap();
    assert_eq!(res4.status(), StatusCode::BAD_REQUEST);
    let json4 = parse_json_response(res4).await;
    assert_eq!(json4["error"], "Invalid KDF parameters");

    // KDF validation: parallelism < 1
    let payload_low_par = json!({
        "email": "test@example.com",
        "client_auth_key": "valid_key",
        "kdf_salt": "c2FsdA==",
        "wrapped_vault_key": "v1.iv.cipher",
        "kdf_parallelism": 0
    });
    let req5 = Request::builder()
        .uri("/api/auth/register")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&payload_low_par).unwrap()))
        .unwrap();
    let res5 = app.oneshot(req5).await.unwrap();
    assert_eq!(res5.status(), StatusCode::BAD_REQUEST);
    let json5 = parse_json_response(res5).await;
    assert_eq!(json5["error"], "Invalid KDF parameters");
}

#[tokio::test]
async fn test_rotate_password_requires_auth_and_valid_body() {
    let app = setup_test_app().await;

    // Without auth header -> 401
    let payload = json!({
        "old_client_auth_key": "key1",
        "new_client_auth_key": "key2",
        "new_kdf_salt": "salt2",
        "new_wrapped_vault_key": "v1.iv.cipher2"
    });
    let req = Request::builder()
        .uri("/api/auth/rotate-password")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // Register user first to get token
    let reg_payload = json!({
        "email": "rotator@example.com",
        "client_auth_key": "old_auth_key",
        "kdf_salt": "c2FsdF9vcmlnaW5hbF8xNg==",
        "wrapped_vault_key": "v1.iv.cipher"
    });
    let reg_req = Request::builder()
        .uri("/api/auth/register")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&reg_payload).unwrap()))
        .unwrap();
    let reg_res = app.clone().oneshot(reg_req).await.unwrap();
    let reg_json = parse_json_response(reg_res).await;
    let token = reg_json["token"].as_str().unwrap();

    // Invalid new_kdf_memory_kb < 1024
    let rotate_bad_mem = json!({
        "old_client_auth_key": "old_auth_key",
        "new_client_auth_key": "new_auth_key",
        "new_kdf_salt": "bmV3X3NhbHQ=",
        "new_kdf_memory_kb": 256,
        "new_wrapped_vault_key": "v1.iv.cipher"
    });
    let req_mem = Request::builder()
        .uri("/api/auth/rotate-password")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&rotate_bad_mem).unwrap()))
        .unwrap();
    let res_mem = app.clone().oneshot(req_mem).await.unwrap();
    assert_eq!(res_mem.status(), StatusCode::BAD_REQUEST);
    let json_mem = parse_json_response(res_mem).await;
    assert_eq!(json_mem["error"], "Invalid KDF parameters");

    // Invalid new_kdf_iterations < 1
    let rotate_bad_iter = json!({
        "old_client_auth_key": "old_auth_key",
        "new_client_auth_key": "new_auth_key",
        "new_kdf_salt": "bmV3X3NhbHQ=",
        "new_kdf_iterations": 0,
        "new_wrapped_vault_key": "v1.iv.cipher"
    });
    let req_iter = Request::builder()
        .uri("/api/auth/rotate-password")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&rotate_bad_iter).unwrap()))
        .unwrap();
    let res_iter = app.clone().oneshot(req_iter).await.unwrap();
    assert_eq!(res_iter.status(), StatusCode::BAD_REQUEST);
    let json_iter = parse_json_response(res_iter).await;
    assert_eq!(json_iter["error"], "Invalid KDF parameters");

    // Invalid new_kdf_parallelism < 1
    let rotate_bad_par = json!({
        "old_client_auth_key": "old_auth_key",
        "new_client_auth_key": "new_auth_key",
        "new_kdf_salt": "bmV3X3NhbHQ=",
        "new_kdf_parallelism": 0,
        "new_wrapped_vault_key": "v1.iv.cipher"
    });
    let req_par = Request::builder()
        .uri("/api/auth/rotate-password")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&rotate_bad_par).unwrap()))
        .unwrap();
    let res_par = app.oneshot(req_par).await.unwrap();
    assert_eq!(res_par.status(), StatusCode::BAD_REQUEST);
    let json_par = parse_json_response(res_par).await;
    assert_eq!(json_par["error"], "Invalid KDF parameters");
}

