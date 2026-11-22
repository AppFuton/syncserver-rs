use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    Router,
};
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

async fn parse_bytes_response(response: axum::response::Response) -> Vec<u8> {
    axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec()
}

async fn register_user(app: &Router, email: &str) -> String {
    let register_payload = json!({
        "email": email,
        "client_auth_key": "auth_key_test_123",
        "kdf_salt": "c2FsdF90ZXN0XzE2Ynl0ZXM=",
        "kdf_memory_kb": 65536,
        "kdf_iterations": 3,
        "kdf_parallelism": 1,
        "wrapped_vault_key": "v1.iv123.cipher123"
    });

    let req = Request::builder()
        .uri("/api/auth/register")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&register_payload).unwrap()))
        .unwrap();

    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let json = parse_json_response(response).await;
    json["token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn test_vault_snapshot_etag_and_concurrency() {
    let app = setup_test_app().await;
    let token = register_user(&app, "user1@example.com").await;

    // 1. Initial GET -> 404 Not Found
    let req_initial_get = Request::builder()
        .uri("/api/vault/sync")
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let res_initial_get = app.clone().oneshot(req_initial_get).await.unwrap();
    assert_eq!(res_initial_get.status(), StatusCode::NOT_FOUND);

    // Initial GET /api/vault/sync/meta -> 200 OK with exists: false
    let req_initial_meta = Request::builder()
        .uri("/api/vault/sync/meta")
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let res_initial_meta = app.clone().oneshot(req_initial_meta).await.unwrap();
    assert_eq!(res_initial_meta.status(), StatusCode::OK);
    let meta_json = parse_json_response(res_initial_meta).await;
    assert_eq!(meta_json["exists"], false);
    assert!(meta_json["version"].is_null());
    assert!(meta_json["updated_at"].is_null());
    assert_eq!(meta_json["size_bytes"], 0);

    // 2. POST binary blob -> 200 OK, version 1
    let blob_v1 = b"encrypted_vault_snapshot_bytes_v1".to_vec();
    let req_post_v1 = Request::builder()
        .uri("/api/vault/sync")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(blob_v1.clone()))
        .unwrap();
    let res_post_v1 = app.clone().oneshot(req_post_v1).await.unwrap();
    assert_eq!(res_post_v1.status(), StatusCode::OK);
    let post_v1_json = parse_json_response(res_post_v1).await;
    assert_eq!(post_v1_json["version"], 1);
    assert_eq!(post_v1_json["size_bytes"], blob_v1.len() as i64);
    assert!(post_v1_json["updated_at"].as_i64().unwrap() > 0);

    // GET /api/vault/sync/meta -> exists: true, version 1
    let req_meta_v1 = Request::builder()
        .uri("/api/vault/sync/meta")
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let res_meta_v1 = app.clone().oneshot(req_meta_v1).await.unwrap();
    assert_eq!(res_meta_v1.status(), StatusCode::OK);
    let meta_v1_json = parse_json_response(res_meta_v1).await;
    assert_eq!(meta_v1_json["exists"], true);
    assert_eq!(meta_v1_json["version"], 1);
    assert_eq!(meta_v1_json["size_bytes"], blob_v1.len() as i64);

    // Full GET /api/vault/sync -> 200 OK with ETag: "1" and binary body
    let req_get_v1 = Request::builder()
        .uri("/api/vault/sync")
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let res_get_v1 = app.clone().oneshot(req_get_v1).await.unwrap();
    assert_eq!(res_get_v1.status(), StatusCode::OK);
    assert_eq!(
        res_get_v1.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/octet-stream"
    );
    assert_eq!(
        res_get_v1.headers().get(header::ETAG).unwrap(),
        "\"1\""
    );
    let body_v1 = parse_bytes_response(res_get_v1).await;
    assert_eq!(body_v1, blob_v1);

    // 3. GET with If-None-Match: "1" -> 304 Not Modified
    let req_get_none_match = Request::builder()
        .uri("/api/vault/sync")
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::IF_NONE_MATCH, "\"1\"")
        .body(Body::empty())
        .unwrap();
    let res_get_none_match = app.clone().oneshot(req_get_none_match).await.unwrap();
    assert_eq!(res_get_none_match.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(
        res_get_none_match.headers().get(header::ETAG).unwrap(),
        "\"1\""
    );
    let empty_body = parse_bytes_response(res_get_none_match).await;
    assert!(empty_body.is_empty());

    // GET with unquoted If-None-Match: 1 -> 304 Not Modified
    let req_get_none_match_unquoted = Request::builder()
        .uri("/api/vault/sync")
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::IF_NONE_MATCH, "1")
        .body(Body::empty())
        .unwrap();
    let res_get_none_match_unquoted = app.clone().oneshot(req_get_none_match_unquoted).await.unwrap();
    assert_eq!(res_get_none_match_unquoted.status(), StatusCode::NOT_MODIFIED);

    // GET with If-None-Match: "99" (mismatch) -> 200 OK with full body
    let req_get_none_match_mismatch = Request::builder()
        .uri("/api/vault/sync")
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::IF_NONE_MATCH, "\"99\"")
        .body(Body::empty())
        .unwrap();
    let res_get_none_match_mismatch = app.clone().oneshot(req_get_none_match_mismatch).await.unwrap();
    assert_eq!(res_get_none_match_mismatch.status(), StatusCode::OK);
    let mismatch_body = parse_bytes_response(res_get_none_match_mismatch).await;
    assert_eq!(mismatch_body, blob_v1);

    // 4. POST with If-Match: "1" -> 200 OK, version 2
    let blob_v2 = b"encrypted_vault_snapshot_bytes_v2_updated".to_vec();
    let req_post_v2 = Request::builder()
        .uri("/api/vault/sync")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::IF_MATCH, "\"1\"")
        .body(Body::from(blob_v2.clone()))
        .unwrap();
    let res_post_v2 = app.clone().oneshot(req_post_v2).await.unwrap();
    assert_eq!(res_post_v2.status(), StatusCode::OK);
    let post_v2_json = parse_json_response(res_post_v2).await;
    assert_eq!(post_v2_json["version"], 2);
    assert_eq!(post_v2_json["size_bytes"], blob_v2.len() as i64);

    // 5. POST with stale If-Match: "1" -> 412 Precondition Failed
    let blob_conflict = b"encrypted_vault_snapshot_conflict".to_vec();
    let req_post_conflict = Request::builder()
        .uri("/api/vault/sync")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::IF_MATCH, "\"1\"")
        .body(Body::from(blob_conflict.clone()))
        .unwrap();
    let res_post_conflict = app.clone().oneshot(req_post_conflict).await.unwrap();
    assert_eq!(res_post_conflict.status(), StatusCode::PRECONDITION_FAILED);

    // POST with stale unquoted If-Match: 1 -> 412 Precondition Failed
    let req_post_conflict_unquoted = Request::builder()
        .uri("/api/vault/sync")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::IF_MATCH, "1")
        .body(Body::from(blob_conflict))
        .unwrap();
    let res_post_conflict_unquoted = app.clone().oneshot(req_post_conflict_unquoted).await.unwrap();
    assert_eq!(res_post_conflict_unquoted.status(), StatusCode::PRECONDITION_FAILED);

    // POST with matching If-Match: "2" -> 200 OK, version 3
    let blob_v3 = b"encrypted_vault_snapshot_bytes_v3".to_vec();
    let req_post_v3 = Request::builder()
        .uri("/api/vault/sync")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::IF_MATCH, "\"2\"")
        .body(Body::from(blob_v3.clone()))
        .unwrap();
    let res_post_v3 = app.clone().oneshot(req_post_v3).await.unwrap();
    assert_eq!(res_post_v3.status(), StatusCode::OK);
    let post_v3_json = parse_json_response(res_post_v3).await;
    assert_eq!(post_v3_json["version"], 3);

    // Verify GET now returns version 3 with ETag: "3"
    let req_get_v3 = Request::builder()
        .uri("/api/vault/sync")
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let res_get_v3 = app.oneshot(req_get_v3).await.unwrap();
    assert_eq!(res_get_v3.status(), StatusCode::OK);
    assert_eq!(res_get_v3.headers().get(header::ETAG).unwrap(), "\"3\"");
    let body_v3 = parse_bytes_response(res_get_v3).await;
    assert_eq!(body_v3, blob_v3);
}

#[tokio::test]
async fn test_vault_sync_unauthorized() {
    let app = setup_test_app().await;

    // GET without auth header -> 401
    let req_get = Request::builder()
        .uri("/api/vault/sync")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_get = app.clone().oneshot(req_get).await.unwrap();
    assert_eq!(res_get.status(), StatusCode::UNAUTHORIZED);

    // POST without auth header -> 401
    let req_post = Request::builder()
        .uri("/api/vault/sync")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(b"test_blob".to_vec()))
        .unwrap();
    let res_post = app.clone().oneshot(req_post).await.unwrap();
    assert_eq!(res_post.status(), StatusCode::UNAUTHORIZED);

    // GET /meta without auth header -> 401
    let req_meta = Request::builder()
        .uri("/api/vault/sync/meta")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_meta = app.oneshot(req_meta).await.unwrap();
    assert_eq!(res_meta.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_vault_sync_user_isolation() {
    let app = setup_test_app().await;
    let token_a = register_user(&app, "user_a@example.com").await;
    let token_b = register_user(&app, "user_b@example.com").await;

    // User A uploads snapshot
    let blob_a = b"user_a_secret_vault_snapshot".to_vec();
    let req_post_a = Request::builder()
        .uri("/api/vault/sync")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {token_a}"))
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(blob_a.clone()))
        .unwrap();
    let res_post_a = app.clone().oneshot(req_post_a).await.unwrap();
    assert_eq!(res_post_a.status(), StatusCode::OK);

    // User B checks meta -> exists: false
    let req_meta_b = Request::builder()
        .uri("/api/vault/sync/meta")
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {token_b}"))
        .body(Body::empty())
        .unwrap();
    let res_meta_b = app.clone().oneshot(req_meta_b).await.unwrap();
    assert_eq!(res_meta_b.status(), StatusCode::OK);
    let meta_b_json = parse_json_response(res_meta_b).await;
    assert_eq!(meta_b_json["exists"], false);

    // User B tries to GET snapshot -> 404
    let req_get_b = Request::builder()
        .uri("/api/vault/sync")
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {token_b}"))
        .body(Body::empty())
        .unwrap();
    let res_get_b = app.clone().oneshot(req_get_b).await.unwrap();
    assert_eq!(res_get_b.status(), StatusCode::NOT_FOUND);

    // User A gets snapshot -> 200 OK with blob A
    let req_get_a = Request::builder()
        .uri("/api/vault/sync")
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {token_a}"))
        .body(Body::empty())
        .unwrap();
    let res_get_a = app.clone().oneshot(req_get_a).await.unwrap();
    assert_eq!(res_get_a.status(), StatusCode::OK);
    let body_a = parse_bytes_response(res_get_a).await;
    assert_eq!(body_a, blob_a);

    // User B uploads snapshot -> version 1
    let blob_b = b"user_b_vault_data".to_vec();
    let req_post_b = Request::builder()
        .uri("/api/vault/sync")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {token_b}"))
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(blob_b.clone()))
        .unwrap();
    let res_post_b = app.clone().oneshot(req_post_b).await.unwrap();
    assert_eq!(res_post_b.status(), StatusCode::OK);
    let post_b_json = parse_json_response(res_post_b).await;
    assert_eq!(post_b_json["version"], 1);

    // User A snapshot is still intact and version 1
    let req_get_a_again = Request::builder()
        .uri("/api/vault/sync")
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {token_a}"))
        .body(Body::empty())
        .unwrap();
    let res_get_a_again = app.oneshot(req_get_a_again).await.unwrap();
    assert_eq!(res_get_a_again.status(), StatusCode::OK);
    assert_eq!(parse_bytes_response(res_get_a_again).await, blob_a);
}

#[tokio::test]
async fn test_vault_sync_body_limit_enforced() {
    let app = setup_test_app().await;
    let token = register_user(&app, "user_limit@example.com").await;

    // Payload exceeding 25 MB (25 MB + 1 byte)
    let oversized_blob = vec![0u8; 25 * 1024 * 1024 + 1];
    let req_oversized = Request::builder()
        .uri("/api/vault/sync")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(oversized_blob))
        .unwrap();
    let res_oversized = app.oneshot(req_oversized).await.unwrap();
    assert_eq!(res_oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
}
