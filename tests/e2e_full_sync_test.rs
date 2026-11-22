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

#[tokio::test]
async fn test_health_endpoint() {
    let app = setup_test_app().await;

    let req = Request::builder()
        .uri("/api/health")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let json = parse_json_response(response).await;
    assert_eq!(json["status"], "healthy");
    assert_eq!(json["version"], env!("CARGO_PKG_VERSION"));
    assert!(json["timestamp"].as_i64().unwrap() > 0);
}

#[tokio::test]
async fn test_cors_exposed_headers() {
    let app = setup_test_app().await;

    let req = Request::builder()
        .uri("/api/health")
        .method("GET")
        .header(header::ORIGIN, "http://example.com")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let expose = response
        .headers()
        .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
        .expect("access-control-expose-headers header should be present")
        .to_str()
        .unwrap()
        .to_ascii_lowercase();

    assert!(expose.contains("etag"));
    assert!(expose.contains("if-match"));
    assert!(expose.contains("if-none-match"));
}

#[tokio::test]
async fn test_e2e_full_client_lifecycle() {
    let app = setup_test_app().await;

    // =========================================================================
    // Step 1: Health check
    // =========================================================================
    let req = Request::builder()
        .uri("/api/health")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let health_json = parse_json_response(resp).await;
    assert_eq!(health_json["status"], "healthy");
    assert_eq!(health_json["version"], env!("CARGO_PKG_VERSION"));
    assert!(health_json["timestamp"].as_i64().unwrap() > 0);

    // =========================================================================
    // Step 2: Pre-login params for non-existent email -> fake salt returned
    // =========================================================================
    let user_email = "alice@example.com";
    let req = Request::builder()
        .uri(format!("/api/auth/params?email={user_email}"))
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let params_json = parse_json_response(resp).await;
    let fake_salt = params_json["kdf_salt"].as_str().unwrap().to_string();
    assert!(!fake_salt.is_empty());
    assert_eq!(params_json["kdf_memory_kb"], 65536);
    assert_eq!(params_json["kdf_iterations"], 3);
    assert_eq!(params_json["kdf_parallelism"], 1);

    // Verify deterministic fake salt for the same non-existent email
    let req_repeat = Request::builder()
        .uri(format!("/api/auth/params?email={user_email}"))
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let resp_repeat = app.clone().oneshot(req_repeat).await.unwrap();
    let params_repeat_json = parse_json_response(resp_repeat).await;
    assert_eq!(params_repeat_json["kdf_salt"], fake_salt);

    // Verify distinct fake salt for a different email
    let req_diff = Request::builder()
        .uri("/api/auth/params?email=bob@example.com")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let resp_diff = app.clone().oneshot(req_diff).await.unwrap();
    let params_diff_json = parse_json_response(resp_diff).await;
    assert_ne!(params_diff_json["kdf_salt"], fake_salt);

    // =========================================================================
    // Step 3: Registration with wrapped vault key
    // =========================================================================
    let initial_auth_key = "initial_client_auth_key_alice_123";
    let wrapped_vault_key_v1 = "v1.iv_random_base64_blob.cipher_encrypted_vault_key_aes256gcm";

    let register_payload = json!({
        "email": user_email,
        "client_auth_key": initial_auth_key,
        "kdf_salt": fake_salt,
        "kdf_memory_kb": 65536,
        "kdf_iterations": 3,
        "kdf_parallelism": 1,
        "wrapped_vault_key": wrapped_vault_key_v1,
    });

    let req = Request::builder()
        .uri("/api/auth/register")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&register_payload).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let reg_json = parse_json_response(resp).await;
    let initial_user_id = reg_json["user_id"].as_str().unwrap().to_string();
    assert_eq!(reg_json["email"], user_email);
    assert!(!reg_json["token"].as_str().unwrap().is_empty());

    // Verify /api/auth/params now returns the registered salt
    let req = Request::builder()
        .uri(format!("/api/auth/params?email={user_email}"))
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let params_registered_json = parse_json_response(resp).await;
    assert_eq!(params_registered_json["kdf_salt"], fake_salt);

    // =========================================================================
    // Step 4: Login -> receive JWT & wrapped vault key
    // =========================================================================
    // 4a: Failed login with invalid client auth key
    let bad_login_payload = json!({
        "email": user_email,
        "client_auth_key": "wrong_auth_key",
    });
    let req = Request::builder()
        .uri("/api/auth/login")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&bad_login_payload).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 4b: Successful login
    let login_payload = json!({
        "email": user_email,
        "client_auth_key": initial_auth_key,
    });
    let req = Request::builder()
        .uri("/api/auth/login")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&login_payload).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let login_json = parse_json_response(resp).await;
    let auth_token = login_json["token"].as_str().unwrap().to_string();
    assert_eq!(login_json["user_id"], initial_user_id);
    assert_eq!(login_json["wrapped_vault_key"], wrapped_vault_key_v1);
    assert_eq!(login_json["kdf_salt"], fake_salt);

    // =========================================================================
    // Step 5: Consolidated vault sync upload -> version 1
    // =========================================================================
    let vault_blob_v1 = b"FUTON_ENCRYPTED_VAULT_SNAPSHOT_COMPRESSED_V1".to_vec();

    // Check meta before upload (does not exist yet)
    let req = Request::builder()
        .uri("/api/vault/sync/meta")
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {auth_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let meta_json = parse_json_response(resp).await;
    assert_eq!(meta_json["exists"], false);

    // Upload vault snapshot v1
    let req = Request::builder()
        .uri("/api/vault/sync")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {auth_token}"))
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(vault_blob_v1.clone()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let vault_resp = parse_json_response(resp).await;
    assert_eq!(vault_resp["version"], 1);
    assert_eq!(vault_resp["size_bytes"], vault_blob_v1.len() as i64);
    assert!(vault_resp["updated_at"].as_i64().unwrap() > 0);

    // =========================================================================
    // Step 6: Consolidated vault sync download with ETag and 304 If-None-Match
    // =========================================================================
    // 6a: Fresh download
    let req = Request::builder()
        .uri("/api/vault/sync")
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {auth_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let etag_header = resp
        .headers()
        .get(header::ETAG)
        .expect("ETag header must be present")
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(etag_header, "\"1\"");
    let downloaded_blob = parse_bytes_response(resp).await;
    assert_eq!(downloaded_blob, vault_blob_v1);

    // 6b: Download with matching If-None-Match -> 304 Not Modified
    let req = Request::builder()
        .uri("/api/vault/sync")
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {auth_token}"))
        .header(header::IF_NONE_MATCH, &etag_header)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
    let not_modified_body = parse_bytes_response(resp).await;
    assert!(not_modified_body.is_empty());

    // =========================================================================
    // Step 7: Granular items batch upload (10 encrypted records)
    // =========================================================================
    let mut items_to_upload = Vec::new();
    for i in 1..=10 {
        items_to_upload.push(json!({
            "id": format!("item-record-{:03}", i),
            "encrypted_payload": format!("enc_ciphertext_for_item_{:03}_payload_xyz", i),
            "deleted_at": Value::Null,
        }));
    }

    let req = Request::builder()
        .uri("/api/items")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {auth_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&json!({ "items": items_to_upload })).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let items_resp = parse_json_response(resp).await;
    let synced_array = items_resp["synced"].as_array().unwrap();
    assert_eq!(synced_array.len(), 10);
    let first_batch_server_timestamp = items_resp["server_timestamp"].as_i64().unwrap();
    assert!(first_batch_server_timestamp > 0);

    for (idx, item_sync) in synced_array.iter().enumerate() {
        let expected_id = format!("item-record-{:03}", idx + 1);
        assert_eq!(item_sync["id"], expected_id);
        assert_eq!(item_sync["version"], 1);
        assert!(item_sync["updated_at"].as_i64().unwrap() > 0);
    }

    // =========================================================================
    // Step 8: Granular items delta retrieval with ?since=...
    // =========================================================================
    // 8a: Verify full fetch returns all 10 items
    let req = Request::builder()
        .uri("/api/items")
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {auth_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let get_items_json = parse_json_response(resp).await;
    let all_items = get_items_json["items"].as_array().unwrap();
    assert_eq!(all_items.len(), 10);

    // Small delay ensures clock ticks forward for subsequent modifications
    tokio::time::sleep(std::time::Duration::from_millis(15)).await;

    // 8b: Update 3 items: update item-002 and item-005, soft-delete item-008
    let update_items = vec![
        json!({
            "id": "item-record-002",
            "encrypted_payload": "updated_enc_ciphertext_for_item_002",
            "deleted_at": Value::Null,
        }),
        json!({
            "id": "item-record-005",
            "encrypted_payload": "updated_enc_ciphertext_for_item_005",
            "deleted_at": Value::Null,
        }),
        json!({
            "id": "item-record-008",
            "encrypted_payload": "enc_ciphertext_for_item_008_payload_xyz",
            "deleted_at": 1700000050000_i64,
        }),
    ];

    let req = Request::builder()
        .uri("/api/items")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {auth_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&json!({ "items": update_items })).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 8c: Delta sync with ?since={first_batch_server_timestamp}
    let req = Request::builder()
        .uri(format!("/api/items?since={first_batch_server_timestamp}"))
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {auth_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let delta_json = parse_json_response(resp).await;
    let delta_items = delta_json["items"].as_array().unwrap();
    assert_eq!(delta_items.len(), 3);

    let delta_ids: Vec<&str> = delta_items
        .iter()
        .map(|it| it["id"].as_str().unwrap())
        .collect();
    assert!(delta_ids.contains(&"item-record-002"));
    assert!(delta_ids.contains(&"item-record-005"));
    assert!(delta_ids.contains(&"item-record-008"));

    // Verify soft-deleted item retains deleted_at
    let item_8 = delta_items.iter().find(|it| it["id"] == "item-record-008").unwrap();
    assert_eq!(item_8["deleted_at"], 1700000050000_i64);

    // =========================================================================
    // Step 9: Atomic password rotation
    // =========================================================================
    let rotated_auth_key = "rotated_client_auth_key_alice_456";
    let rotated_salt = "bmV3X3NhbHRfZm9yX3JvdGF0aW9uXzE2Ynl0ZXM=";
    let wrapped_vault_key_v2 = "v2.iv_reencrypted.new_wrapped_vault_key_aes256gcm";

    let rotate_payload = json!({
        "old_client_auth_key": initial_auth_key,
        "new_client_auth_key": rotated_auth_key,
        "new_kdf_salt": rotated_salt,
        "new_kdf_memory_kb": 65536,
        "new_kdf_iterations": 3,
        "new_kdf_parallelism": 1,
        "new_wrapped_vault_key": wrapped_vault_key_v2,
    });

    let req = Request::builder()
        .uri("/api/auth/rotate-password")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {auth_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&rotate_payload).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let rotate_json = parse_json_response(resp).await;
    assert_eq!(rotate_json["status"], "password_rotated");

    // Old credentials must fail immediately
    let old_login_payload = json!({
        "email": user_email,
        "client_auth_key": initial_auth_key,
    });
    let req = Request::builder()
        .uri("/api/auth/login")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&old_login_payload).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // =========================================================================
    // Step 10: Login with new credentials and verify all vault data & items intact
    // =========================================================================
    // 10a: Login with rotated credentials
    let new_login_payload = json!({
        "email": user_email,
        "client_auth_key": rotated_auth_key,
    });
    let req = Request::builder()
        .uri("/api/auth/login")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&new_login_payload).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let new_login_json = parse_json_response(resp).await;
    let new_token = new_login_json["token"].as_str().unwrap().to_string();
    assert_eq!(new_login_json["user_id"], initial_user_id);
    assert_eq!(new_login_json["wrapped_vault_key"], wrapped_vault_key_v2);
    assert_eq!(new_login_json["kdf_salt"], rotated_salt);

    // 10b: Verify vault archive download with new token
    let req = Request::builder()
        .uri("/api/vault/sync")
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {new_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get(header::ETAG).unwrap().to_str().unwrap(),
        "\"1\""
    );
    let downloaded_vault_after_rotation = parse_bytes_response(resp).await;
    assert_eq!(downloaded_vault_after_rotation, vault_blob_v1);

    // 10c: Verify all 10 items intact with new token
    let req = Request::builder()
        .uri("/api/items")
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {new_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let items_after_rotation_json = parse_json_response(resp).await;
    let items_after_rotation = items_after_rotation_json["items"].as_array().unwrap();
    assert_eq!(items_after_rotation.len(), 10);

    // 10d: Upload version 2 vault snapshot with If-Match concurrency control
    let vault_blob_v2 = b"FUTON_ENCRYPTED_VAULT_SNAPSHOT_COMPRESSED_V2".to_vec();
    let req = Request::builder()
        .uri("/api/vault/sync")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {new_token}"))
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::IF_MATCH, "\"1\"")
        .body(Body::from(vault_blob_v2.clone()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v2_resp = parse_json_response(resp).await;
    assert_eq!(v2_resp["version"], 2);

    // 10e: Download v2 vault snapshot and verify ETag "2"
    let req = Request::builder()
        .uri("/api/vault/sync")
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {new_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get(header::ETAG).unwrap().to_str().unwrap(),
        "\"2\""
    );
    let v2_body = parse_bytes_response(resp).await;
    assert_eq!(v2_body, vault_blob_v2);
}
