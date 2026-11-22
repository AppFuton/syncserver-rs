use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    Router,
};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
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
async fn test_items_sync_and_delta_retrieval() {
    let app = setup_test_app().await;
    let token = register_user(&app, "user_items@example.com").await;

    // Initial GET /api/items -> empty list with server_timestamp
    let req_initial = Request::builder()
        .uri("/api/items")
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let res_initial = app.clone().oneshot(req_initial).await.unwrap();
    assert_eq!(res_initial.status(), StatusCode::OK);
    let initial_json = parse_json_response(res_initial).await;
    assert_eq!(initial_json["items"].as_array().unwrap().len(), 0);
    assert!(initial_json["server_timestamp"].as_i64().unwrap() > 0);

    // 1. POST two items -> 200 OK
    let post_payload = json!({
        "items": [
            {
                "id": "item_1",
                "encrypted_payload": "payload_content_1",
                "deleted_at": null
            },
            {
                "id": "item_2",
                "encrypted_payload": "payload_content_2",
                "deleted_at": null
            }
        ]
    });

    let req_post = Request::builder()
        .uri("/api/items")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&post_payload).unwrap()))
        .unwrap();
    let res_post = app.clone().oneshot(req_post).await.unwrap();
    assert_eq!(res_post.status(), StatusCode::OK);
    let post_json = parse_json_response(res_post).await;
    let synced = post_json["synced"].as_array().unwrap();
    assert_eq!(synced.len(), 2);
    assert_eq!(synced[0]["id"], "item_1");
    assert_eq!(synced[0]["version"], 1);
    assert_eq!(synced[1]["id"], "item_2");
    assert_eq!(synced[1]["version"], 1);
    let t1 = post_json["server_timestamp"].as_i64().unwrap();
    assert!(t1 > 0);

    // 2. GET /api/items?since=0 -> returns both items
    let req_get_all = Request::builder()
        .uri("/api/items?since=0")
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let res_get_all = app.clone().oneshot(req_get_all).await.unwrap();
    assert_eq!(res_get_all.status(), StatusCode::OK);
    let get_all_json = parse_json_response(res_get_all).await;
    let items_all = get_all_json["items"].as_array().unwrap();
    assert_eq!(items_all.len(), 2);
    assert_eq!(items_all[0]["id"], "item_1");
    assert_eq!(items_all[0]["encrypted_payload"], "payload_content_1");
    assert_eq!(items_all[0]["version"], 1);
    assert!(items_all[0]["deleted_at"].is_null());
    assert_eq!(items_all[1]["id"], "item_2");
    assert_eq!(items_all[1]["encrypted_payload"], "payload_content_2");
    assert_eq!(items_all[1]["version"], 1);
    assert!(items_all[1]["deleted_at"].is_null());

    // Sleep 15ms so server timestamp is strictly greater than t1
    tokio::time::sleep(Duration::from_millis(15)).await;

    // 3. POST tombstone (deleted_at: now) for one item
    let now_tombstone = chrono::Utc::now().timestamp_millis();
    let tombstone_payload = json!({
        "items": [
            {
                "id": "item_1",
                "encrypted_payload": "tombstone_payload_1",
                "deleted_at": now_tombstone
            }
        ]
    });

    let req_tombstone = Request::builder()
        .uri("/api/items")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&tombstone_payload).unwrap()))
        .unwrap();
    let res_tombstone = app.clone().oneshot(req_tombstone).await.unwrap();
    assert_eq!(res_tombstone.status(), StatusCode::OK);
    let tombstone_json = parse_json_response(res_tombstone).await;
    let synced_tombstone = tombstone_json["synced"].as_array().unwrap();
    assert_eq!(synced_tombstone.len(), 1);
    assert_eq!(synced_tombstone[0]["id"], "item_1");
    assert_eq!(synced_tombstone[0]["version"], 2);
    let t2 = tombstone_json["server_timestamp"].as_i64().unwrap();
    assert!(t2 > t1);

    // 4. GET /api/items?since=T1 -> returns only the tombstoned item
    let req_delta = Request::builder()
        .uri(format!("/api/items?since={t1}"))
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let res_delta = app.clone().oneshot(req_delta).await.unwrap();
    assert_eq!(res_delta.status(), StatusCode::OK);
    let delta_json = parse_json_response(res_delta).await;
    let delta_items = delta_json["items"].as_array().unwrap();
    assert_eq!(delta_items.len(), 1);
    assert_eq!(delta_items[0]["id"], "item_1");
    assert_eq!(delta_items[0]["version"], 2);
    assert_eq!(delta_items[0]["encrypted_payload"], "tombstone_payload_1");
    assert_eq!(delta_items[0]["deleted_at"], now_tombstone);
}

#[tokio::test]
async fn test_items_sync_unauthorized() {
    let app = setup_test_app().await;

    // GET without auth header -> 401
    let req_get = Request::builder()
        .uri("/api/items")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res_get = app.clone().oneshot(req_get).await.unwrap();
    assert_eq!(res_get.status(), StatusCode::UNAUTHORIZED);

    // POST without auth header -> 401
    let req_post = Request::builder()
        .uri("/api/items")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json!({"items": []}).to_string()))
        .unwrap();
    let res_post = app.clone().oneshot(req_post).await.unwrap();
    assert_eq!(res_post.status(), StatusCode::UNAUTHORIZED);

    // GET with invalid Bearer token -> 401
    let req_invalid = Request::builder()
        .uri("/api/items")
        .method("GET")
        .header(header::AUTHORIZATION, "Bearer invalid_token_value")
        .body(Body::empty())
        .unwrap();
    let res_invalid = app.oneshot(req_invalid).await.unwrap();
    assert_eq!(res_invalid.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_items_user_isolation() {
    let app = setup_test_app().await;
    let token_a = register_user(&app, "user_a_items@example.com").await;
    let token_b = register_user(&app, "user_b_items@example.com").await;

    // User A posts item_1
    let req_post_a = Request::builder()
        .uri("/api/items")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {token_a}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "items": [
                    { "id": "shared_id", "encrypted_payload": "user_a_secret", "deleted_at": null }
                ]
            })
            .to_string(),
        ))
        .unwrap();
    let res_post_a = app.clone().oneshot(req_post_a).await.unwrap();
    assert_eq!(res_post_a.status(), StatusCode::OK);

    // User B gets items -> empty
    let req_get_b = Request::builder()
        .uri("/api/items")
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {token_b}"))
        .body(Body::empty())
        .unwrap();
    let res_get_b = app.clone().oneshot(req_get_b).await.unwrap();
    assert_eq!(res_get_b.status(), StatusCode::OK);
    let b_json = parse_json_response(res_get_b).await;
    assert_eq!(b_json["items"].as_array().unwrap().len(), 0);

    // User B posts item with same ID "shared_id"
    let req_post_b = Request::builder()
        .uri("/api/items")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {token_b}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "items": [
                    { "id": "shared_id", "encrypted_payload": "user_b_secret", "deleted_at": null }
                ]
            })
            .to_string(),
        ))
        .unwrap();
    let res_post_b = app.clone().oneshot(req_post_b).await.unwrap();
    assert_eq!(res_post_b.status(), StatusCode::OK);

    // User A retrieves items -> still user_a_secret
    let req_get_a = Request::builder()
        .uri("/api/items")
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {token_a}"))
        .body(Body::empty())
        .unwrap();
    let res_get_a = app.clone().oneshot(req_get_a).await.unwrap();
    assert_eq!(res_get_a.status(), StatusCode::OK);
    let a_json = parse_json_response(res_get_a).await;
    let a_items = a_json["items"].as_array().unwrap();
    assert_eq!(a_items.len(), 1);
    assert_eq!(a_items[0]["id"], "shared_id");
    assert_eq!(a_items[0]["encrypted_payload"], "user_a_secret");

    // User B retrieves items -> user_b_secret
    let req_get_b2 = Request::builder()
        .uri("/api/items")
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {token_b}"))
        .body(Body::empty())
        .unwrap();
    let res_get_b2 = app.oneshot(req_get_b2).await.unwrap();
    assert_eq!(res_get_b2.status(), StatusCode::OK);
    let b2_json = parse_json_response(res_get_b2).await;
    let b_items = b2_json["items"].as_array().unwrap();
    assert_eq!(b_items.len(), 1);
    assert_eq!(b_items[0]["id"], "shared_id");
    assert_eq!(b_items[0]["encrypted_payload"], "user_b_secret");
}

#[tokio::test]
async fn test_items_body_limit_enforced() {
    let app = setup_test_app().await;
    let token = register_user(&app, "user_limit_items@example.com").await;

    // Create a payload larger than 2 MB (e.g. 2 * 1024 * 1024 + 100 bytes)
    let large_string = "x".repeat(2 * 1024 * 1024 + 100);
    let payload = json!({
        "items": [
            {
                "id": "huge_item",
                "encrypted_payload": large_string,
                "deleted_at": null
            }
        ]
    });

    let req_oversized = Request::builder()
        .uri("/api/items")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();
    let res_oversized = app.oneshot(req_oversized).await.unwrap();
    assert_eq!(res_oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn test_items_empty_id_rejected() {
    let app = setup_test_app().await;
    let token = register_user(&app, "user_empty_id@example.com").await;

    let payload = json!({
        "items": [
            {
                "id": "   ",
                "encrypted_payload": "some_data",
                "deleted_at": null
            }
        ]
    });

    let req = Request::builder()
        .uri("/api/items")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_items_empty_batch_and_omitted_deleted_at() {
    let app = setup_test_app().await;
    let token = register_user(&app, "user_batch@example.com").await;

    // 1. Post empty items array
    let req_empty = Request::builder()
        .uri("/api/items")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json!({"items": []}).to_string()))
        .unwrap();
    let res_empty = app.clone().oneshot(req_empty).await.unwrap();
    assert_eq!(res_empty.status(), StatusCode::OK);
    let empty_json = parse_json_response(res_empty).await;
    assert_eq!(empty_json["synced"].as_array().unwrap().len(), 0);
    assert!(empty_json["server_timestamp"].as_i64().unwrap() > 0);

    // 2. Post item where deleted_at field is completely omitted (serde default)
    let req_omitted = Request::builder()
        .uri("/api/items")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "items": [
                    {
                        "id": "item_no_del",
                        "encrypted_payload": "data_no_del"
                    }
                ]
            })
            .to_string(),
        ))
        .unwrap();
    let res_omitted = app.clone().oneshot(req_omitted).await.unwrap();
    assert_eq!(res_omitted.status(), StatusCode::OK);
    let omitted_json = parse_json_response(res_omitted).await;
    assert_eq!(omitted_json["synced"].as_array().unwrap().len(), 1);

    // Verify GET returns it with null deleted_at
    let req_get = Request::builder()
        .uri("/api/items")
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let res_get = app.oneshot(req_get).await.unwrap();
    assert_eq!(res_get.status(), StatusCode::OK);
    let get_json = parse_json_response(res_get).await;
    let items = get_json["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], "item_no_del");
    assert!(items[0]["deleted_at"].is_null());
}
