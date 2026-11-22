use syncserver_rs::crypto::{hash_password, verify_password};
use syncserver_rs::db::{
    NewUser, PasswordRotation, Repository, SqliteRepository, VaultItemUpsert,
};
use syncserver_rs::error::AppError;

#[tokio::test]
async fn test_sqlite_user_lifecycle_and_rotation() {
    let repo = SqliteRepository::new_in_memory().await.unwrap();
    let auth_key = "client_auth_key_12345";
    let hash = hash_password(auth_key).unwrap();

    let new_user = NewUser {
        id: None,
        email: "  TestUser@Example.COM  ".to_string(),
        server_password_hash: hash,
        kdf_salt: "salt12345".to_string(),
        kdf_memory_kb: 65536,
        kdf_iterations: 3,
        kdf_parallelism: 1,
        wrapped_vault_key: "v1.iv.cipher".to_string(),
    };

    // 1. Create user and verify normalization
    let created = repo.create_user(&new_user).await.unwrap();
    assert_eq!(created.email, "testuser@example.com");
    assert!(!created.id.is_empty());
    assert_eq!(created.kdf_salt, "salt12345");
    assert_eq!(created.kdf_memory_kb, 65536);
    assert_eq!(created.kdf_iterations, 3);
    assert_eq!(created.kdf_parallelism, 1);
    assert_eq!(created.wrapped_vault_key, "v1.iv.cipher");
    assert!(created.created_at > 0);
    assert_eq!(created.created_at, created.updated_at);

    // 2. Query user by email (both lowercase and uppercase with whitespace)
    let fetched = repo
        .get_user_by_email("testuser@example.com")
        .await
        .unwrap()
        .expect("User should be found by exact email");
    assert_eq!(fetched.id, created.id);

    let fetched_mixed = repo
        .get_user_by_email("  TESTUSER@example.COM ")
        .await
        .unwrap()
        .expect("User should be found by un-normalized email");
    assert_eq!(fetched_mixed.id, created.id);

    // 3. Query non-existent email returns None
    assert!(repo
        .get_user_by_email("unknown@example.com")
        .await
        .unwrap()
        .is_none());

    // 4. Query user by ID
    let fetched_by_id = repo
        .get_user_by_id(&created.id)
        .await
        .unwrap()
        .expect("User should be found by ID");
    assert_eq!(fetched_by_id.email, "testuser@example.com");

    // 5. Duplicate email registration returns Conflict
    let dup_err = repo.create_user(&new_user).await;
    assert!(matches!(dup_err, Err(AppError::Conflict(_))));

    // 6. Rotate password with wrong old_auth_key returns Unauthorized
    let rotation = PasswordRotation {
        new_client_auth_key: "new_auth_key_67890".to_string(),
        new_kdf_salt: "new_salt_abc".to_string(),
        new_kdf_memory_kb: 65536,
        new_kdf_iterations: 3,
        new_kdf_parallelism: 1,
        new_wrapped_vault_key: "v1.new_iv.new_cipher".to_string(),
    };
    let unauth_err = repo
        .rotate_password(&created.id, "wrong_old_key", &rotation)
        .await;
    assert!(matches!(unauth_err, Err(AppError::Unauthorized(_))));

    // Verify password hash and metadata were NOT changed
    let not_rotated = repo.get_user_by_id(&created.id).await.unwrap().unwrap();
    assert_eq!(not_rotated.kdf_salt, "salt12345");
    assert!(verify_password(auth_key, &not_rotated.server_password_hash).unwrap());

    // 7. Rotate password with valid credentials succeeds
    repo.rotate_password(&created.id, auth_key, &rotation)
        .await
        .unwrap();

    let rotated = repo.get_user_by_id(&created.id).await.unwrap().unwrap();
    assert_eq!(rotated.kdf_salt, "new_salt_abc");
    assert_eq!(rotated.wrapped_vault_key, "v1.new_iv.new_cipher");
    assert!(verify_password("new_auth_key_67890", &rotated.server_password_hash).unwrap());
    assert!(!verify_password(auth_key, &rotated.server_password_hash).unwrap());
    assert!(rotated.updated_at >= not_rotated.updated_at);
}

#[tokio::test]
async fn test_sqlite_snapshot_concurrency() {
    let repo = SqliteRepository::new_in_memory().await.unwrap();

    let auth_key = "auth_key_snapshot";
    let hash = hash_password(auth_key).unwrap();
    let user = repo
        .create_user(&NewUser {
            id: Some("user-uuid-snap".to_string()),
            email: "snapshot@example.com".to_string(),
            server_password_hash: hash,
            kdf_salt: "salt".to_string(),
            kdf_memory_kb: 65536,
            kdf_iterations: 3,
            kdf_parallelism: 1,
            wrapped_vault_key: "wrapped".to_string(),
        })
        .await
        .unwrap();

    // 1. Initial snapshot does not exist
    let initial = repo.get_vault_snapshot(&user.id).await.unwrap();
    assert!(initial.is_none());

    // 2. Put with expected_version Some(1) when none exists fails (PreconditionFailed)
    let err = repo
        .put_vault_snapshot(&user.id, b"first blob".to_vec(), Some(1))
        .await;
    assert!(matches!(err, Err(AppError::PreconditionFailed(_))));

    // 3. Put with expected_version Some(0) when none exists succeeds -> version 1
    let meta1 = repo
        .put_vault_snapshot(&user.id, b"first blob".to_vec(), Some(0))
        .await
        .unwrap();
    assert_eq!(meta1.version, 1);
    assert_eq!(meta1.size_bytes, b"first blob".len() as i64);

    let snap1 = repo
        .get_vault_snapshot(&user.id)
        .await
        .unwrap()
        .expect("Snapshot should exist");
    assert_eq!(snap1.version, 1);
    assert_eq!(snap1.encrypted_blob, b"first blob".to_vec());

    // 4. Put with stale expected_version Some(0) fails
    let stale_err = repo
        .put_vault_snapshot(&user.id, b"second blob".to_vec(), Some(0))
        .await;
    assert!(matches!(stale_err, Err(AppError::PreconditionFailed(_))));

    // 5. Put with correct expected_version Some(1) succeeds -> version 2
    let meta2 = repo
        .put_vault_snapshot(&user.id, b"second blob".to_vec(), Some(1))
        .await
        .unwrap();
    assert_eq!(meta2.version, 2);
    assert_eq!(meta2.size_bytes, b"second blob".len() as i64);

    let snap2 = repo
        .get_vault_snapshot(&user.id)
        .await
        .unwrap()
        .expect("Snapshot should exist");
    assert_eq!(snap2.version, 2);
    assert_eq!(snap2.encrypted_blob, b"second blob".to_vec());

    // 6. Put with expected_version None (unconditional) succeeds -> version 3
    let meta3 = repo
        .put_vault_snapshot(&user.id, b"third blob".to_vec(), None)
        .await
        .unwrap();
    assert_eq!(meta3.version, 3);

    let snap3 = repo
        .get_vault_snapshot(&user.id)
        .await
        .unwrap()
        .expect("Snapshot should exist");
    assert_eq!(snap3.version, 3);
    assert_eq!(snap3.encrypted_blob, b"third blob".to_vec());
}

#[tokio::test]
async fn test_sqlite_vault_items_sync() {
    let repo = SqliteRepository::new_in_memory().await.unwrap();

    let auth_key = "auth_key_items";
    let hash = hash_password(auth_key).unwrap();
    let user = repo
        .create_user(&NewUser {
            id: Some("user-uuid-items".to_string()),
            email: "items@example.com".to_string(),
            server_password_hash: hash,
            kdf_salt: "salt".to_string(),
            kdf_memory_kb: 65536,
            kdf_iterations: 3,
            kdf_parallelism: 1,
            wrapped_vault_key: "wrapped".to_string(),
        })
        .await
        .unwrap();

    let items = vec![
        VaultItemUpsert {
            id: "item-1".to_string(),
            encrypted_payload: "payload-1".to_string(),
            deleted_at: None,
        },
        VaultItemUpsert {
            id: "item-2".to_string(),
            encrypted_payload: "payload-2".to_string(),
            deleted_at: None,
        },
    ];

    let results = repo.upsert_vault_items(&user.id, &items, 1000).await.unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].id, "item-1");
    assert_eq!(results[0].version, 1);
    assert_eq!(results[0].updated_at, 1000);
    assert_eq!(results[1].id, "item-2");
    assert_eq!(results[1].version, 1);
    assert_eq!(results[1].updated_at, 1000);

    // Retrieve all items
    let fetched = repo.get_vault_items(&user.id, None).await.unwrap();
    assert_eq!(fetched.len(), 2);
    assert_eq!(fetched[0].id, "item-1");
    assert_eq!(fetched[0].created_at, 1000);
    assert_eq!(fetched[0].version, 1);
    assert_eq!(fetched[1].id, "item-2");
    assert_eq!(fetched[1].created_at, 1000);
    assert_eq!(fetched[1].version, 1);

    // Retrieve since = Some(1000) (exclusive) -> empty
    let empty = repo.get_vault_items(&user.id, Some(1000)).await.unwrap();
    assert!(empty.is_empty());

    // Retrieve since = Some(500) -> returns both
    let since_500 = repo.get_vault_items(&user.id, Some(500)).await.unwrap();
    assert_eq!(since_500.len(), 2);

    // Update item-1 (tombstone) at now_ms = 2000
    let update_items = vec![VaultItemUpsert {
        id: "item-1".to_string(),
        encrypted_payload: "payload-1-updated".to_string(),
        deleted_at: Some(2000),
    }];
    let update_results = repo
        .upsert_vault_items(&user.id, &update_items, 2000)
        .await
        .unwrap();
    assert_eq!(update_results.len(), 1);
    assert_eq!(update_results[0].id, "item-1");
    assert_eq!(update_results[0].version, 2);
    assert_eq!(update_results[0].updated_at, 2000);

    // Retrieve since = Some(1000) -> returns only item-1
    let delta = repo.get_vault_items(&user.id, Some(1000)).await.unwrap();
    assert_eq!(delta.len(), 1);
    assert_eq!(delta[0].id, "item-1");
    assert_eq!(delta[0].version, 2);
    assert_eq!(delta[0].encrypted_payload, "payload-1-updated");
    assert_eq!(delta[0].deleted_at, Some(2000));
    assert_eq!(delta[0].created_at, 1000);
    assert_eq!(delta[0].updated_at, 2000);
}

#[tokio::test]
async fn test_sqlite_file_repository_and_deterministic_sorting() {
    let temp_dir = std::env::temp_dir();
    let db_path = temp_dir.join(format!("test_syncserver_{}.db", uuid::Uuid::new_v4()));
    let db_url = format!("sqlite://{}", db_path.to_str().unwrap());

    let repo = SqliteRepository::new(&db_url).await.unwrap();

    // Verify WAL journal mode and busy timeout
    let journal_mode: (String,) = sqlx::query_as("PRAGMA journal_mode")
        .fetch_one(repo.pool())
        .await
        .unwrap();
    assert_eq!(journal_mode.0.to_lowercase(), "wal");

    let busy_timeout: (i64,) = sqlx::query_as("PRAGMA busy_timeout")
        .fetch_one(repo.pool())
        .await
        .unwrap();
    assert_eq!(busy_timeout.0, 5000);

    // Verify deterministic sorting by (updated_at ASC, id ASC)
    let user = repo
        .create_user(&NewUser {
            id: Some("user-sort-test".to_string()),
            email: "sort@example.com".to_string(),
            server_password_hash: hash_password("pass").unwrap(),
            kdf_salt: "salt".to_string(),
            kdf_memory_kb: 65536,
            kdf_iterations: 3,
            kdf_parallelism: 1,
            wrapped_vault_key: "wrapped".to_string(),
        })
        .await
        .unwrap();

    let items = vec![
        VaultItemUpsert {
            id: "charlie".to_string(),
            encrypted_payload: "p-c".to_string(),
            deleted_at: None,
        },
        VaultItemUpsert {
            id: "alpha".to_string(),
            encrypted_payload: "p-a".to_string(),
            deleted_at: None,
        },
        VaultItemUpsert {
            id: "bravo".to_string(),
            encrypted_payload: "p-b".to_string(),
            deleted_at: None,
        },
    ];

    repo.upsert_vault_items(&user.id, &items, 5000)
        .await
        .unwrap();

    // Query all items - should be sorted alpha, bravo, charlie
    let fetched = repo.get_vault_items(&user.id, None).await.unwrap();
    let ids: Vec<&str> = fetched.iter().map(|i| i.id.as_str()).collect();
    assert_eq!(ids, vec!["alpha", "bravo", "charlie"]);

    // Query since 4000 - should also be sorted alpha, bravo, charlie
    let fetched_since = repo.get_vault_items(&user.id, Some(4000)).await.unwrap();
    let ids_since: Vec<&str> = fetched_since.iter().map(|i| i.id.as_str()).collect();
    assert_eq!(ids_since, vec!["alpha", "bravo", "charlie"]);

    // Clean up temporary database files
    let _ = std::fs::remove_file(&db_path);
    let _ = std::fs::remove_file(format!("{}-wal", db_path.to_str().unwrap()));
    let _ = std::fs::remove_file(format!("{}-shm", db_path.to_str().unwrap()));
}
