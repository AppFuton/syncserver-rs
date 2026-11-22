use base64::prelude::*;
use syncserver_rs::crypto::{
    generate_fake_salt, hash_password, normalize_email, verify_dummy_password, verify_password,
};

#[test]
fn test_email_normalization() {
    assert_eq!(normalize_email("  User@Example.Com "), "user@example.com");
    assert_eq!(normalize_email("\tAdmin@futon.IO\n"), "admin@futon.io");
}

#[test]
fn test_fake_salt_deterministic_and_unique() {
    let secret = b"super_secret_server_hmac_key_12345";
    let salt1 = generate_fake_salt(secret, "user@example.com");
    let salt2 = generate_fake_salt(secret, "user@example.com");
    let salt_unnormalized = generate_fake_salt(secret, "  USER@EXAMPLE.COM  ");
    let salt3 = generate_fake_salt(secret, "other@example.com");
    assert_eq!(salt1, salt2);
    assert_eq!(salt1, salt_unnormalized);
    assert_ne!(salt1, salt3);
    assert_eq!(
        BASE64_STANDARD.decode(&salt1).unwrap().len(),
        16
    );
}

#[test]
fn test_argon2_hash_and_verify() {
    let key = "client_auth_key_sample_base64_string";
    let hash = hash_password(key).unwrap();
    assert!(hash.starts_with("$argon2id$"));
    assert!(verify_password(key, &hash).unwrap());
    assert!(!verify_password("wrong_key", &hash).unwrap());
}

#[test]
fn test_verify_dummy_password() {
    let key = "client_auth_key_sample_base64_string";
    assert!(verify_dummy_password(key).is_ok());
    assert!(verify_dummy_password("any_other_key").is_ok());
}

#[test]
fn test_verify_password_invalid_hash() {
    assert!(verify_password("key", "invalid_argon_hash").is_err());
}
