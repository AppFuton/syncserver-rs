use base64::prelude::*;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

pub fn generate_fake_salt(server_secret: &[u8], normalized_email: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(server_secret)
        .expect("HMAC-SHA256 accepts keys of any size");
    mac.update(normalized_email.as_bytes());
    let result = mac.finalize().into_bytes();
    BASE64_STANDARD.encode(&result[..16])
}
