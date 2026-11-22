pub mod argon;
pub mod fake_salt;

pub use argon::{hash_password, verify_dummy_password, verify_password};
pub use fake_salt::{generate_fake_salt, normalize_email};
