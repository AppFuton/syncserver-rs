use crate::error::AppError;
use argon2::{
    password_hash::{
        rand_core::OsRng,
        Error as HashError, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
    },
    Argon2, Params,
};

// Static precomputed dummy hash for timing attack mitigation.
// Parameters match argon2id (m=65536, t=3, p=1).
pub static PRECOMPUTED_DUMMY_HASH: &str =
    "$argon2id$v=19$m=65536,t=3,p=1$vs7W1imaf/zy0c2DPMpxHQ$lI67fNYfv3EDIbVfjsA+JFoKc/rhNhJlq5iRAdUehBc";

pub fn hash_password(auth_key: &str) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut OsRng);
    let params = Params::new(65536, 3, 1, None)
        .map_err(|e| AppError::Internal(format!("Invalid Argon2 params: {e}")))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    argon2
        .hash_password(auth_key.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| AppError::Internal(format!("Argon2 hashing failed: {e}")))
}

pub fn verify_password(auth_key: &str, password_hash: &str) -> Result<bool, AppError> {
    let parsed_hash = PasswordHash::new(password_hash)
        .map_err(|e| AppError::Internal(format!("Invalid password hash: {e}")))?;

    let argon2 = Argon2::default();
    match argon2.verify_password(auth_key.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(HashError::Password) => Ok(false),
        Err(e) => Err(AppError::Internal(format!("Argon2 verification failed: {e}"))),
    }
}

pub fn verify_dummy_password(auth_key: &str) -> Result<(), AppError> {
    let _ = verify_password(auth_key, PRECOMPUTED_DUMMY_HASH)?;
    Ok(())
}
