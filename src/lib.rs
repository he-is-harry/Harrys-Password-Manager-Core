#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(not(feature = "wasm"))]
use crate::errors::{EncryptError, DecryptError, PasswordGeneratorError};
use crate::internal::{decrypt_password_internal, encrypt_password_internal, generate_password_internal, keygen_internal, EncryptedPassword, KeyPair, PasswordGeneratorOptions};

mod errors;
mod internal;

#[cfg(not(feature = "wasm"))]
pub fn keygen() -> Result<KeyPair, rand::rand_core::OsError> {
    keygen_internal()
}

#[cfg(not(feature = "wasm"))]
pub fn encrypt_password(
    master_password: &[u8],
    encryption_key: &[u8],
    actual_password: &[u8],
) -> Result<EncryptedPassword, EncryptError> {
    encrypt_password_internal(master_password, encryption_key, actual_password)
}

#[cfg(not(feature = "wasm"))]
pub fn decrypt_password(
    master_password: &[u8],
    kem_private_key: &[u8],
    encrypted_data: &EncryptedPassword,
) -> Result<Vec<u8>, DecryptError> {
    decrypt_password_internal(master_password, kem_private_key, encrypted_data)
}

#[cfg(not(feature = "wasm"))]
pub fn generate_password(options: Option<PasswordGeneratorOptions>) -> Result<String, PasswordGeneratorError> {
    generate_password_internal(options)
}

#[cfg(feature = "wasm")]
pub fn keygen() -> Result<KeyPair, JsError> {
    keygen_internal().map_err(|e| wasm_bindgen::JsError::new(&e.to_string()))
}

#[cfg(feature = "wasm")]
pub fn encrypt_password(
    master_password: &[u8],
    encryption_key: &[u8],
    actual_password: &[u8],
) -> Result<EncryptedPassword, JsError> {
    encrypt_password_internal(master_password, encryption_key, actual_password).map_err(|e| wasm_bindgen::JsError::new(&e.to_string()))
}

#[cfg(feature = "wasm")]
pub fn decrypt_password(
    master_password: &[u8],
    kem_private_key: &[u8],
    encrypted_data: &EncryptedPassword,
) -> Result<Vec<u8>, JsError> {
    decrypt_password_internal(master_password, kem_private_key, encrypted_data).map_err(|e| wasm_bindgen::JsError::new(&e.to_string()))
}

#[cfg(feature = "wasm")]
pub fn generate_password(options: Option<PasswordGeneratorOptions>) -> Result<String, JsError> {
    generate_password_internal(options).map_err(|e| wasm_bindgen::JsError::new(&e.to_string()))
}
