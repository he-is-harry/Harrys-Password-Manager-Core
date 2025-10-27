#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;
#[cfg(not(feature = "wasm"))]
use zeroize::Zeroizing;

use crate::internal::{
    decrypt_password_internal, encrypt_password_internal, generate_password_internal,
    keygen_internal,
};
use crate::types::{EncryptedPassword, KeyPair, PasswordGeneratorOptions};
#[cfg(not(feature = "wasm"))]
use crate::errors::{DecryptError, EncryptError, PasswordGeneratorError};
#[cfg(feature = "wasm")]
use crate::types::{DecryptedPassword, GeneratedPassword};

mod errors;
mod internal;
mod types;

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
) -> Result<Zeroizing<Vec<u8>>, DecryptError> {
    decrypt_password_internal(master_password, kem_private_key, encrypted_data)
}

#[cfg(not(feature = "wasm"))]
pub fn generate_password(
    options: Option<PasswordGeneratorOptions>,
) -> Result<Zeroizing<String>, PasswordGeneratorError> {
    generate_password_internal(options)
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn keygen() -> Result<KeyPair, JsError> {
    keygen_internal().map_err(|e| wasm_bindgen::JsError::new(&e.to_string()))
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn encrypt_password(
    master_password: &[u8],
    encryption_key: &[u8],
    actual_password: &[u8],
) -> Result<EncryptedPassword, JsError> {
    encrypt_password_internal(master_password, encryption_key, actual_password)
        .map_err(|e| wasm_bindgen::JsError::new(&e.to_string()))
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn decrypt_password(
    master_password: &[u8],
    kem_private_key: &[u8],
    encrypted_data: &EncryptedPassword,
) -> Result<DecryptedPassword, JsError> {
    decrypt_password_internal(master_password, kem_private_key, encrypted_data)
        .map(|password| DecryptedPassword {
            password: password.to_vec(),
        })
        .map_err(|e| wasm_bindgen::JsError::new(&e.to_string()))
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn generate_password(
    options: Option<PasswordGeneratorOptions>,
) -> Result<GeneratedPassword, JsError> {
    generate_password_internal(options)
        .map(|password| GeneratedPassword {
            password: password.to_string(),
        })
        .map_err(|e| wasm_bindgen::JsError::new(&e.to_string()))
}
