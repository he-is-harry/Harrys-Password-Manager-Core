#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

#[cfg(any(
    all(feature = "rust", feature = "wasm"),
    all(feature = "rust", feature = "uniffi"),
    all(feature = "wasm", feature = "uniffi"),
))]
compile_error!("Features `rust`, `wasm`, and `uniffi` are mutually exclusive — enable only one at a time.");


#[cfg(feature = "rust")]
use zeroize::Zeroizing;

#[cfg(feature = "rust")]
use crate::errors::{DecryptError, EncryptError, PasswordGeneratorError};
#[cfg(feature = "rust")]
use crate::internal::{
    decrypt_password_internal, encrypt_password_internal, generate_password_internal,
    keygen_internal,
};
#[cfg(feature = "rust")]
use crate::types::{EncryptedPassword, KeyPair, PasswordGeneratorOptions};

pub mod errors;
mod internal;
pub mod types;
pub mod wasm;
pub mod foreign;

#[cfg(feature = "wasm")]
pub use wasm::wasm_exports::*;

#[cfg(feature = "rust")]
pub fn keygen() -> Result<KeyPair, rand::rand_core::OsError> {
    keygen_internal()
}

#[cfg(feature = "rust")]
pub fn encrypt_password(
    master_password: &[u8],
    encryption_key: &[u8],
    actual_password: &[u8],
) -> Result<EncryptedPassword, EncryptError> {
    encrypt_password_internal(master_password, encryption_key, actual_password)
}

#[cfg(feature = "rust")]
pub fn decrypt_password(
    master_password: &[u8],
    kem_private_key: &[u8],
    encrypted_data: &EncryptedPassword,
) -> Result<Zeroizing<Vec<u8>>, DecryptError> {
    decrypt_password_internal(master_password, kem_private_key, encrypted_data)
}

#[cfg(feature = "rust")]
pub fn generate_password(
    options: Option<PasswordGeneratorOptions>,
) -> Result<Zeroizing<String>, PasswordGeneratorError> {
    generate_password_internal(options)
}
