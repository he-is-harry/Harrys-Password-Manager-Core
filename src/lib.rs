use zeroize::Zeroizing;

use crate::errors::{DecryptError, EncryptError, PasswordGeneratorError};
#[cfg(feature = "foreign")]
use crate::internal::{
    decrypt_device_key_internal, decrypt_vault_key_internal,
    generate_encrypted_device_keys_internal, generate_encrypted_vault_key_internal,
};
use crate::internal::{
    decrypt_password_internal, encrypt_password_internal, generate_password_internal,
    keygen_internal,
};
#[cfg(feature = "foreign")]
use crate::types::{EncryptedDeviceKeyPair, EncryptedVaultKey};
use crate::types::{EncryptedPassword, KeyPair, PasswordGeneratorOptions};

pub mod errors;
mod internal;
pub mod types;

pub fn keygen() -> Result<KeyPair, rand::rand_core::OsError> {
    keygen_internal()
}

pub fn encrypt_password(
    master_password: &[u8],
    encryption_key: &[u8],
    actual_password: &[u8],
) -> Result<EncryptedPassword, EncryptError> {
    encrypt_password_internal(master_password, encryption_key, actual_password)
}

pub fn decrypt_password(
    master_password: &[u8],
    kem_private_key: &[u8],
    encrypted_data: &EncryptedPassword,
) -> Result<Zeroizing<Vec<u8>>, DecryptError> {
    decrypt_password_internal(master_password, kem_private_key, encrypted_data)
}

pub fn generate_password(
    options: Option<PasswordGeneratorOptions>,
) -> Result<Zeroizing<String>, PasswordGeneratorError> {
    generate_password_internal(options)
}

#[cfg(feature = "foreign")]
pub fn generate_encrypted_vault_key(
    master_password: &[u8],
) -> Result<EncryptedVaultKey, EncryptError> {
    generate_encrypted_vault_key_internal(master_password)
}

#[cfg(feature = "foreign")]
pub fn decrypt_vault_key(
    master_password: &[u8],
    encrypted_vault_key: &EncryptedVaultKey,
) -> Result<Zeroizing<Vec<u8>>, DecryptError> {
    decrypt_vault_key_internal(master_password, encrypted_vault_key)
}

#[cfg(feature = "foreign")]
pub fn generate_encrypted_device_keys() -> Result<EncryptedDeviceKeyPair, EncryptError> {
    generate_encrypted_device_keys_internal()
}

#[cfg(feature = "foreign")]
pub fn decrypt_device_key(
    wrapping_key: &[u8],
    key_ciphertext: &[u8],
    key_nonce: &[u8],
) -> Result<Zeroizing<Vec<u8>>, DecryptError> {
    decrypt_device_key_internal(wrapping_key, key_ciphertext, key_nonce)
}
