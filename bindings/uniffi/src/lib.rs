uniffi::setup_scaffolding!();

pub mod errors;
pub mod types;

use harrys_password_manager_core::{
    decrypt_device_key as decrypt_device_key_internal,
    decrypt_password as decrypt_password_internal, decrypt_vault_key as decrypt_vault_key_internal,
    encrypt_password as encrypt_password_internal,
    generate_encrypted_device_keys as generate_encrypted_device_keys_internal,
    generate_encrypted_vault_key as generate_encrypted_vault_key_internal,
    generate_password as generate_password_internal, keygen as keygen_internal,
};

use crate::errors::{
    UniffiDecryptError, UniffiEncryptError, UniffiKeygenError, UniffiPasswordGeneratorError,
};
use crate::types::{
    EncryptedDeviceKeyPair, EncryptedPassword, EncryptedVaultKey, KeyPair, PasswordGeneratorOptions,
};

#[uniffi::export]
pub fn keygen() -> Result<KeyPair, UniffiKeygenError> {
    keygen_internal()
        .map(Into::into)
        .map_err(|e| UniffiKeygenError::OsRngError(e.to_string()))
}

#[uniffi::export]
pub fn encrypt_password(
    master_password: &[u8],
    encryption_key: &[u8],
    actual_password: &[u8],
) -> Result<EncryptedPassword, UniffiEncryptError> {
    encrypt_password_internal(master_password, encryption_key, actual_password)
        .map(Into::into)
        .map_err(Into::into)
}

#[uniffi::export]
pub fn decrypt_password(
    master_password: &[u8],
    kem_private_key: &[u8],
    encrypted_data: &EncryptedPassword,
) -> Result<Vec<u8>, UniffiDecryptError> {
    let core_encrypted_data: harrys_password_manager_core::types::EncryptedPassword =
        encrypted_data.into();
    decrypt_password_internal(master_password, kem_private_key, &core_encrypted_data)
        .map(|z| z.to_vec())
        .map_err(Into::into)
}

#[uniffi::export]
pub fn generate_password(
    options: Option<PasswordGeneratorOptions>,
) -> Result<String, UniffiPasswordGeneratorError> {
    let core_options = options.map(Into::into);
    generate_password_internal(core_options)
        .map(|z| z.to_string())
        .map_err(Into::into)
}

#[uniffi::export]
pub fn generate_encrypted_vault_key(
    master_password: &[u8],
) -> Result<EncryptedVaultKey, UniffiEncryptError> {
    generate_encrypted_vault_key_internal(master_password)
        .map(Into::into)
        .map_err(Into::into)
}

#[uniffi::export]
pub fn decrypt_vault_key(
    master_password: &[u8],
    encrypted_vault_key: &EncryptedVaultKey,
) -> Result<Vec<u8>, UniffiDecryptError> {
    let core_encrypted_vault_key: harrys_password_manager_core::types::EncryptedVaultKey =
        encrypted_vault_key.into();
    decrypt_vault_key_internal(master_password, &core_encrypted_vault_key)
        .map(|z| z.to_vec())
        .map_err(Into::into)
}

#[uniffi::export]
pub fn generate_encrypted_device_keys() -> Result<EncryptedDeviceKeyPair, UniffiEncryptError> {
    generate_encrypted_device_keys_internal()
        .map(Into::into)
        .map_err(Into::into)
}

#[uniffi::export]
pub fn decrypt_device_keys(
    wrapping_key: &[u8],
    key_ciphertext: &[u8],
    key_nonce: &[u8],
) -> Result<Vec<u8>, UniffiDecryptError> {
    decrypt_device_key_internal(wrapping_key, key_ciphertext, key_nonce)
        .map(|z| z.to_vec())
        .map_err(Into::into)
}
