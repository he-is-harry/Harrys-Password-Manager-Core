#![deny(clippy::all)]

use napi::bindgen_prelude::Buffer;
use napi_derive::napi;

pub mod types;

use harrys_password_manager_core::{
  decrypt_device_key as decrypt_device_key_internal, decrypt_password as decrypt_password_internal,
  decrypt_vault_key as decrypt_vault_key_internal,
  decrypt_network_packet as decrypt_network_packet_internal,
  encrypt_password as encrypt_password_internal,
  encrypt_network_packet as encrypt_network_packet_internal,
  generate_encrypted_device_keys as generate_encrypted_device_keys_internal,
  generate_encrypted_vault_key as generate_encrypted_vault_key_internal,
  generate_password as generate_password_internal, keygen as keygen_internal,
  generate_network_shared_secret_key as generate_network_shared_secret_key_internal,
};

use crate::types::{
  EncryptedDeviceKeyPair, EncryptedPassword, EncryptedVaultKey, KeyPair, PasswordGeneratorOptions,
};

#[napi]
pub fn keygen() -> napi::Result<KeyPair> {
  keygen_internal()
    .map(Into::into)
    .map_err(|e| napi::Error::from_reason(format!("Random number generation failed: {}", e)))
}

#[napi]
pub fn encrypt_password(
  master_password: &[u8],
  encryption_key: &[u8],
  actual_password: &[u8],
) -> napi::Result<EncryptedPassword> {
  encrypt_password_internal(master_password, encryption_key, actual_password)
    .map(Into::into)
    .map_err(|e| napi::Error::from_reason(e.to_string()))
}

#[napi]
pub fn decrypt_password(
  master_password: &[u8],
  kem_private_key: &[u8],
  encrypted_data: &EncryptedPassword,
) -> napi::Result<Buffer> {
  let core_encrypted_data = encrypted_data.try_into()?;
  decrypt_password_internal(master_password, kem_private_key, &core_encrypted_data)
    .map(|z| z.to_vec().into())
    .map_err(|e| napi::Error::from_reason(e.to_string()))
}

#[napi]
pub fn generate_password(options: Option<PasswordGeneratorOptions>) -> napi::Result<String> {
  let core_options = options.map(Into::into);
  generate_password_internal(core_options)
    .map(|z| z.to_string())
    .map_err(|e| napi::Error::from_reason(e.to_string()))
}

#[napi]
pub fn generate_encrypted_vault_key(master_password: &[u8]) -> napi::Result<EncryptedVaultKey> {
  generate_encrypted_vault_key_internal(master_password)
    .map(Into::into)
    .map_err(|e| napi::Error::from_reason(e.to_string()))
}

#[napi]
pub fn decrypt_vault_key(
  master_password: &[u8],
  encrypted_vault_key: &EncryptedVaultKey,
) -> napi::Result<Buffer> {
  let core_encrypted_vault_key: harrys_password_manager_core::types::EncryptedVaultKey =
    encrypted_vault_key.into();
  decrypt_vault_key_internal(master_password, &core_encrypted_vault_key)
    .map(|z| z.to_vec().into())
    .map_err(|e| napi::Error::from_reason(e.to_string()))
}

#[napi]
pub fn generate_encrypted_device_keys() -> napi::Result<EncryptedDeviceKeyPair> {
  generate_encrypted_device_keys_internal()
    .map(Into::into)
    .map_err(|e| napi::Error::from_reason(e.to_string()))
}

#[napi]
pub fn decrypt_device_keys(
  wrapping_key: &[u8],
  key_ciphertext: &[u8],
  key_nonce: &[u8],
) -> napi::Result<Buffer> {
  decrypt_device_key_internal(wrapping_key, key_ciphertext, key_nonce)
    .map(|z| z.to_vec().into())
    .map_err(|e| napi::Error::from_reason(e.to_string()))
}

#[napi]
pub fn generate_network_shared_secret_key() -> napi::Result<Buffer> {
  generate_network_shared_secret_key_internal()
    .map(|z| z.to_vec().into())
    .map_err(|e| napi::Error::from_reason(format!("Random number generation failed: {}", e)))
}

#[napi]
pub fn encrypt_network_packet(
  data: String,
  shared_secret_key: &[u8],
) -> napi::Result<Buffer> {
  encrypt_network_packet_internal(data, shared_secret_key)
    .map(|z| z.to_vec().into())
    .map_err(|e| napi::Error::from_reason(e.to_string()))
}

#[napi]
pub fn decrypt_network_packet(
  encrypted_data: &[u8],
  shared_secret_key: &[u8],
) -> napi::Result<String> {
  decrypt_network_packet_internal(encrypted_data, shared_secret_key)
    .map(|z| z.to_string())
    .map_err(|e| napi::Error::from_reason(e.to_string()))
}
