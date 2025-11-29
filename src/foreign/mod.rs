#[cfg(feature = "uniffi")]
pub mod errors;

#[cfg(feature = "uniffi")]
pub mod types;

#[cfg(feature = "uniffi")]
pub mod uniffi_exports {
    use super::errors::{
        UniffiDecryptError, UniffiEncryptError, UniffiKeygenError, UniffiPasswordGeneratorError,
    };
    use crate::internal::{
        decrypt_password_internal, decrypt_vault_key_internal, encrypt_password_internal, generate_encrypted_vault_key_internal, generate_password_internal, keygen_internal
    };
    use crate::types::{EncryptedPassword, EncryptedVaultKey, KeyPair, PasswordGeneratorOptions};

    #[uniffi::export]
    pub fn keygen() -> Result<KeyPair, UniffiKeygenError> {
        keygen_internal().map_err(|e| UniffiKeygenError::OsRngError(e.to_string()))
    }

    #[uniffi::export]
    pub fn encrypt_password(
        master_password: &[u8],
        encryption_key: &[u8],
        actual_password: &[u8],
    ) -> Result<EncryptedPassword, UniffiEncryptError> {
        encrypt_password_internal(master_password, encryption_key, actual_password)
            .map_err(Into::into)
    }

    #[uniffi::export]
    pub fn decrypt_password(
        master_password: &[u8],
        kem_private_key: &[u8],
        encrypted_data: &EncryptedPassword,
    ) -> Result<Vec<u8>, UniffiDecryptError> {
        decrypt_password_internal(master_password, kem_private_key, encrypted_data)
            .map(|z| z.to_vec())
            .map_err(Into::into)
    }

    #[uniffi::export]
    pub fn generate_password(
        options: Option<PasswordGeneratorOptions>,
    ) -> Result<String, UniffiPasswordGeneratorError> {
        generate_password_internal(options)
            .map(|z| z.to_string())
            .map_err(Into::into)
    }

    #[uniffi::export]
    pub fn generate_encrypted_vault_key(
        master_password: &[u8],
    ) -> Result<EncryptedVaultKey, UniffiEncryptError> {
        generate_encrypted_vault_key_internal(master_password).map_err(Into::into)
    }

    #[uniffi::export]
    pub fn decrypt_vault_key(
        master_password: &[u8],
        encrypted_vault_key: &EncryptedVaultKey,
    ) -> Result<Vec<u8>, UniffiDecryptError> {
        decrypt_vault_key_internal(master_password, encrypted_vault_key)
            .map(|z| z.to_vec())
            .map_err(Into::into)
    }
}
