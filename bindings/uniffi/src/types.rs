use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::UniffiEncryptError;

#[derive(Clone, Zeroize, ZeroizeOnDrop, uniffi::Object)]
pub struct KeyPair {
    pub(crate) encryption_key: Vec<u8>,
    pub(crate) decryption_key: Vec<u8>,
}

#[uniffi::export]
impl KeyPair {
    #[uniffi::constructor]
    pub fn new(encryption_key: Vec<u8>, decryption_key: Vec<u8>) -> Self {
        KeyPair {
            encryption_key,
            decryption_key,
        }
    }

    pub fn encryption_key(&self) -> Vec<u8> {
        self.encryption_key.clone()
    }

    pub fn decryption_key(&self) -> Vec<u8> {
        self.decryption_key.clone()
    }
}

impl From<harrys_password_manager_core::types::KeyPair> for KeyPair {
    fn from(value: harrys_password_manager_core::types::KeyPair) -> Self {
        KeyPair {
            encryption_key: value.encryption_key.clone(),
            decryption_key: value.decryption_key.clone(),
        }
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop, uniffi::Object)]
pub struct EncryptedPassword {
    pub(crate) argon2_salt: Vec<u8>,
    pub(crate) hkdf_salt: Vec<u8>,
    pub(crate) kem_nonce: Vec<u8>,
    pub(crate) kem_ciphertext: [u8; 1104],
    pub(crate) password_nonce: Vec<u8>,
    pub(crate) password_ciphertext: Vec<u8>,
}

#[uniffi::export]
impl EncryptedPassword {
    #[uniffi::constructor]
    pub fn new(
        argon2_salt: Vec<u8>,
        hkdf_salt: Vec<u8>,
        kem_nonce: Vec<u8>,
        kem_ciphertext: Vec<u8>,
        password_nonce: Vec<u8>,
        password_ciphertext: Vec<u8>,
    ) -> Result<Self, UniffiEncryptError> {
        let kem_ciphertext_fixed =
            <[u8; 1104]>::try_from(kem_ciphertext).map_err(|v: Vec<u8>| {
                UniffiEncryptError::TryFromSliceError(format!(
                    "Wrong length for kem_ciphertext: Expected 1104 bytes, got {}",
                    v.len()
                ))
            })?;

        Ok(EncryptedPassword {
            argon2_salt,
            hkdf_salt,
            kem_nonce,
            kem_ciphertext: kem_ciphertext_fixed,
            password_nonce,
            password_ciphertext,
        })
    }

    pub fn argon2_salt(&self) -> Vec<u8> {
        self.argon2_salt.clone()
    }

    pub fn hkdf_salt(&self) -> Vec<u8> {
        self.hkdf_salt.clone()
    }

    pub fn kem_nonce(&self) -> Vec<u8> {
        self.kem_nonce.clone()
    }

    pub fn kem_ciphertext(&self) -> Vec<u8> {
        self.kem_ciphertext.to_vec()
    }

    pub fn password_nonce(&self) -> Vec<u8> {
        self.password_nonce.clone()
    }

    pub fn password_ciphertext(&self) -> Vec<u8> {
        self.password_ciphertext.clone()
    }
}

impl From<harrys_password_manager_core::types::EncryptedPassword> for EncryptedPassword {
    fn from(value: harrys_password_manager_core::types::EncryptedPassword) -> Self {
        EncryptedPassword {
            argon2_salt: value.argon2_salt.clone(),
            hkdf_salt: value.hkdf_salt.clone(),
            kem_nonce: value.kem_nonce.clone(),
            kem_ciphertext: value.kem_ciphertext.clone(),
            password_nonce: value.password_nonce.clone(),
            password_ciphertext: value.password_ciphertext.clone(),
        }
    }
}

impl From<&EncryptedPassword> for harrys_password_manager_core::types::EncryptedPassword {
    fn from(value: &EncryptedPassword) -> Self {
        harrys_password_manager_core::types::EncryptedPassword {
            argon2_salt: value.argon2_salt.clone(),
            hkdf_salt: value.hkdf_salt.clone(),
            kem_nonce: value.kem_nonce.clone(),
            kem_ciphertext: value.kem_ciphertext,
            password_nonce: value.password_nonce.clone(),
            password_ciphertext: value.password_ciphertext.clone(),
        }
    }
}

#[derive(uniffi::Record)]
pub struct PasswordGeneratorOptions {
    pub length: Option<u32>,
    pub include_numbers: Option<bool>,
    pub include_uppercase: Option<bool>,
    pub include_lowercase: Option<bool>,
    pub include_symbols: Option<bool>,
    pub min_numbers: Option<u32>,
    pub min_uppercase: Option<u32>,
    pub min_lowercase: Option<u32>,
    pub min_symbols: Option<u32>,
}

impl Default for PasswordGeneratorOptions {
    fn default() -> Self {
        PasswordGeneratorOptions {
            length: Some(12),
            include_numbers: Some(true),
            include_uppercase: Some(true),
            include_lowercase: Some(true),
            include_symbols: Some(true),
            min_numbers: Some(1),
            min_uppercase: Some(1),
            min_lowercase: Some(1),
            min_symbols: Some(1),
        }
    }
}

impl From<PasswordGeneratorOptions>
    for harrys_password_manager_core::types::PasswordGeneratorOptions
{
    fn from(value: PasswordGeneratorOptions) -> Self {
        harrys_password_manager_core::types::PasswordGeneratorOptions {
            length: value.length,
            include_numbers: value.include_numbers,
            include_uppercase: value.include_uppercase,
            include_lowercase: value.include_lowercase,
            include_symbols: value.include_symbols,
            min_numbers: value.min_numbers,
            min_uppercase: value.min_uppercase,
            min_lowercase: value.min_lowercase,
            min_symbols: value.min_symbols,
        }
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop, uniffi::Object)]
pub struct EncryptedVaultKey {
    pub(crate) argon2_salt: Vec<u8>,
    pub(crate) vault_key_ciphertext: Vec<u8>,
    pub(crate) vault_key_nonce: Vec<u8>,
}

#[uniffi::export]
impl EncryptedVaultKey {
    #[uniffi::constructor]
    pub fn new(
        argon2_salt: Vec<u8>,
        vault_key_ciphertext: Vec<u8>,
        vault_key_nonce: Vec<u8>,
    ) -> Self {
        EncryptedVaultKey {
            argon2_salt,
            vault_key_ciphertext,
            vault_key_nonce,
        }
    }

    pub fn argon2_salt(&self) -> Vec<u8> {
        self.argon2_salt.clone()
    }

    pub fn vault_key_ciphertext(&self) -> Vec<u8> {
        self.vault_key_ciphertext.clone()
    }

    pub fn vault_key_nonce(&self) -> Vec<u8> {
        self.vault_key_nonce.clone()
    }
}

impl From<harrys_password_manager_core::types::EncryptedVaultKey> for EncryptedVaultKey {
    fn from(value: harrys_password_manager_core::types::EncryptedVaultKey) -> Self {
        EncryptedVaultKey {
            argon2_salt: value.argon2_salt.clone(),
            vault_key_ciphertext: value.vault_key_ciphertext.clone(),
            vault_key_nonce: value.vault_key_nonce.clone(),
        }
    }
}

impl From<&EncryptedVaultKey> for harrys_password_manager_core::types::EncryptedVaultKey {
    fn from(value: &EncryptedVaultKey) -> Self {
        harrys_password_manager_core::types::EncryptedVaultKey {
            argon2_salt: value.argon2_salt.clone(),
            vault_key_ciphertext: value.vault_key_ciphertext.clone(),
            vault_key_nonce: value.vault_key_nonce.clone(),
        }
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop, uniffi::Object)]
pub struct EncryptedDeviceKeyPair {
    pub(crate) wrapping_key: Vec<u8>,
    pub(crate) encryption_key_ciphertext: Vec<u8>,
    pub(crate) encryption_key_nonce: Vec<u8>,
    pub(crate) decryption_key_ciphertext: Vec<u8>,
    pub(crate) decryption_key_nonce: Vec<u8>,
}

#[uniffi::export]
impl EncryptedDeviceKeyPair {
    pub fn wrapping_key(&self) -> Vec<u8> {
        self.wrapping_key.clone()
    }

    pub fn encryption_key_ciphertext(&self) -> Vec<u8> {
        self.encryption_key_ciphertext.clone()
    }

    pub fn encryption_key_nonce(&self) -> Vec<u8> {
        self.encryption_key_nonce.clone()
    }

    pub fn decryption_key_ciphertext(&self) -> Vec<u8> {
        self.decryption_key_ciphertext.clone()
    }

    pub fn decryption_key_nonce(&self) -> Vec<u8> {
        self.decryption_key_nonce.clone()
    }
}

impl From<harrys_password_manager_core::types::EncryptedDeviceKeyPair> for EncryptedDeviceKeyPair {
    fn from(value: harrys_password_manager_core::types::EncryptedDeviceKeyPair) -> Self {
        EncryptedDeviceKeyPair {
            wrapping_key: value.wrapping_key.clone(),
            encryption_key_ciphertext: value.encryption_key_ciphertext.clone(),
            encryption_key_nonce: value.encryption_key_nonce.clone(),
            decryption_key_ciphertext: value.decryption_key_ciphertext.clone(),
            decryption_key_nonce: value.decryption_key_nonce.clone(),
        }
    }
}
