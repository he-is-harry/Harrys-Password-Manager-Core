#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[cfg(feature = "rust")]
pub struct KeyPair {
    pub encryption_key: Vec<u8>,
    pub decryption_key: Vec<u8>,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[cfg(any(feature = "wasm", feature = "uniffi"))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct KeyPair {
    pub(crate) encryption_key: Vec<u8>,
    pub(crate) decryption_key: Vec<u8>,
}

#[cfg(any(feature = "wasm", feature = "uniffi"))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[cfg_attr(feature = "uniffi", uniffi::export)]
impl KeyPair {
    #[cfg_attr(feature = "wasm", wasm_bindgen(constructor))]
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn new(encryption_key: Vec<u8>, decryption_key: Vec<u8>) -> Self {
        KeyPair {
            encryption_key,
            decryption_key,
        }
    }

    #[cfg_attr(feature = "wasm", wasm_bindgen(getter))]
    pub fn encryption_key(&self) -> Vec<u8> {
        self.encryption_key.clone()
    }

    #[cfg_attr(feature = "wasm", wasm_bindgen(getter))]
    pub fn decryption_key(&self) -> Vec<u8> {
        self.decryption_key.clone()
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[cfg(feature = "rust")]
pub struct EncryptedPassword {
    pub argon2_salt: Vec<u8>,
    pub hkdf_salt: Vec<u8>,
    pub kem_nonce: Vec<u8>,
    pub kem_ciphertext: [u8; 1104],
    pub password_nonce: Vec<u8>,
    pub password_ciphertext: Vec<u8>,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[cfg(any(feature = "wasm", feature = "uniffi"))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct EncryptedPassword {
    pub(crate) argon2_salt: Vec<u8>,
    pub(crate) hkdf_salt: Vec<u8>,
    pub(crate) kem_nonce: Vec<u8>,
    pub(crate) kem_ciphertext: [u8; 1104],
    pub(crate) password_nonce: Vec<u8>,
    pub(crate) password_ciphertext: Vec<u8>,
}

#[cfg(any(feature = "wasm", feature = "uniffi"))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[cfg_attr(feature = "uniffi", uniffi::export)]
impl EncryptedPassword {
    #[cfg_attr(feature = "wasm", wasm_bindgen(getter))]
    pub fn argon2_salt(&self) -> Vec<u8> {
        self.argon2_salt.clone()
    }

    #[cfg_attr(feature = "wasm", wasm_bindgen(getter))]
    pub fn hkdf_salt(&self) -> Vec<u8> {
        self.hkdf_salt.clone()
    }

    #[cfg_attr(feature = "wasm", wasm_bindgen(getter))]
    pub fn kem_nonce(&self) -> Vec<u8> {
        self.kem_nonce.clone()
    }

    #[cfg_attr(feature = "wasm", wasm_bindgen(getter))]
    pub fn kem_ciphertext(&self) -> Vec<u8> {
        self.kem_ciphertext.to_vec()
    }

    #[cfg_attr(feature = "wasm", wasm_bindgen(getter))]
    pub fn password_nonce(&self) -> Vec<u8> {
        self.password_nonce.clone()
    }

    #[cfg_attr(feature = "wasm", wasm_bindgen(getter))]
    pub fn password_ciphertext(&self) -> Vec<u8> {
        self.password_ciphertext.clone()
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl EncryptedPassword {
    #[wasm_bindgen(constructor)]
    pub fn new(
        argon2_salt: Vec<u8>,
        hkdf_salt: Vec<u8>,
        kem_nonce: Vec<u8>,
        kem_ciphertext: Vec<u8>,
        password_nonce: Vec<u8>,
        password_ciphertext: Vec<u8>,
    ) -> Result<Self, JsError> {
        let kem_ciphertext_fixed =
            <[u8; 1104]>::try_from(kem_ciphertext).map_err(|v: Vec<u8>| {
                wasm_bindgen::JsError::new(&format!(
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
}

#[cfg(any(feature = "wasm", feature = "uniffi"))]
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct DecryptedPassword {
    pub(crate) password: Vec<u8>,
}

#[cfg(any(feature = "wasm", feature = "uniffi"))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[cfg_attr(feature = "uniffi", uniffi::export)]
impl DecryptedPassword {
    #[cfg_attr(feature = "wasm", wasm_bindgen(getter))]
    pub fn password(&self) -> Vec<u8> {
        self.password.clone()
    }
}

#[cfg(any(feature = "wasm", feature = "uniffi"))]
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct GeneratedPassword {
    pub(crate) password: String,
}

#[cfg(any(feature = "wasm", feature = "uniffi"))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[cfg_attr(feature = "uniffi", uniffi::export)]
impl GeneratedPassword {
    #[cfg_attr(feature = "wasm", wasm_bindgen(getter))]
    pub fn password(&self) -> String {
        self.password.clone()
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
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

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[cfg(any(feature = "wasm", feature = "uniffi"))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct EncryptedVaultKey {
    pub(crate) argon2_salt: Vec<u8>,
    pub(crate) vault_key_ciphertext: Vec<u8>,
    pub(crate) vault_key_nonce: Vec<u8>,
}

#[cfg(any(feature = "wasm", feature = "uniffi"))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[cfg_attr(feature = "uniffi", uniffi::export)]
impl EncryptedVaultKey {
    #[cfg_attr(feature = "wasm", wasm_bindgen(constructor))]
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
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

    #[cfg_attr(feature = "wasm", wasm_bindgen(getter))]
    pub fn argon2_salt(&self) -> Vec<u8> {
        self.argon2_salt.clone()
    }

    #[cfg_attr(feature = "wasm", wasm_bindgen(getter))]
    pub fn vault_key_ciphertext(&self) -> Vec<u8> {
        self.vault_key_ciphertext.clone()
    }

    #[cfg_attr(feature = "wasm", wasm_bindgen(getter))]
    pub fn vault_key_nonce(&self) -> Vec<u8> {
        self.vault_key_nonce.clone()
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[cfg(any(feature = "wasm", feature = "uniffi"))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct EncryptedDeviceKeyPair {
    pub(crate) wrapping_key: Vec<u8>,
    pub(crate) encryption_key_ciphertext: Vec<u8>,
    pub(crate) encryption_key_nonce: Vec<u8>,
    pub(crate) decryption_key_ciphertext: Vec<u8>,
    pub(crate) decryption_key_nonce: Vec<u8>,
}

#[cfg(any(feature = "wasm", feature = "uniffi"))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[cfg_attr(feature = "uniffi", uniffi::export)]
impl EncryptedDeviceKeyPair {
    #[cfg_attr(feature = "wasm", wasm_bindgen(getter))]
    pub fn wrapping_key(&self) -> Vec<u8> {
        self.wrapping_key.clone()
    }

    #[cfg_attr(feature = "wasm", wasm_bindgen(getter))]
    pub fn encryption_key_ciphertext(&self) -> Vec<u8> {
        self.encryption_key_ciphertext.clone()
    }

    #[cfg_attr(feature = "wasm", wasm_bindgen(getter))]
    pub fn encryption_key_nonce(&self) -> Vec<u8> {
        self.encryption_key_nonce.clone()
    }

    #[cfg_attr(feature = "wasm", wasm_bindgen(getter))]
    pub fn decryption_key_ciphertext(&self) -> Vec<u8> {
        self.decryption_key_ciphertext.clone()
    }

    #[cfg_attr(feature = "wasm", wasm_bindgen(getter))]
    pub fn decryption_key_nonce(&self) -> Vec<u8> {
        self.decryption_key_nonce.clone()
    }
}
