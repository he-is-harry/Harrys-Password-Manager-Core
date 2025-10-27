use zeroize::{Zeroize, ZeroizeOnDrop};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct KeyPair {
    pub(crate) encryption_key: Vec<u8>,
    pub(crate) decryption_key: Vec<u8>,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl KeyPair {
    #[cfg_attr(feature = "wasm", wasm_bindgen(constructor))]
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
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct EncryptedPassword {
    pub(crate) argon2_salt: Vec<u8>,
    pub(crate) hkdf_salt: Vec<u8>,
    pub(crate) kem_nonce: Vec<u8>,
    pub(crate) kem_ciphertext: [u8; 1104],
    pub(crate) password_nonce: Vec<u8>,
    pub(crate) password_ciphertext: Vec<u8>,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl EncryptedPassword {
    #[cfg(not(feature = "wasm"))]
    pub fn new(argon2_salt: Vec<u8>, hkdf_salt: Vec<u8>, kem_nonce: Vec<u8>, kem_ciphertext: [u8; 1104], password_nonce: Vec<u8>, password_ciphertext: Vec<u8>) -> Self {
        EncryptedPassword {
            argon2_salt,
            hkdf_salt,
            kem_nonce,
            kem_ciphertext,
            password_nonce,
            password_ciphertext,
        }
    }

    #[wasm_bindgen(constructor)]
    #[cfg(feature = "wasm")]
    pub fn new(argon2_salt: Vec<u8>, hkdf_salt: Vec<u8>, kem_nonce: Vec<u8>, kem_ciphertext: Vec<u8>, password_nonce: Vec<u8>, password_ciphertext: Vec<u8>) -> Result<Self, JsError> {
        let kem_ciphertext_fixed = <[u8; 1104]>::try_from(kem_ciphertext)
            .map_err(|v: Vec<u8>| wasm_bindgen::JsError::new(&format!("Wrong length for kem_ciphertext: Expected 1104 bytes, got {}", v.len())))?;

        Ok(EncryptedPassword {
            argon2_salt,
            hkdf_salt,
            kem_nonce,
            kem_ciphertext: kem_ciphertext_fixed,
            password_nonce,
            password_ciphertext,
        })
    }

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

    #[cfg(not(feature = "wasm"))]
    pub fn kem_ciphertext(&self) -> [u8; 1104] {
        self.kem_ciphertext.clone()
    }

    #[cfg(feature = "wasm")]
    #[wasm_bindgen(getter)]
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
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[wasm_bindgen]
pub struct DecryptedPassword {
    pub(crate) password: Vec<u8>,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl DecryptedPassword {
    #[wasm_bindgen(getter)]
    pub fn password(&self) -> Vec<u8> {
        self.password.clone()
    }
}

#[cfg(feature = "wasm")]
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[wasm_bindgen]
pub struct GeneratedPassword {
    pub(crate) password: String,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl GeneratedPassword {
    #[wasm_bindgen(getter)]
    pub fn password(&self) -> String {
        self.password.clone()
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct PasswordGeneratorOptions {
    pub length: Option<usize>,
    pub include_numbers: Option<bool>,
    pub include_uppercase: Option<bool>,
    pub include_lowercase: Option<bool>,
    pub include_symbols: Option<bool>,
    pub min_numbers: Option<usize>,
    pub min_uppercase: Option<usize>,
    pub min_lowercase: Option<usize>,
    pub min_symbols: Option<usize>,
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
