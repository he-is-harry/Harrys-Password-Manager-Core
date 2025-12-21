use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyPair {
    pub encryption_key: Vec<u8>,
    pub decryption_key: Vec<u8>,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EncryptedPassword {
    pub argon2_salt: Vec<u8>,
    pub hkdf_salt: Vec<u8>,
    pub kem_nonce: Vec<u8>,
    pub kem_ciphertext: [u8; 1104],
    pub password_nonce: Vec<u8>,
    pub password_ciphertext: Vec<u8>,
}

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
#[cfg(feature = "foreign")]
pub struct EncryptedVaultKey {
    pub argon2_salt: Vec<u8>,
    pub vault_key_ciphertext: Vec<u8>,
    pub vault_key_nonce: Vec<u8>,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[cfg(feature = "foreign")]
pub struct EncryptedDeviceKeyPair {
    pub wrapping_key: Vec<u8>,
    pub encryption_key_ciphertext: Vec<u8>,
    pub encryption_key_nonce: Vec<u8>,
    pub decryption_key_ciphertext: Vec<u8>,
    pub decryption_key_nonce: Vec<u8>,
}
