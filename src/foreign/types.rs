use crate::types::EncryptedPassword;
use super::errors::UniffiEncryptError;

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
}