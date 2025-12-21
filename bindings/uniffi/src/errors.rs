use harrys_password_manager_core::errors::{DecryptError, EncryptError, PasswordGeneratorError};
use thiserror::Error;

#[derive(Debug, Error, uniffi::Error)]
pub enum UniffiEncryptError {
    #[error("Random number generation failed: {0}")]
    OsRngError(String),
    #[error("Failed to generate hash of password: {0}")]
    Argon2Error(String),
    #[error("Failed to perform AEAD encryption: {0}")]
    ChaCha20Poly1305Error(String),
    #[error("HMAC key derivation invalid length: {0}")]
    HkdfInvalidLength(String),
    #[error("Failed to convert to array from slice: {0}")]
    TryFromSliceError(String),
}

impl From<EncryptError> for UniffiEncryptError {
    fn from(e: EncryptError) -> Self {
        match e {
            EncryptError::OsRngError(e) => UniffiEncryptError::OsRngError(e.to_string()),
            EncryptError::Argon2Error(e) => UniffiEncryptError::Argon2Error(e.to_string()),
            EncryptError::ChaCha20Poly1305Error(e) => {
                UniffiEncryptError::ChaCha20Poly1305Error(e.to_string())
            }
            EncryptError::HkdfInvalidLength(e) => {
                UniffiEncryptError::HkdfInvalidLength(e.to_string())
            }
            EncryptError::TryFromSliceError(e) => {
                UniffiEncryptError::TryFromSliceError(e.to_string())
            }
        }
    }
}

#[derive(Debug, Error, uniffi::Error)]
pub enum UniffiDecryptError {
    #[error("Decryption failed")]
    DecryptionFailed,
}

impl From<DecryptError> for UniffiDecryptError {
    fn from(_: DecryptError) -> Self {
        UniffiDecryptError::DecryptionFailed
    }
}

#[derive(Debug, Error, uniffi::Error)]
pub enum UniffiPasswordGeneratorError {
    #[error("Please specify at least one of uppercase, lowercase, number, or symbols.")]
    NoneSelected,
    #[error(
        "You have specified {required} required characters, which exceeds the password length of {length}."
    )]
    TooManyRequired { required: u32, length: u32 },
}

impl From<PasswordGeneratorError> for UniffiPasswordGeneratorError {
    fn from(e: PasswordGeneratorError) -> Self {
        match e {
            PasswordGeneratorError::NoneSelected => UniffiPasswordGeneratorError::NoneSelected,
            PasswordGeneratorError::TooManyRequired { required, length } => {
                UniffiPasswordGeneratorError::TooManyRequired {
                    required: required as u32,
                    length: length as u32,
                }
            }
        }
    }
}

#[derive(Debug, Error, uniffi::Error)]
pub enum UniffiKeygenError {
    #[error("Random number generation failed: {0}")]
    OsRngError(String),
}
