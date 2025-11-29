use thiserror::Error;

#[derive(Debug, Error)]
pub enum EncryptError {
    #[error("Random number generation failed")]
    OsRngError(#[from] rand::rand_core::OsError),
    #[error("Failed to generate hash of password")]
    Argon2Error(#[from] argon2::Error),
    #[error("Failed to perform AEAD encryption")]
    ChaCha20Poly1305Error(#[from] chacha20poly1305::Error),
    #[error("HMAC key derivation invalid length")]
    HkdfInvalidLength(#[from] hkdf::InvalidLength),
    #[error("Failed to convert to array from slice")]
    TryFromSliceError(#[from] std::array::TryFromSliceError),
}

#[derive(Debug, Error)]
#[error("Decryption failed")]
pub struct DecryptError;

#[derive(Debug, Error)]
pub enum PasswordGeneratorError {
    #[error("Please specify at least one of uppercase, lowercase, number, or symbols.")]
    NoneSelected, // no options selected
    #[error(
        "You have specified {required} required characters, which exceeds the password length of {length}."
    )]
    TooManyRequired {
        // too many required chars vs length
        required: u32,
        length: u32,
    },
}
