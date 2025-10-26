#[derive(Debug)]
pub enum EncryptError {
    OsRngError(rand::rand_core::OsError),
	Argon2Error(argon2::Error),
    ChaCha20Poly1305Error(chacha20poly1305::Error),
    HkdfInvalidLength(hkdf::InvalidLength),
    TryFromSliceError(std::array::TryFromSliceError),
}

impl From<rand::rand_core::OsError> for EncryptError {
    fn from(err: rand::rand_core::OsError) -> EncryptError {
        EncryptError::OsRngError(err)
    }
}

impl From<argon2::Error> for EncryptError {
    fn from(err: argon2::Error) -> EncryptError {
        EncryptError::Argon2Error(err)
    }
}

impl From<chacha20poly1305::Error> for EncryptError {
    fn from(err: chacha20poly1305::Error) -> EncryptError {
        EncryptError::ChaCha20Poly1305Error(err)
    }
}

impl From<hkdf::InvalidLength> for EncryptError {
    fn from(err: hkdf::InvalidLength) -> EncryptError {
        EncryptError::HkdfInvalidLength(err)
    }
}

impl From<std::array::TryFromSliceError> for EncryptError {
    fn from(err: std::array::TryFromSliceError) -> EncryptError {
        EncryptError::TryFromSliceError(err)
    }
}

impl std::fmt::Display for EncryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptError::OsRngError(_os_error) => {
                write!(f, "Random number generation failed")
            }
            EncryptError::Argon2Error(_argon2_error) => {
                write!(f, "Failed to generate hash of password")
            }
            EncryptError::ChaCha20Poly1305Error(_chacha20_error) => {
                write!(f, "Failed to perform AEAD encryption")
            }
            EncryptError::HkdfInvalidLength(_hkdf_error) => {
                write!(f, "HMAC key derivation invalid length")
            }
            EncryptError::TryFromSliceError(_try_slice_error) => {
                write!(f, "Failed to convert to array from slice")
            }
        }
    }
}

#[derive(Debug)]
pub struct DecryptError;

impl std::fmt::Display for DecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Decryption failed")
    }
}

impl std::error::Error for DecryptError {}

#[derive(Debug)]
pub enum PasswordGeneratorError {
    NoneSelected,       // no options selected
    TooManyRequired {   // too many required chars vs length
        required: usize,
        length: usize,
    },
}

impl std::fmt::Display for PasswordGeneratorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PasswordGeneratorError::NoneSelected => {
                write!(f, "Please specify at least one of uppercase, lowercase, number, or symbols.")
            }
            PasswordGeneratorError::TooManyRequired { required, length } => {
                write!(f, "You have specified {required} required characters, which exceeds the password length of {length}.")
            }
        }
    }
}
