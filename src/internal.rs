use argon2::Argon2;
use chacha20poly1305::aead::{Aead, AeadMutInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use fips203_rust::types::{CipherText, DecapsKey, EncapsKey};
use fips203_rust::{MlKem, MlKemParams::MlKem768};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::{Rng, TryRngCore};
use sha3::Sha3_256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use std::cmp::max;

use crate::errors::{DecryptError, EncryptError, PasswordGeneratorError};

const LOWERCASE_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const NUMBERS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

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

pub(crate) fn keygen_internal() -> Result<KeyPair, rand::rand_core::OsError> {
    let kem = MlKem::new(MlKem768);
    let (encryption_key, decryption_key) = kem.keygen()?;

    Ok(KeyPair {
        encryption_key: encryption_key.into_bytes(),
        decryption_key: decryption_key.into_bytes(),
    })
}

pub(crate) fn encrypt_password_internal(
    master_password: &[u8],
    encryption_key: &[u8],
    actual_password: &[u8],
) -> Result<EncryptedPassword, EncryptError> {
    // 1. Generate salt for Argon2id
    let mut argon2_salt = vec![0u8; 16];
    OsRng.try_fill_bytes(&mut argon2_salt)?;

    // 2. Generate salt for HKDF
    let mut hkdf_salt = vec![0u8; 16];
    OsRng.try_fill_bytes(&mut hkdf_salt)?;

    // 3. Generate shared secret key and ciphertext using ML-KEM
    let kem = MlKem::new(MlKem768);
    let (shared_secret, kem_ciphertext) = kem.encaps(&EncapsKey::from_slice(encryption_key))?;

    // 4. Argon2id hash of master password using salt to get key
    let argon2 = Argon2::default();
    let mut argon2_key = Zeroizing::new([0u8; 32]);
    argon2.hash_password_into(master_password, &argon2_salt, &mut *argon2_key)?;

    // 5. Generate random nonce for KEM ciphertext
    let mut kem_nonce = vec![0u8; 12];
    OsRng.try_fill_bytes(&mut kem_nonce)?;

    // 6. AEAD encrypt the KEM ciphertext with nonce and Argon2id key
    let kem_aead = ChaCha20Poly1305::new(Key::from_slice(&*argon2_key));
    let kem_ciphertext_bytes = Zeroizing::new(kem_ciphertext.into_bytes());
    let kem_ciphertext_result = kem_aead
        .encrypt(Nonce::from_slice(&kem_nonce), kem_ciphertext_bytes.as_ref())?;
	let kem_ciphertext_enc: [u8; 1104] = kem_ciphertext_result.as_slice().try_into()?;

    // 7. Create HKDF data encryption key from shared secret key
    let shared_secret_bytes = Zeroizing::new(shared_secret.into_bytes());
    let hk = Hkdf::<Sha3_256>::new(Some(&hkdf_salt), &*shared_secret_bytes);
    let mut hkdf_key = Zeroizing::new([0u8; 32]);
    hk.expand(b"password-encryption", &mut *hkdf_key)?;

    // 8. Generate random nonce for actual user password
    let mut password_nonce = vec![0u8; 12];
    OsRng.try_fill_bytes(&mut password_nonce)?;

    // 9. AEAD encrypt the user password with nonce and HKDF key
    let pw_aead = ChaCha20Poly1305::new(Key::from_slice(&*hkdf_key));
    let password_ciphertext =
        pw_aead.encrypt(Nonce::from_slice(&password_nonce), actual_password)?;

    // 10. Return object containing salts, encrypted outputs, and nonces
    Ok(EncryptedPassword {
        argon2_salt,
        hkdf_salt,
        kem_nonce,
        kem_ciphertext: kem_ciphertext_enc,
        password_nonce,
        password_ciphertext,
    })
}

pub(crate) fn decrypt_password_internal(
    master_password: &[u8],
    kem_private_key: &[u8],
    encrypted_data: &EncryptedPassword,
) -> Result<Zeroizing<Vec<u8>>, DecryptError> {
    // 1. Derive Argon2id key from master password
    let argon2 = Argon2::default();
    let mut argon2_key = Zeroizing::new([0u8; 32]);
    let _ = argon2.hash_password_into(
        master_password,
        &encrypted_data.argon2_salt,
        &mut *argon2_key,
    );

    // 2. AEAD decrypt KEM ciphertext using Argon2id key
    let mut kem_aead = ChaCha20Poly1305::new(Key::from_slice(&*argon2_key));
    let mut kem_ciphertext = Zeroizing::new(encrypted_data.kem_ciphertext.to_vec());
    let _ = kem_aead.decrypt_in_place(
        Nonce::from_slice(&encrypted_data.kem_nonce),
        b"",
        &mut *kem_ciphertext,
    );

    // 3. Decapsulate shared secret using ML-KEM private key
    let kem = MlKem::new(MlKem768);
    // Since AEAD will always validate the encryption, we can be sure that the size will be exactly 1088 bytes
    // - This fact derives from the source code of ChaCha20Poly1305 where it will not run the stream cipher
    // if the verification fails
    let shared_secret = kem.decaps(&DecapsKey::from_slice(kem_private_key), &CipherText::from_slice(&kem_ciphertext[0..1088]));

    // 4. Derive HKDF key from shared secret
    let shared_secret_bytes = Zeroizing::new(shared_secret.into_bytes());
    let hk = Hkdf::<Sha3_256>::new(Some(&encrypted_data.hkdf_salt), &*shared_secret_bytes);
    let mut hkdf_key = Zeroizing::new([0u8; 32]);
    let _ = hk.expand(b"password-encryption", &mut *hkdf_key);

    // 5. AEAD decrypt actual password using HKDF key
    let pw_aead = ChaCha20Poly1305::new(Key::from_slice(&*hkdf_key));
    let actual_password = pw_aead
        .decrypt(
            Nonce::from_slice(&encrypted_data.password_nonce),
            encrypted_data.password_ciphertext.as_ref(),
        )
        .map(|password_vec| Zeroizing::new(password_vec))
        .map_err(|_| DecryptError);

    actual_password
}

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

pub(crate) fn generate_password_internal(
    options: Option<PasswordGeneratorOptions>,
) -> Result<Zeroizing<String>, PasswordGeneratorError> {
    let options = options.unwrap_or_default();

    let length_option = options.length;
    let include_numbers = options.include_numbers.unwrap_or(true);
    let include_uppercase = options.include_uppercase.unwrap_or(true);
    let include_lowercase = options.include_lowercase.unwrap_or(true);
    let include_symbols = options.include_symbols.unwrap_or(true);
    let min_numbers = options.min_numbers.unwrap_or(1);
    let min_uppercase = options.min_uppercase.unwrap_or(1);
    let min_lowercase = options.min_lowercase.unwrap_or(1);
    let min_symbols = options.min_symbols.unwrap_or(1);

    let mut charset = Vec::new();
    let mut min_chars = 0;
    if include_numbers {
        charset.extend_from_slice(NUMBERS);
        min_chars += min_numbers;
    }
    if include_uppercase {
        charset.extend_from_slice(UPPERCASE_CHARS);
        min_chars += min_uppercase;
    }
    if include_lowercase {
        charset.extend_from_slice(LOWERCASE_CHARS);
        min_chars += min_lowercase;
    }
    if include_symbols {
        charset.extend_from_slice(SYMBOLS);
        min_chars += min_symbols;
    }

    // Input validation
    if charset.is_empty() {
        return Err(PasswordGeneratorError::NoneSelected);
    }
    if let Some(length) = length_option
        && min_chars > length
    {
        return Err(PasswordGeneratorError::TooManyRequired {
            required: min_chars,
            length: length,
        });
    }
    // Define the length
    let length = length_option.unwrap_or_else(|| max(12, min_chars));

    let mut password_chars = Vec::with_capacity(length);
    let mut rng = rand::rng();

    // Ensure minimum requirements
    if include_numbers {
        for _ in 0..min_numbers {
            password_chars.push(NUMBERS[rng.random_range(0..NUMBERS.len())]);
        }
    }
    if include_uppercase {
        for _ in 0..min_uppercase {
            password_chars.push(UPPERCASE_CHARS[rng.random_range(0..UPPERCASE_CHARS.len())]);
        }
    }
    if include_lowercase {
        for _ in 0..min_lowercase {
            password_chars.push(LOWERCASE_CHARS[rng.random_range(0..LOWERCASE_CHARS.len())]);
        }
    }
    if include_symbols {
        for _ in 0..min_symbols {
            password_chars.push(SYMBOLS[rng.random_range(0..SYMBOLS.len())]);
        }
    }

    // Fill the rest of the password length
    while password_chars.len() < length {
        password_chars.push(charset[rng.random_range(0..charset.len())]);
    }

    // Shuffle the password to randomize the positions of the minimum required characters
    password_chars.shuffle(&mut rng);

    Ok(Zeroizing::new(String::from_utf8(password_chars).expect("Invalid UTF-8 character")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_password_default() {
        let password =
            generate_password_internal(None).expect("Password generation should not fail");
        assert_eq!(password.len(), 12);
        assert!(password.chars().any(|c| c.is_ascii_digit()));
        assert!(password.chars().any(|c| c.is_ascii_uppercase()));
        assert!(password.chars().any(|c| c.is_ascii_lowercase()));
        assert!(
            password
                .chars()
                .any(|c| SYMBOLS.iter().any(|&s_char| s_char == (c as u8)))
        );
    }

    #[test]
    fn test_generate_password_custom_length() {
        let options = PasswordGeneratorOptions {
            length: Some(20),
            ..Default::default()
        };
        let password =
            generate_password_internal(Some(options)).expect("Password generation should not fail");
        assert_eq!(password.len(), 20);
    }

    #[test]
    fn test_generate_password_no_numbers() {
        let options = PasswordGeneratorOptions {
            include_numbers: Some(false),
            min_numbers: Some(0),
            ..Default::default()
        };
        let password =
            generate_password_internal(Some(options)).expect("Password generation should not fail");
        assert!(!password.chars().any(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_password_min_requirements() {
        let options = PasswordGeneratorOptions {
            length: Some(10),
            include_numbers: Some(true),
            include_uppercase: Some(true),
            include_lowercase: Some(true),
            include_symbols: Some(true),
            min_numbers: Some(2),
            min_uppercase: Some(2),
            min_lowercase: Some(2),
            min_symbols: Some(2),
        };
        let password =
            generate_password_internal(Some(options)).expect("Password generation should not fail");
        assert_eq!(password.len(), 10);

        let num_numbers = password.chars().filter(|c| c.is_ascii_digit()).count();
        let num_uppercase = password.chars().filter(|c| c.is_ascii_uppercase()).count();
        let num_lowercase = password.chars().filter(|c| c.is_ascii_lowercase()).count();
        let num_symbols = password.bytes().filter(|b| SYMBOLS.contains(b)).count();

        assert!(num_numbers >= 2);
        assert!(num_uppercase >= 2);
        assert!(num_lowercase >= 2);
        assert!(num_symbols >= 2);
    }

    #[test]
    fn test_generate_password_mixed_options() {
        let options = PasswordGeneratorOptions {
            length: Some(10),
            include_numbers: Some(true),
            include_uppercase: Some(true),
            include_lowercase: Some(true),
            include_symbols: Some(false),
            min_numbers: Some(1),
            min_uppercase: Some(2),
            min_lowercase: Some(3),
            min_symbols: Some(2),
        };
        let password =
            generate_password_internal(Some(options)).expect("Password generation should not fail");
        assert_eq!(password.len(), 10);

        let num_numbers = password.chars().filter(|c| c.is_ascii_digit()).count();
        let num_uppercase = password.chars().filter(|c| c.is_ascii_uppercase()).count();
        let num_lowercase = password.chars().filter(|c| c.is_ascii_lowercase()).count();

        assert!(num_numbers >= 1);
        assert!(num_uppercase >= 2);
        assert!(num_lowercase >= 3);
        assert!(!password.bytes().any(|b| SYMBOLS.contains(&b)));
    }

    #[test]
    fn test_generate_password_empty_charset() {
        let options = PasswordGeneratorOptions {
            include_numbers: Some(false),
            include_uppercase: Some(false),
            include_lowercase: Some(false),
            include_symbols: Some(false),
            min_numbers: Some(0),
            min_uppercase: Some(0),
            min_lowercase: Some(0),
            min_symbols: Some(0),
            length: Some(10),
        };
        let password = generate_password_internal(Some(options));
        assert!(matches!(
            password,
            Err(PasswordGeneratorError::NoneSelected)
        ));
    }

    #[test]
    fn test_generate_password_too_many_required() {
        let options = PasswordGeneratorOptions {
            include_numbers: Some(true),
            include_uppercase: Some(true),
            include_lowercase: Some(true),
            include_symbols: Some(true),
            min_numbers: Some(2),
            min_uppercase: Some(3),
            min_lowercase: Some(4),
            min_symbols: Some(5),
            length: Some(10),
        };
        let password = generate_password_internal(Some(options));
        assert!(matches!(
            password,
            Err(PasswordGeneratorError::TooManyRequired {
                required: 14,
                length: 10
            })
        ));
    }

    #[test]
    fn test_roundtrip() {
        let key_pair = keygen_internal().expect("random generation for key should not fail");
        let master_password = b"master password";
        let user_password = b"secret";
        let encrypted_password =
            encrypt_password_internal(master_password, &key_pair.encryption_key, user_password)
                .expect("encryption should not fail");
        let decrypted_password = decrypt_password_internal(
            master_password,
            &key_pair.decryption_key,
            &encrypted_password,
        )
        .expect("decryption should not fail");

        assert_eq!(user_password, decrypted_password.as_slice());
    }

    #[test]
    fn test_return_an_error_at_end() {
        let key_pair = keygen_internal().expect("random generation for key should not fail");
        let master_password = b"master password";
        let user_password = b"secret";
        let encrypted_password =
            encrypt_password_internal(master_password, &key_pair.encryption_key, user_password)
                .expect("encryption should not fail");
        let decrypted_password = decrypt_password_internal(
            b"wrong password",
            &key_pair.decryption_key,
            &encrypted_password,
        );

        assert!(matches!(decrypted_password, Err(DecryptError)));
    }
}
