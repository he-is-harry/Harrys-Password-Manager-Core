use argon2::Argon2;
use chacha20poly1305::aead::{Aead, AeadMutInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use fips203_rust::types::{CipherText, DecapsKey, EncapsKey};
use fips203_rust::{MlKem, MlKemParams::MlKem768};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::{Rng, TryRngCore};
use sha3::{Digest, Sha3_256};
use std::cmp::max;
use zeroize::Zeroizing;

use crate::errors::{DecryptError, EncryptError, PasswordGeneratorError};
#[cfg(feature = "foreign")]
use crate::types::{EncryptedDeviceKeyPair, EncryptedVaultKey};
use crate::types::{EncryptedPassword, KeyPair, PasswordGeneratorOptions};

const LOWERCASE_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const NUMBERS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

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
    #[allow(deprecated)]
    // generic-array seems to have deprecated from_slice in 0.14, we need to wait for chacha20poly1305 to update
    let kem_aead = ChaCha20Poly1305::new(Key::from_slice(&*argon2_key));
    let kem_ciphertext_bytes = Zeroizing::new(kem_ciphertext.into_bytes());
    #[allow(deprecated)]
    let kem_ciphertext_result =
        kem_aead.encrypt(Nonce::from_slice(&kem_nonce), kem_ciphertext_bytes.as_ref())?;
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
    #[allow(deprecated)]
    let pw_aead = ChaCha20Poly1305::new(Key::from_slice(&*hkdf_key));
    #[allow(deprecated)]
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
    // For ML-KEM-768, k = 3, and the dk must be 768k + 96 = 2400 bytes
    if kem_private_key.len() != 2400 {
        return Err(DecryptError);
    }

    // FIPS 203 check: SHA3-256(dk[384k : 768k + 32]) == dk[768k + 32 : 768k + 64]
    let mut hasher = Sha3_256::new();
    hasher.update(&kem_private_key[1152..2336]);
    let hash = hasher.finalize();
    #[allow(deprecated)]
    if hash.as_slice() != &kem_private_key[2336..2368] {
        return Err(DecryptError);
    }

    // 1. Derive Argon2id key from master password
    let argon2 = Argon2::default();
    let mut argon2_key = Zeroizing::new([0u8; 32]);
    let _ = argon2.hash_password_into(
        master_password,
        &encrypted_data.argon2_salt,
        &mut *argon2_key,
    );

    // 2. AEAD decrypt KEM ciphertext using Argon2id key
    #[allow(deprecated)]
    let mut kem_aead = ChaCha20Poly1305::new(Key::from_slice(&*argon2_key));
    let mut kem_ciphertext = Zeroizing::new(encrypted_data.kem_ciphertext.to_vec());
    #[allow(deprecated)]
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
    let shared_secret = kem.decaps(
        &DecapsKey::from_slice(kem_private_key),
        &CipherText::from_slice(&kem_ciphertext[0..1088]),
    );

    // 4. Derive HKDF key from shared secret
    let shared_secret_bytes = Zeroizing::new(shared_secret.into_bytes());
    let hk = Hkdf::<Sha3_256>::new(Some(&encrypted_data.hkdf_salt), &*shared_secret_bytes);
    let mut hkdf_key = Zeroizing::new([0u8; 32]);
    let _ = hk.expand(b"password-encryption", &mut *hkdf_key);

    // 5. AEAD decrypt actual password using HKDF key
    #[allow(deprecated)]
    let pw_aead = ChaCha20Poly1305::new(Key::from_slice(&*hkdf_key));
    #[allow(deprecated)]
    let actual_password = pw_aead
        .decrypt(
            Nonce::from_slice(&encrypted_data.password_nonce),
            encrypted_data.password_ciphertext.as_ref(),
        )
        .map(|password_vec| Zeroizing::new(password_vec))
        .map_err(|_| DecryptError);

    actual_password
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

    let mut password_chars = Vec::with_capacity(length as usize);
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
    while password_chars.len() < length as usize {
        password_chars.push(charset[rng.random_range(0..charset.len())]);
    }

    // Shuffle the password to randomize the positions of the minimum required characters
    password_chars.shuffle(&mut rng);

    Ok(Zeroizing::new(
        String::from_utf8(password_chars).expect("Invalid UTF-8 character"),
    ))
}

#[cfg(feature = "foreign")]
pub(crate) fn generate_encrypted_vault_key_internal(
    master_password: &[u8],
) -> Result<EncryptedVaultKey, EncryptError> {
    // 1. Generate 32 bytes random vault key
    let mut vault_key = Zeroizing::new([0u8; 32]);
    OsRng.try_fill_bytes(&mut *vault_key)?;

    // 2. Generate salt for Argon2id
    let mut argon2_salt = vec![0u8; 16];
    OsRng.try_fill_bytes(&mut argon2_salt)?;

    // 3. Argon2id hash of master password using salt to get key
    let argon2 = Argon2::default();
    let mut argon2_key = Zeroizing::new([0u8; 32]);
    argon2.hash_password_into(master_password, &argon2_salt, &mut *argon2_key)?;

    // 4. Generate random nonce for vault key ciphertext
    let mut vault_key_nonce = vec![0u8; 12];
    OsRng.try_fill_bytes(&mut vault_key_nonce)?;

    // 5. AEAD encrypt the vault key with nonce and Argon2id key
    let aead = ChaCha20Poly1305::new(Key::from_slice(&*argon2_key));
    let vault_key_ciphertext =
        aead.encrypt(Nonce::from_slice(&vault_key_nonce), vault_key.as_ref())?;

    // 6. Return object containing salt, encrypted output, and nonce
    Ok(EncryptedVaultKey {
        argon2_salt,
        vault_key_ciphertext,
        vault_key_nonce,
    })
}

#[cfg(feature = "foreign")]
pub(crate) fn decrypt_vault_key_internal(
    master_password: &[u8],
    encrypted_vault_key: &EncryptedVaultKey,
) -> Result<Zeroizing<Vec<u8>>, DecryptError> {
    // 1. Derive Argon2id key from master password
    let argon2 = Argon2::default();
    let mut argon2_key = Zeroizing::new([0u8; 32]);
    let _ = argon2.hash_password_into(
        master_password,
        &encrypted_vault_key.argon2_salt,
        &mut *argon2_key,
    );

    // 2. AEAD decrypt vault key ciphertext using Argon2id key
    let aead = ChaCha20Poly1305::new(Key::from_slice(&*argon2_key));
    let vault_key = aead
        .decrypt(
            Nonce::from_slice(&encrypted_vault_key.vault_key_nonce),
            encrypted_vault_key.vault_key_ciphertext.as_ref(),
        )
        .map(|vault_key_vec| Zeroizing::new(vault_key_vec))
        .map_err(|_| DecryptError);

    vault_key
}

#[cfg(feature = "foreign")]
pub(crate) fn generate_encrypted_device_keys_internal()
-> Result<EncryptedDeviceKeyPair, EncryptError> {
    // 1. Generate KEM key pair
    let kem = MlKem::new(MlKem768);
    let (encryption_key, decryption_key) = kem.keygen()?;

    // 2. Generate random wrapping key
    let mut wrapping_key = Zeroizing::new([0u8; 32]);
    OsRng.try_fill_bytes(&mut *wrapping_key)?;

    // 3. Generate nonces
    let mut encryption_key_nonce = vec![0u8; 12];
    OsRng.try_fill_bytes(&mut encryption_key_nonce)?;
    let mut decryption_key_nonce = vec![0u8; 12];
    OsRng.try_fill_bytes(&mut decryption_key_nonce)?;

    // 4. Encrypt keys
    let aead = ChaCha20Poly1305::new(Key::from_slice(&*wrapping_key));

    let encryption_key_bytes = Zeroizing::new(encryption_key.into_bytes());
    let decryption_key_bytes = Zeroizing::new(decryption_key.into_bytes());

    let encryption_key_ciphertext = aead.encrypt(
        Nonce::from_slice(&encryption_key_nonce),
        encryption_key_bytes.as_ref(),
    )?;
    let decryption_key_ciphertext = aead.encrypt(
        Nonce::from_slice(&decryption_key_nonce),
        decryption_key_bytes.as_ref(),
    )?;

    Ok(EncryptedDeviceKeyPair {
        wrapping_key: wrapping_key.to_vec(),
        encryption_key_ciphertext,
        encryption_key_nonce,
        decryption_key_ciphertext,
        decryption_key_nonce,
    })
}

#[cfg(feature = "foreign")]
pub(crate) fn decrypt_device_key_internal(
    wrapping_key: &[u8],
    key_ciphertext: &[u8],
    key_nonce: &[u8],
) -> Result<Zeroizing<Vec<u8>>, DecryptError> {
    let aead = ChaCha20Poly1305::new(Key::from_slice(wrapping_key));

    let decrypted_key = aead
        .decrypt(Nonce::from_slice(key_nonce), key_ciphertext)
        .map(|decrypted_key_vec| Zeroizing::new(decrypted_key_vec))
        .map_err(|_| DecryptError);

    decrypted_key
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

    #[test]
    #[cfg(feature = "foreign")]
    fn test_generate_encrypted_vault_key() {
        let master_password = b"master password";
        let encrypted_key = generate_encrypted_vault_key_internal(master_password)
            .expect("vault key generation should not fail");

        assert_eq!(encrypted_key.argon2_salt.len(), 16);
        assert_eq!(encrypted_key.vault_key_nonce.len(), 12);
        // Ciphertext length = 32 (key) + 16 (tag) = 48
        assert_eq!(encrypted_key.vault_key_ciphertext.len(), 48);

        // Verify we can decrypt it
        let argon2 = Argon2::default();
        let mut argon2_key = Zeroizing::new([0u8; 32]);
        argon2
            .hash_password_into(
                master_password,
                &encrypted_key.argon2_salt,
                &mut *argon2_key,
            )
            .expect("argon2 hashing should not fail");

        let aead = ChaCha20Poly1305::new(Key::from_slice(&*argon2_key));
        let decrypted_key = aead
            .decrypt(
                Nonce::from_slice(&encrypted_key.vault_key_nonce),
                encrypted_key.vault_key_ciphertext.as_ref(),
            )
            .expect("decryption should not fail");

        assert_eq!(decrypted_key.len(), 32);
    }

    #[test]
    #[cfg(feature = "foreign")]
    fn test_vault_key_roundtrip() {
        let master_password = b"master password";
        let encrypted_key = generate_encrypted_vault_key_internal(master_password)
            .expect("vault key generation should not fail");

        let decrypted_key = decrypt_vault_key_internal(master_password, &encrypted_key)
            .expect("authentication should not fail");

        assert_eq!(decrypted_key.len(), 32);

        // Test with wrong password
        let wrong_password = b"wrong password";
        let result = decrypt_vault_key_internal(wrong_password, &encrypted_key);
        assert!(matches!(result, Err(DecryptError)));
    }
    #[test]
    #[cfg(feature = "foreign")]
    fn test_device_keys_roundtrip() {
        let encrypted_keys = generate_encrypted_device_keys_internal()
            .expect("device key generation should not fail");

        assert_eq!(encrypted_keys.wrapping_key.len(), 32);

        let encryption_key = decrypt_device_key_internal(
            &encrypted_keys.wrapping_key,
            &encrypted_keys.encryption_key_ciphertext,
            &encrypted_keys.encryption_key_nonce,
        )
        .expect("device key decryption should not fail");

        let decryption_key = decrypt_device_key_internal(
            &encrypted_keys.wrapping_key,
            &encrypted_keys.decryption_key_ciphertext,
            &encrypted_keys.decryption_key_nonce,
        )
        .expect("device key decryption should not fail");

        // Verify keys work by encrypting/decrypting a password
        let master_password = b"master password";
        let user_password = b"secret";

        let encrypted_password =
            encrypt_password_internal(master_password, &encryption_key, user_password)
                .expect("encryption with derived key should not fail");
        let decrypted_password =
            decrypt_password_internal(master_password, &decryption_key, &encrypted_password)
                .expect("decryption with derived key should not fail");

        assert_eq!(user_password, decrypted_password.as_slice());
    }

    #[test]
    fn test_decrypt_password_kem_key_length_check() {
        let key_pair = keygen_internal().expect("random generation for key should not fail");
        let master_password = b"master password";
        let user_password = b"secret";
        let encrypted_password =
            encrypt_password_internal(master_password, &key_pair.encryption_key, user_password)
                .expect("encryption should not fail");

        let result = decrypt_password_internal(
            master_password,
            &key_pair.encryption_key,
            &encrypted_password,
        );

        assert!(matches!(result, Err(DecryptError)));
    }

    #[test]
    fn test_decrypt_password_kem_key_hash_check() {
        let key_pair = keygen_internal().expect("random generation for key should not fail");
        let master_password = b"master password";
        let user_password = b"secret";
        let encrypted_password =
            encrypt_password_internal(master_password, &key_pair.encryption_key, user_password)
                .expect("encryption should not fail");

        // Corrupt the private key in the range [1152..2336]
        // This should cause the hash check to fail
        let mut corrupted_decryption_key = key_pair.decryption_key.clone();
        corrupted_decryption_key[1200] ^= 0xFF;

        let result = decrypt_password_internal(
            master_password,
            &corrupted_decryption_key,
            &encrypted_password,
        );

        assert!(matches!(result, Err(DecryptError)));
    }
}
