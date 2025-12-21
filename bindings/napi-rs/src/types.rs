use napi::bindgen_prelude::{Buffer, BufferSlice};
use napi_derive::napi;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[napi]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KeyPair {
  pub(crate) encryption_key: Vec<u8>,
  pub(crate) decryption_key: Vec<u8>,
}

#[napi]
impl KeyPair {
  #[napi(constructor)]
  pub fn new(encryption_key: BufferSlice, decryption_key: BufferSlice) -> Self {
    Self {
      encryption_key: encryption_key.to_vec(),
      decryption_key: decryption_key.to_vec(),
    }
  }

  #[napi(getter)]
  pub fn encryption_key(&self) -> Buffer {
    self.encryption_key.clone().into()
  }

  #[napi(getter)]
  pub fn decryption_key(&self) -> Buffer {
    self.decryption_key.clone().into()
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

#[napi]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EncryptedPassword {
  pub(crate) argon2_salt: Vec<u8>,
  pub(crate) hkdf_salt: Vec<u8>,
  pub(crate) kem_nonce: Vec<u8>,
  pub(crate) kem_ciphertext: Vec<u8>,
  pub(crate) password_nonce: Vec<u8>,
  pub(crate) password_ciphertext: Vec<u8>,
}

#[napi]
impl EncryptedPassword {
  #[napi(constructor)]
  pub fn new(
    argon2_salt: BufferSlice,
    hkdf_salt: BufferSlice,
    kem_nonce: BufferSlice,
    kem_ciphertext: BufferSlice,
    password_nonce: BufferSlice,
    password_ciphertext: BufferSlice,
  ) -> Self {
    Self {
      argon2_salt: argon2_salt.to_vec(),
      hkdf_salt: hkdf_salt.to_vec(),
      kem_nonce: kem_nonce.to_vec(),
      kem_ciphertext: kem_ciphertext.to_vec(),
      password_nonce: password_nonce.to_vec(),
      password_ciphertext: password_ciphertext.to_vec(),
    }
  }

  #[napi(getter)]
  pub fn argon2_salt(&self) -> Buffer {
    self.argon2_salt.clone().into()
  }

  #[napi(getter)]
  pub fn hkdf_salt(&self) -> Buffer {
    self.hkdf_salt.clone().into()
  }

  #[napi(getter)]
  pub fn kem_nonce(&self) -> Buffer {
    self.kem_nonce.clone().into()
  }

  #[napi(getter)]
  pub fn kem_ciphertext(&self) -> Buffer {
    self.kem_ciphertext.clone().into()
  }

  #[napi(getter)]
  pub fn password_nonce(&self) -> Buffer {
    self.password_nonce.clone().into()
  }

  #[napi(getter)]
  pub fn password_ciphertext(&self) -> Buffer {
    self.password_ciphertext.clone().into()
  }
}

impl From<harrys_password_manager_core::types::EncryptedPassword> for EncryptedPassword {
  fn from(value: harrys_password_manager_core::types::EncryptedPassword) -> Self {
    EncryptedPassword {
      argon2_salt: value.argon2_salt.clone(),
      hkdf_salt: value.hkdf_salt.clone(),
      kem_nonce: value.kem_nonce.clone(),
      kem_ciphertext: value.kem_ciphertext.to_vec(),
      password_nonce: value.password_nonce.clone(),
      password_ciphertext: value.password_ciphertext.clone(),
    }
  }
}

impl TryFrom<&EncryptedPassword> for harrys_password_manager_core::types::EncryptedPassword {
  type Error = napi::Error;

  fn try_from(value: &EncryptedPassword) -> napi::Result<Self> {
    let kem_ciphertext_fixed: [u8; 1104] =
      value
        .kem_ciphertext
        .clone()
        .try_into()
        .map_err(|v: Vec<u8>| {
          napi::Error::from_reason(format!(
            "Wrong length for kem_ciphertext: Expected 1104 bytes, got {}",
            v.len()
          ))
        })?;

    Ok(harrys_password_manager_core::types::EncryptedPassword {
      argon2_salt: value.argon2_salt.clone().into(),
      hkdf_salt: value.hkdf_salt.clone().into(),
      kem_nonce: value.kem_nonce.clone().into(),
      kem_ciphertext: kem_ciphertext_fixed,
      password_nonce: value.password_nonce.clone().into(),
      password_ciphertext: value.password_ciphertext.clone(),
    })
  }
}

#[napi(object)]
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

#[napi]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EncryptedVaultKey {
  pub(crate) argon2_salt: Vec<u8>,
  pub(crate) vault_key_ciphertext: Vec<u8>,
  pub(crate) vault_key_nonce: Vec<u8>,
}

#[napi]
impl EncryptedVaultKey {
  #[napi(constructor)]
  pub fn new(
    argon2_salt: BufferSlice,
    vault_key_ciphertext: BufferSlice,
    vault_key_nonce: BufferSlice,
  ) -> Self {
    Self {
      argon2_salt: argon2_salt.to_vec(),
      vault_key_ciphertext: vault_key_ciphertext.to_vec(),
      vault_key_nonce: vault_key_nonce.to_vec(),
    }
  }

  #[napi(getter)]
  pub fn argon2_salt(&self) -> Buffer {
    self.argon2_salt.clone().into()
  }

  #[napi(getter)]
  pub fn vault_key_ciphertext(&self) -> Buffer {
    self.vault_key_ciphertext.clone().into()
  }

  #[napi(getter)]
  pub fn vault_key_nonce(&self) -> Buffer {
    self.vault_key_nonce.clone().into()
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

#[napi]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EncryptedDeviceKeyPair {
  pub(crate) wrapping_key: Vec<u8>,
  pub(crate) encryption_key_ciphertext: Vec<u8>,
  pub(crate) encryption_key_nonce: Vec<u8>,
  pub(crate) decryption_key_ciphertext: Vec<u8>,
  pub(crate) decryption_key_nonce: Vec<u8>,
}

#[napi]
impl EncryptedDeviceKeyPair {
  #[napi(constructor)]
  pub fn new(
    wrapping_key: BufferSlice,
    encryption_key_ciphertext: BufferSlice,
    encryption_key_nonce: BufferSlice,
    decryption_key_ciphertext: BufferSlice,
    decryption_key_nonce: BufferSlice,
  ) -> Self {
    Self {
      wrapping_key: wrapping_key.to_vec(),
      encryption_key_ciphertext: encryption_key_ciphertext.to_vec(),
      encryption_key_nonce: encryption_key_nonce.to_vec(),
      decryption_key_ciphertext: decryption_key_ciphertext.to_vec(),
      decryption_key_nonce: decryption_key_nonce.to_vec(),
    }
  }

  #[napi(getter)]
  pub fn wrapping_key(&self) -> Buffer {
    self.wrapping_key.clone().into()
  }

  #[napi(getter)]
  pub fn encryption_key_ciphertext(&self) -> Buffer {
    self.encryption_key_ciphertext.clone().into()
  }

  #[napi(getter)]
  pub fn encryption_key_nonce(&self) -> Buffer {
    self.encryption_key_nonce.clone().into()
  }

  #[napi(getter)]
  pub fn decryption_key_ciphertext(&self) -> Buffer {
    self.decryption_key_ciphertext.clone().into()
  }

  #[napi(getter)]
  pub fn decryption_key_nonce(&self) -> Buffer {
    self.decryption_key_nonce.clone().into()
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
