#[cfg(feature = "wasm")]
pub mod wasm_exports {
    use wasm_bindgen::prelude::*;
    use crate::internal::{
        decrypt_password_internal, encrypt_password_internal, generate_encrypted_vault_key_internal,
        generate_password_internal, keygen_internal,
    };
    use crate::types::{
        DecryptedPassword, EncryptedPassword, EncryptedVaultKey, GeneratedPassword, KeyPair,
        PasswordGeneratorOptions,
    };

    #[wasm_bindgen]
    pub fn keygen() -> Result<KeyPair, JsError> {
        keygen_internal().map_err(|e| wasm_bindgen::JsError::new(&e.to_string()))
    }

    #[wasm_bindgen]
    pub fn encrypt_password(
        master_password: &[u8],
        encryption_key: &[u8],
        actual_password: &[u8],
    ) -> Result<EncryptedPassword, JsError> {
        encrypt_password_internal(master_password, encryption_key, actual_password)
            .map_err(|e| wasm_bindgen::JsError::new(&e.to_string()))
    }

    #[wasm_bindgen]
    pub fn decrypt_password(
        master_password: &[u8],
        kem_private_key: &[u8],
        encrypted_data: &EncryptedPassword,
    ) -> Result<DecryptedPassword, JsError> {
        decrypt_password_internal(master_password, kem_private_key, encrypted_data)
            .map(|password| DecryptedPassword {
                password: password.to_vec(),
            })
            .map_err(|e| wasm_bindgen::JsError::new(&e.to_string()))
    }

    #[wasm_bindgen]
    pub fn generate_password(
        options: Option<PasswordGeneratorOptions>,
    ) -> Result<GeneratedPassword, JsError> {
        generate_password_internal(options)
            .map(|password| GeneratedPassword {
                password: password.to_string(),
            })
            .map_err(|e| wasm_bindgen::JsError::new(&e.to_string()))
    }

    #[wasm_bindgen]
    pub fn generate_encrypted_vault_key(master_password: &[u8]) -> Result<EncryptedVaultKey, JsError> {
        generate_encrypted_vault_key_internal(master_password)
            .map_err(|e| wasm_bindgen::JsError::new(&e.to_string()))
    }
}

