# Harry's Password Manager Core

The cryptographic core library behind Harry's Password Manager ecosystem. This library provides the core security primitives used across the [Mobile App (React Native / Expo)](https://github.com/he-is-harry/Harrys-Password-Manager-App), [Desktop App (Electron)](https://github.com/he-is-harry/Harrys-Password-Manager-Desktop), and [CLI](https://github.com/he-is-harry/Harrys-Password-Manager-CLI).

## Overview

`harrys-password-manager-core` is written in Rust to ensure high performance and memory safety. It handles all sensitive cryptographic operations, including key generation, password encryption/decryption, and secure password generation.

### Key Features

- **Robust Key Management**: Generation and handling of high-entropy key pairs.
- **Secure Password Encryption**: Post-quantum encryption for your sensitive data.
- **Dynamic Password Generation**: Highly configurable and secure password generator.
- **Multi-Platform Support**: Seamlessly integrates with Node.js and React Native through specialized bindings.

## Security & Cryptography

The library implements its password encryption using a hybrid symmetric and asymmetric approach to ensure post-quantum security. The following cryptographic primitives are used:

- **ML-KEM (FIPS 203)**: A post-quantum secure Key Encapsulation Mechanism (Module-Lattice-based Key Encapsulation Mechanism) used for secure key exchange, ensuring security even against future quantum computing threats.
- **Argon2id**: A memory-hard password hashing function used to derive strong encryption keys from master passwords, providing superior protection against both GPU and ASIC-based brute-force attacks.
- **HKDF (HMAC-based Key Derivation Function)**: Used following key encapsulation to derive session-specific keys, ensuring that the final encryption keys have maximum entropy.
- **ChaCha20-Poly1305**: A high-speed Authenticated Encryption with Associated Data (AEAD) algorithm used for symmetric encryption. It provides both data confidentiality and authenticity (integrity) verification.

Additionally, the library attempts to achieve side-channel attack resistance by using constant-time operations provided by the underlying cryptographic libraries and avoiding intermediate returns and error messages in decryption logic. We also utilize the `zeroize` library to securely clear sensitive data from memory as soon as it is no longer needed.

However, it is important to note that when using the Uniffi or Napi bindings, data is often copied as it passes between memory boundaries (e.g., from Rust to JavaScript), which can limit the effectiveness of zeroizing.

## Basic Functionality

The core library exposes several high-level functions:

- `keygen()`: Generates a new `KeyPair` containing a ML-KEM public and private key.
- `encrypt_password(master_password, encryption_key, actual_password)`: Encrypts a password using a master password and an encryption key.
- `decrypt_password(master_password, kem_private_key, encrypted_data)`: Decrypts an encrypted password and a decryption key.
- `generate_password(options)`: Generates a secure, random password based on provided [`PasswordGeneratorOptions`](https://github.com/he-is-harry/Harrys-Password-Manager-Core/blob/main/src/types.rs#L19).

## The `foreign` Feature Flag

The `foreign` feature flag enables additional functionality that may not be available in foreign languages and environments. Since equivalent ML-KEM or ChaCha20Poly1305 implementations may not be available, this feature provides the following additional functionality:

- **Vault & Device Key Management**: Functions to generate and decrypt vault keys and device-specific public and private keys.
- **Network Security**: Primitives for generating shared secrets and encrypting/decrypting network packets.

This feature is typically enabled for our binding layers to provide a comprehensive and consistent API to the host applications.

## Bindings

To support our diverse application stack, we provide the following bindings for different environments:

### Node.js Bindings (`napi-rs`)

Used in the **Desktop App (Electron)** and can be used in other Node.js environments.
Located in [`bindings/napi-rs`](https://github.com/he-is-harry/Harrys-Password-Manager-Core/tree/main/bindings/napi-rs). Click on that folder to check out how to use Harry's Password Manager Core in Node.js.

### Native Bindings (`uniffi`)

Used in the **Mobile App (Expo / React Native)**.
Located in [`bindings/uniffi`](https://github.com/he-is-harry/Harrys-Password-Manager-Core/tree/main/bindings/uniffi). Check out the [`harrys-password-manager-core`](https://github.com/he-is-harry/Harrys-Password-Manager-App/tree/main/modules/harrys-password-manager-core) module in Harry's Password Manager App to see how to use Harry's Password Manager Core in React Native.

## Development Guide

### Compiling `napi-rs` Bindings

To compile the Node.js bindings, navigate to the `bindings/napi-rs` directory and run:

```bash
pnpm install
pnpm build
```

The output will be available as a native addon in the same directory.

### Compiling `uniffi` Bindings

The Uniffi bindings support compiling to several native environments. However, we only currently compile to React Native, using the [uniffi-bindgen-react-native](https://github.com/jhugman/uniffi-bindgen-react-native) project. To compile the bindings for React Native, reference the [Harry's Password Manager App repository](https://github.com/he-is-harry/Harrys-Password-Manager-App), specifically `modules/harrys-password-manager-core`. In that repository, we have a easy to use script to compile the bindings for React Native.

To build these bindings:
1. Clone the [Harry's Password Manager App repository](https://github.com/he-is-harry/Harrys-Password-Manager-App) and this Harry's Password Manager Core repository.
   > **Note:** Our current setup requires that both the `Harrys-Password-Manager-App` and `Harrys-Password-Manager-Core` directories are located within the same parent directory for the build scripts to function correctly.
   >
   > ```text
   > parent_directory/
   > ├── Harrys-Password-Manager-App/
   > └── Harrys-Password-Manager-Core/
   > ```
``` bash
git clone https://github.com/he-is-harry/Harrys-Password-Manager-App.git
git clone https://github.com/he-is-harry/Harrys-Password-Manager-Core.git
```
2. Navigate to the `Harrys-Password-Manager-App` directory.
3. Run the build script, and optionally add the `--release` flag for a release build:
```bash
./scripts/build_core.sh # add --release for release build
```
