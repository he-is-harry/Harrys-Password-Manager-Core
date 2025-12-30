# Harry's Password Manager Core (Node.js Bindings)

Node.js bindings for the Core cryptographic library of Harry's Password Manager, built with [`napi-rs`](https://napi.rs/). These bindings are primarily used in the [Harry's Password Manager Desktop application](https://github.com/he-is-harry/Harrys-Password-Manager-Desktop) to perform secure cryptographic operations.

## Installation

This library is not currently published to npm. To use it in your project, you must clone this repository to install it, similar to how it is done in [Harry's Password Manager Desktop](https://github.com/he-is-harry/Harrys-Password-Manager-Desktop).

1. Clone this repository
```bash
git clone https://github.com/he-is-harry/Harrys-Password-Manager-Core.git
```
2. In your project, using your favourite package manager (pnpm, npm, yarn, etc.) install the package
```bash
pnpm install path/to/Harrys-Password-Manager-Core/bindings/napi-rs
```

## Usage

The package provides direct access to the high-performance Rust cryptographic functions.

### Example: Basic Encryption & Decryption

```typescript
import { 
  keygen, 
  encryptPassword, 
  decryptPassword 
} from '@he-is-harry/harrys-password-manager-core-napi';

const masterPassword = Buffer.from('my-secure-master-password');
const actualPassword = Buffer.from('the-password-to-store');

// 1. Generate keys
const keypair = keygen();

// 2. Encrypt
const encryptedData = encryptPassword(
  masterPassword, 
  keypair.encryptionKey, 
  actualPassword
);

// 3. Decrypt
const decryptedBytes = decryptPassword(
  masterPassword, 
  keypair.decryptionKey, 
  encryptedData
);

console.log(decryptedBytes.toString()); // 'the-password-to-store'
```

## Development Guide

### Building the Package
To build the native addon for your current platform:

```bash
pnpm install
pnpm build
```

The build process will generate a `.node` binary in the root directory and update the TypeScript definitions.

### Testing
We use [ava](https://github.com/avajs/ava) for testing the native bindings.

```bash
pnpm test
```
