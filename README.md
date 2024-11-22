# ez-web-crypto

![Library Logo](https://github.com/JWally/ez-web-crypto/assets/2482935/0e2faf24-2c5e-416f-b9e3-e75fe2080569)

[![npm version](https://badge.fury.io/js/@justinwwolcott%2Fez-web-crypto.svg)](https://www.npmjs.com/package/@justinwwolcott/ez-web-crypto)
[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg)](https://opensource.org/licenses/ISC)
[![Node.js Version](https://img.shields.io/node/v/@justinwwolcott/ez-web-crypto.svg)](https://nodejs.org/)

A lightweight, type-safe wrapper around the Web Crypto API, providing easy-to-use cryptographic operations for both browser and Node.js environments.

## Features

- 🔐 AES-GCM encryption/decryption
- 🔑 ECDH key exchange and encryption
- ✍️ ECDSA digital signatures
- 🔒 Password-based encryption
- 🌐 HKDF key derivation
- #️⃣ HMAC operations
- 🧮 Cryptographic hashing (SHA-1, SHA-256, SHA-384, SHA-512)
- 📱 Cross-platform compatibility (Browser + Node.js)
- 📘 Full TypeScript support
- 🔄 Flexible key format handling

## Installation

```bash
npm install @justinwwolcott/ez-web-crypto
```

## Usage Examples

### AES Encryption

```typescript
import { AESMakeKey, AESEncrypt, AESDecrypt } from '@justinwwolcott/ez-web-crypto'

// Generate a new AES key
const key = await AESMakeKey()

// Encrypt data
const encrypted = await AESEncrypt(key, btoa('Hello, World!'))

// Decrypt data
const decrypted = await AESDecrypt(key, encrypted.iv, encrypted.ciphertext, true)
console.log(decrypted) // 'Hello, World!'
```

### ECDH Key Exchange and Encryption

```typescript
import { EcMakeCryptKeys, EcEncrypt, EcDecrypt } from '@justinwwolcott/ez-web-crypto'

// Generate key pairs for both parties
const aliceKeys = await EcMakeCryptKeys()
const bobKeys = await EcMakeCryptKeys()

// Alice encrypts message for Bob
const encrypted = await EcEncrypt(aliceKeys.privateKey, bobKeys.publicKey, btoa('Secret message'))

// Bob decrypts message from Alice
const decrypted = await EcDecrypt(bobKeys.privateKey, aliceKeys.publicKey, encrypted.iv, encrypted.ciphertext, true)
```

### Digital Signatures (ECDSA)

```typescript
import { EcMakeSigKeys, EcSignData, EcVerifySig } from '@justinwwolcott/ez-web-crypto'

// Generate signing keys
const keys = await EcMakeSigKeys()

// Sign data
const signature = await EcSignData(keys.privateKey, btoa('Sign this message'))

// Verify signature
const isValid = await EcVerifySig(keys.publicKey, signature, btoa('Sign this message'))
```

### Password-Based Encryption

```typescript
import { PASSWORD_ENCRYPT, PASSWORD_DECRYPT } from '@justinwwolcott/ez-web-crypto'

// Encrypt with password
const encrypted = await PASSWORD_ENCRYPT('myPassword', btoa('Secret data'))

// Decrypt with password
const decrypted = await PASSWORD_DECRYPT('myPassword', encrypted)
```

### HKDF Encryption

```typescript
import { EcMakeCryptKeys, HKDFEncrypt, HKDFDecrypt } from '@justinwwolcott/ez-web-crypto'

// Generate keys
const aliceKeys = await EcMakeCryptKeys()
const bobKeys = await EcMakeCryptKeys()

// Encrypt using HKDF
const encrypted = await HKDFEncrypt(aliceKeys.privateKey, bobKeys.publicKey, btoa('Secret data'))

// Decrypt using HKDF
const decrypted = await HKDFDecrypt(
  bobKeys.privateKey,
  aliceKeys.publicKey,
  encrypted.salt,
  encrypted.iv,
  encrypted.ciphertext,
  true
)
```

### Hashing and HMAC

```typescript
import { HASH, HMAC } from '@justinwwolcott/ez-web-crypto'

// Generate hash
const hash = await HASH('SHA-256', 'Hash this text')

// Generate HMAC
const hmac = await HMAC('secret-key', 'Message to authenticate')
```

## API Reference

### AES Operations

- `AESMakeKey(exportable?: boolean): Promise<Base64String | CryptoKey>`

  - Generates a new AES-GCM key
  - `exportable`: Whether the key should be exportable (default: true)

- `AESEncrypt(key: Base64String | CryptoKey, data: Base64String, nonce?: Base64String): Promise<AESEncryptResult>`

  - Encrypts data using AES-GCM
  - Returns ciphertext and IV

- `AESDecrypt(key: Base64String | CryptoKey, nonce: Base64String, data: Base64String, returnText?: boolean): Promise<string | ArrayBuffer>`
  - Decrypts AES-GCM encrypted data
  - Optional text return format

### ECDH Operations

- `EcMakeCryptKeys(exportable?: boolean): Promise<ECKeyPair>`

  - Generates ECDH key pair for encryption
  - Returns public/private keys in multiple formats

- `EcEncrypt(privateKey: Base64String | CryptoKey, publicKey: Base64String | CryptoKey, data: Base64String): Promise<AESEncryptResult>`

  - Encrypts data using ECDH key exchange
  - Returns encrypted data and IV

- `EcDecrypt(privateKey: Base64String | CryptoKey, publicKey: Base64String | CryptoKey, nonce: Base64String, data: Base64String, returnText?: boolean): Promise<string | ArrayBuffer>`
  - Decrypts ECDH encrypted data

### ECDSA Digital Signatures

- `EcMakeSigKeys(exportable?: boolean): Promise<ECSignatureKeyPair>`
  - Generates ECDSA signing key pair
- `EcSignData(privateKey: Base64String | CryptoKey, data: Base64String): Promise<Base64String>`
  - Signs data using ECDSA
- `EcVerifySig(publicKey: Base64String | CryptoKey, signature: Base64String, data: Base64String): Promise<boolean>`
  - Verifies ECDSA signature

### HKDF Operations

- `HKDFEncrypt(privateKey: Base64String | CryptoKey, publicKey: Base64String | CryptoKey, data: Base64String, ivLength?: number, saltLength?: number): Promise<HKDFEncryptResult>`
  - Encrypts data using HKDF key derivation
- `HKDFDecrypt(privateKey: Base64String | CryptoKey, publicKey: Base64String | CryptoKey, salt: Base64String, iv: Base64String, data: Base64String, returnText?: boolean): Promise<string | ArrayBuffer>`
  - Decrypts HKDF encrypted data

### Password Operations

- `PASSWORD_ENCRYPT(password: string, data: Base64String): Promise<Base64String>`
  - Encrypts data using password-based encryption
- `PASSWORD_DECRYPT(password: string, data: Base64String): Promise<string>`
  - Decrypts password-protected data

### Hashing Operations

- `HASH(algorithm: HashAlgorithm, data: string, length?: number): Promise<Base64String>`
  - Generates cryptographic hash
  - Supports SHA-1, SHA-256, SHA-384, SHA-512
- `HMAC(secret: string, data: string): Promise<HexString>`
  - Generates HMAC using SHA-256

## Type Definitions

```typescript
type Base64String = string
type HexString = string
type HashAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512'

interface AESEncryptResult {
  ciphertext: Base64String
  iv: Base64String
}

interface HKDFEncryptResult {
  ciphertext: Base64String
  salt: Base64String
  iv: Base64String
}

interface ECKeyPair {
  publicKey: Base64String
  privateKey: Base64String | CryptoKey
  rawPublicKey: Base64String
  rawPublicKeyLite: Base64String
  jwkPublicKey?: JsonWebKey
  jwkPrivateKey?: JsonWebKey
}
```

## Environment Support

- Node.js ≥ 14.0.0
- Modern browsers with Web Crypto API support
- Full TypeScript support included

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Security Notes

- All cryptographic operations use standard Web Crypto API implementations
- Keys can be handled in both exportable and non-exportable formats
- Password-based encryption uses multiple rounds of hashing for key strengthening
- All operations are async and type-safe

## License

This project is licensed under the ISC License - see the [LICENSE](LICENSE) file for details.

## Author

Justin W. Wolcott

## Support

If you encounter any problems or have questions, please [open an issue](https://github.com/JWally/ez-web-crypto/issues) on GitHub.
