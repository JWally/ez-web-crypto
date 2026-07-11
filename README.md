# ez-web-crypto

![Library Logo](https://github.com/JWally/ez-web-crypto/assets/2482935/0e2faf24-2c5e-416f-b9e3-e75fe2080569)

[![npm version](https://badge.fury.io/js/@justinwwolcott%2Fez-web-crypto.svg)](https://www.npmjs.com/package/@justinwwolcott/ez-web-crypto)
[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg)](https://opensource.org/licenses/ISC)
[![Node.js Version](https://img.shields.io/node/v/@justinwwolcott/ez-web-crypto.svg)](https://nodejs.org/)

A lightweight, type-safe cryptography library for the browser and Node.js. The API mirrors
the Web Crypto API's operations, but the primitives are implemented in self-contained
JavaScript rather than delegated to `crypto.subtle` — see [Security Notes](#security-notes)
for what that buys you and what it doesn't.

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

- Node.js ≥ 20.0.0
- Modern browsers (only `crypto.getRandomValues` is required from the host)
- Full TypeScript support included

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Security Notes

### Self-contained cryptography

As of v5, the cryptographic primitives are implemented in plain JavaScript rather than
delegated to `crypto.subtle`. SHA-1/256/384/512, HMAC, HKDF, AES-GCM and P-256
(ECDH + ECDSA), along with the base64 and UTF-8 codecs, all run in this library's own
code. Every primitive is checked byte-for-byte against the platform's WebCrypto in the
test suite (`tests/crypto/primitives.test.ts`), and ciphertext, keys and signatures remain
fully interoperable with the previous WebCrypto-backed release
(`tests/crypto/compatibility.test.ts`).

**Why.** A wrapper over `crypto.subtle` routes every plaintext and key through globals that
any earlier-loaded script can replace: `crypto.subtle`, `btoa`/`atob`, `TextEncoder`. Those
hooks sit _below_ the wrapper, so the wrapper cannot detect or prevent them. Owning the
implementation removes that surface — the library reads the platform intrinsics it needs
(only `crypto.getRandomValues`, plus a few `String`/`Array` methods) **once, at module load**,
through a private snapshot, so hooks installed afterwards see nothing and steer nothing.

- Import this library early, before any untrusted script runs. The load-time snapshot is
  what makes the guarantee; code that patches the globals _before_ this module is evaluated
  is outside it.
- Key material lives in a module-scoped `WeakMap`, never on the key object — it will not
  surface in `JSON.stringify`, `Object.keys`, a console dump, or an error report.
- Password-based encryption strengthens the password with 5,000 rounds of SHA-512 before use.

### What this does not buy you

- **`extractable: false` is weaker here than in WebCrypto.** A browser can hold a
  non-extractable key's bytes outside the JS heap entirely; a JS library cannot. We promise
  only that _we_ never hand the material back out. If you need keys the page genuinely cannot
  reach, use WebCrypto directly, a Web Worker, or a hardware/enclave-backed store.
- **The P-256 scalar multiplication is not constant-time.** JavaScript `BigInt` is not
  constant-time in any current engine, so a timing-hardened ladder would be theatre. Treat
  the curve code as safe for ephemeral, per-session keys; keep long-lived private keys off
  untrusted clients.
- **Entropy still comes from the host.** `crypto.getRandomValues` seeds an internal
  HMAC-DRBG (captured at load time and mixed with ambient noise), but if that source is
  already compromised when the module loads, nothing running in the page can repair it.
- **Randomness aside, this is not audited cryptography.** It is a careful, spec-tested
  implementation. For threat models that warrant it, get an independent review.

## License

This project is licensed under the ISC License - see the [LICENSE](LICENSE) file for details.

## Author

Justin W. Wolcott

## Support

If you encounter any problems or have questions, please [open an issue](https://github.com/JWally/ez-web-crypto/issues) on GitHub.
