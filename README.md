![image](https://github.com/JWally/ez-web-crypto/assets/2482935/0e2faf24-2c5e-416f-b9e3-e75fe2080569)

[![npm version](https://badge.fury.io/js/@justinwwolcott%2Fez-web-crypto.svg)](https://www.npmjs.com/package/@justinwwolcott/ez-web-crypto)
[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg)](https://opensource.org/licenses/ISC)
[![Node.js Version](https://img.shields.io/node/v/@justinwwolcott/ez-web-crypto.svg)](https://nodejs.org/)

A lightweight, type-safe wrapper around the Web Crypto API, providing easy-to-use cryptographic operations for both browser and Node.js environments.

## Features

- 🔐 AES-GCM encryption/decryption
- 🔑 ECDH encryption/decryption
- ✍️ ECDSA digital signature/verification
- 🔒 Password-based encryption
- #️⃣ HMAC operations
- 🧮 Cryptographic hashing (SHA-1, SHA-256, SHA-384, SHA-512)
- 📱 Works in both browser and Node.js environments
- 📘 Full TypeScript support

## Installation

```bash
npm install @justinwwolcott/ez-web-crypto
```

## Usage

### AES Encryption

```typescript
import { AESMakeKey, AESEncrypt, AESDecrypt } from '@justinwwolcott/ez-web-crypto';

// Generate a new AES key
const key = await AESMakeKey();

// Encrypt data
const encrypted = await AESEncrypt(key, btoa('Hello, World!'));

// Decrypt data
const decrypted = await AESDecrypt(key, encrypted.iv, encrypted.ciphertext, true);
console.log(decrypted); // 'Hello, World!'
```

### ECDH Key Exchange

```typescript
import { EcMakeCryptKeys, EcEncrypt, EcDecrypt } from '@justinwwolcott/ez-web-crypto';

// Generate key pairs for both parties
const aliceKeys = await EcMakeCryptKeys();
const bobKeys = await EcMakeCryptKeys();

// Alice encrypts message for Bob
const encrypted = await EcEncrypt(
  aliceKeys.privateKey,
  bobKeys.publicKey,
  btoa('Secret message')
);

// Bob decrypts message from Alice
const decrypted = await EcDecrypt(
  bobKeys.privateKey,
  aliceKeys.publicKey,
  encrypted.iv,
  encrypted.ciphertext,
  true
);
```

### Digital Signatures

```typescript
import { EcMakeSigKeys, EcSignData, EcVerifySig } from '@justinwwolcott/ez-web-crypto';

// Generate signing keys
const keys = await EcMakeSigKeys();

// Sign data
const signature = await EcSignData(keys.privateKey, btoa('Sign this message'));

// Verify signature
const isValid = await EcVerifySig(
  keys.publicKey,
  signature,
  btoa('Sign this message')
);
```

### Password-Based Encryption

```typescript
import { PASSWORD_ENCRYPT, PASSWORD_DECRYPT } from '@justinwwolcott/ez-web-crypto';

// Encrypt with password
const encrypted = await PASSWORD_ENCRYPT('myPassword', btoa('Secret data'));

// Decrypt with password
const decrypted = await PASSWORD_DECRYPT('myPassword', encrypted);
```

### Hashing

```typescript
import { HASH } from '@justinwwolcott/ez-web-crypto';

const hash = await HASH('SHA-256', 'Hash this text');
```

## API Reference

### AES Operations
- `AESMakeKey(exportable?: boolean): Promise<Base64String | CryptoKey>`
- `AESEncrypt(key: Base64String | CryptoKey, data: Base64String, nonce?: Base64String): Promise<AESEncryptResult>`
- `AESDecrypt(key: Base64String | CryptoKey, nonce: Base64String, data: Base64String, returnText?: boolean): Promise<string | ArrayBuffer>`

### ECDH Operations
- `EcMakeCryptKeys(exportable?: boolean): Promise<ECKeyPair>`
- `EcEncrypt(privateKey: Base64String | CryptoKey, publicKey: Base64String | CryptoKey, data: Base64String): Promise<AESEncryptResult>`
- `EcDecrypt(privateKey: Base64String | CryptoKey, publicKey: Base64String | CryptoKey, nonce: Base64String, data: Base64String, returnText?: boolean): Promise<string | ArrayBuffer>`

### Digital Signatures
- `EcMakeSigKeys(exportable?: boolean): Promise<ECSignatureKeyPair>`
- `EcSignData(privateKey: Base64String | CryptoKey, data: Base64String): Promise<Base64String>`
- `EcVerifySig(publicKey: Base64String | CryptoKey, signature: Base64String, data: Base64String): Promise<boolean>`

### Password Operations
- `PASSWORD_ENCRYPT(password: string, data: Base64String): Promise<Base64String>`
- `PASSWORD_DECRYPT(password: string, data: Base64String): Promise<string>`

### Hashing Operations
- `HASH(algorithm: HashAlgorithm, data: string, length?: number): Promise<Base64String>`
- `HMAC(secret: string, data: string): Promise<HexString>`

## Environment Support

- Node.js ≥ 14.0.0
- Modern browsers with Web Crypto API support
- TypeScript support included

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. Make sure to read the contributing guidelines before submitting your PR.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the ISC License - see the [LICENSE](LICENSE) file for details.

## Author

Justin W. Wolcott

## Support

If you encounter any problems or have questions, please [open an issue](https://github.com/JWally/ez-web-crypto/issues) on GitHub.