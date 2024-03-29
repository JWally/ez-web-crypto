# EZ_WEB_CRYPTO

A JavaScript library providing an easy interface for working with subtle crypto.

## Description

`EZ_WEB_CRYPTO` is a class designed to simplify interactions with the Web Crypto API. It offers a straightforward approach to performing common cryptographic operations such as encoding, decoding, encryption, and decryption in both browser and Node.js environments.

## Features

- Automatic environment detection (Browser/Node.js)
- Base64 and Uint8Array conversions
- HMAC generation
- Data hashing with SHA algorithms
- Password-based encryption and decryption
- AES key generation, encryption, and decryption
- Elliptic Curve Cryptography (ECC) for key generation, encryption, decryption, and digital signature operations
- HKDF for key derivation and encryption/decryption operations

## Installation

To use `EZ_WEB_CRYPTO` in your project, simply import it:

```javascript
import EZ_WEB_CRYPTO from 'ez-web-crypto';
```

## Usage

### Initialization

```javascript
const ezWebCrypto = new EZ_WEB_CRYPTO();
```

### Conversions

- Base64 to Uint8Array: `ezWebCrypto.base64ToArray(base64String)`
- Uint8Array to Base64: `ezWebCrypto.arrayToBase64(arrayBuffer)`

### HMAC Generation

```javascript
const hmac = await ezWebCrypto.HMAC(secret, data);
```

### Data Hashing

```javascript
const hash = await ezWebCrypto.HASH(algo, data, len);
```

### Password-based Encryption and Decryption

- Encrypt: `ezWebCrypto.PASSWORD_ENCRYPT(password, data)`
- Decrypt: `ezWebCrypto.PASSWORD_DECRYPT(password, encryptedData)`

### AES Operations

- Key Generation: `ezWebCrypto.AESMakeKey(exportable)`
- Key Import: `ezWebCrypto.AESImportKey(key, exportable)`
- Encryption: `ezWebCrypto.AESEncrypt(key, data, nonce)`
- Decryption: `ezWebCrypto.AESDecrypt(key, nonce, data, returnText)`

### ECC Operations

- Key Generation: `ezWebCrypto.EcMakeCryptKeys(exportable)`
- Encryption: `ezWebCrypto.EcEncrypt(privateKey, publicKey, data)`
- Decryption: `ezWebCrypto.EcDecrypt(privateKey, publicKey, nonce, data, returnText)`
- Signature Generation: `ezWebCrypto.EcMakeSigKeys(exportable)`
- Data Signing: `ezWebCrypto.EcSignData(privateKey, data)`
- Signature Verification: `ezWebCrypto.EcVerifySig(publicKey, signature, data)`

### HKDF Operations

- Encryption: `ezWebCrypto.HKDFEncrypt(privateKey, publicKey, data)`
- Decryption: `ezWebCrypto.HKDFDecrypt(privateKey, publicKey, salt, iv, data, returnText)`

### Key Conversion Utilities

- `ezWebCrypto.EcdhConvertKey(key)`
- `ezWebCrypto.EcdsaConvertKey(key)`

## Contributions

Contributions are welcome. Please ensure that your code adheres to the existing coding standards.

## License

MIT
