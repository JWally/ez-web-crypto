import type { Base64String, ECKeyPair, AESEncryptResult } from './types'

import { arrayToBase64, base64ToArray, sleep } from './utils'
import { initializeCrypto } from './init'
import { AESEncrypt } from './aes'

import { EcdhConvertKey } from './key-conversion'

// ec.ts
export const EcMakeCryptKeys = async (exportable: boolean = true): Promise<ECKeyPair> => {
  await sleep(0)

  const { crypto } = await initializeCrypto()

  const keys = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, exportable, [
    'deriveKey',
    'deriveBits',
  ])

  if (!exportable) {
    const exportKeys = await Promise.all([
      crypto.subtle.exportKey('spki', keys.publicKey).then((key) => arrayToBase64(new Uint8Array(key))),
      keys.privateKey,
      crypto.subtle.exportKey('raw', keys.publicKey).then((key) => arrayToBase64(new Uint8Array(key))),
      crypto.subtle.exportKey('raw', keys.publicKey).then((key) => arrayToBase64(new Uint8Array(key).slice(1, 1000))),
    ])

    return {
      publicKey: exportKeys[0],
      privateKey: exportKeys[1],
      rawPublicKey: exportKeys[2],
      rawPublicKeyLite: exportKeys[3],
    }
  }

  const exportKeys = await Promise.all([
    crypto.subtle.exportKey('spki', keys.publicKey).then((key) => arrayToBase64(new Uint8Array(key))),
    crypto.subtle.exportKey('pkcs8', keys.privateKey).then((key) => arrayToBase64(new Uint8Array(key))),
    crypto.subtle.exportKey('jwk', keys.publicKey),
    crypto.subtle.exportKey('jwk', keys.privateKey),
    crypto.subtle.exportKey('raw', keys.publicKey).then((key) => arrayToBase64(new Uint8Array(key))),
    crypto.subtle.exportKey('raw', keys.publicKey).then((key) => arrayToBase64(new Uint8Array(key).slice(1, 1000))),
  ])

  return {
    publicKey: exportKeys[0],
    privateKey: exportKeys[1],
    jwkPublicKey: exportKeys[2],
    jwkPrivateKey: exportKeys[3],
    rawPublicKey: exportKeys[4],
    rawPublicKeyLite: exportKeys[5],
  }
}

export const EcEncrypt = async (
  b64Private: Base64String | CryptoKey,
  b64Public: Base64String | CryptoKey,
  b64data: Base64String
): Promise<AESEncryptResult> => {
  const { crypto } = await initializeCrypto()

  // Convert and cache keys if possible
  const [publicKey, privateKey] = await Promise.all([EcdhConvertKey(b64Public), EcdhConvertKey(b64Private)])

  const aes_key = await crypto.subtle.deriveKey(
    { name: 'ECDH', public: publicKey },
    privateKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  )

  return AESEncrypt(aes_key, b64data) // Avoid double conversion
}

export const EcDecrypt = async (
  b64Private: Base64String | CryptoKey,
  b64Public: Base64String | CryptoKey,
  b64Nonce: Base64String,
  b64data: Base64String,
  returnText: boolean = false
): Promise<string | ArrayBuffer> => {
  const { crypto } = await initializeCrypto();

  // Convert and cache keys in parallel
  const [publicKey, privateKey] = await Promise.all([
    EcdhConvertKey(b64Public),
    EcdhConvertKey(b64Private),
  ]);

  // Base64 to ArrayBuffer conversions
  const [nonce, data] = [base64ToArray(b64Nonce), base64ToArray(b64data)];

  // Derive the shared AES key
  const aesKey = await crypto.subtle.deriveKey(
    { name: 'ECDH', public: publicKey },
    privateKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  // Perform decryption
  const decryptedData = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce },
    aesKey,
    data
  );

  // Return result based on returnText flag
  if (returnText) {
    return new TextDecoder().decode(new Uint8Array(decryptedData));
  }
  return decryptedData;
};

