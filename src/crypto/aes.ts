// aes.ts
import { initializeCrypto } from './init'
import { arrayToBase64, base64ToArray, sleep } from './utils'
import { Base64String, AESEncryptResult } from './types'

export const AESMakeKey = async (exportable: boolean = true): Promise<Base64String | CryptoKey> => {
  await sleep(0)

  const { crypto } = await initializeCrypto()

  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, exportable, ['encrypt', 'decrypt'])

  if (!exportable) {
    return key
  }

  const out = await crypto.subtle.exportKey('raw', key)
  return arrayToBase64(new Uint8Array(out))
}

export const AESImportKey = async (
  aes_key: Base64String | CryptoKey,
  exportable: boolean = true
): Promise<CryptoKey> => {
  await sleep(0)

  const { crypto } = await initializeCrypto()

  // Type guard for CryptoKey
  const isCryptoKey = (key: Base64String | CryptoKey): key is CryptoKey =>
    typeof key === 'object' && key !== null && 'type' in key && 'algorithm' in key

  if (isCryptoKey(aes_key)) {
    return aes_key
  }

  return crypto.subtle.importKey('raw', base64ToArray(aes_key).buffer, 'AES-GCM', exportable, ['encrypt', 'decrypt'])
}

export const AESEncrypt = async (
  base_64_key: Base64String | CryptoKey,
  base_64_data: Base64String,
  base_64_nonce: Base64String | false = false
): Promise<AESEncryptResult> => {
  await sleep(0)

  const { crypto } = await initializeCrypto()
  const aes_key = await AESImportKey(base_64_key)
  const nonce = base_64_nonce ? base64ToArray(base_64_nonce) : crypto.getRandomValues(new Uint8Array(16))

  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aes_key, base64ToArray(base_64_data))

  return {
    ciphertext: arrayToBase64(new Uint8Array(encrypted)),
    iv: arrayToBase64(nonce),
  }
}

export const AESDecrypt = async (
  base_64_key: Base64String | CryptoKey,
  base_64_nonce: Base64String,
  base_64_cipher: Base64String,
  returnText: boolean = false
): Promise<string | ArrayBuffer> => {
  await sleep(0)

  const { crypto } = await initializeCrypto()
  const aes_key = await AESImportKey(base_64_key)
  const nonce_ary = base64ToArray(base_64_nonce)
  const cipher_ary = base64ToArray(base_64_cipher)

  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce_ary }, aes_key, cipher_ary)

  if (!returnText) {
    return decrypted
  }

  const decryptedArray = new Uint8Array(decrypted)
  return new TextDecoder().decode(decryptedArray)
}
