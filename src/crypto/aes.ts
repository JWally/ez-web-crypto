// aes.ts
import { arrayToBase64, base64ToArray, sleep } from './utils'
import { gcmEncrypt, gcmDecrypt } from './primitives/aes'
import { randomBytes } from './primitives/random'
import { decodeUtf8 } from './primitives/utf8'
import { toArrayBuffer } from './primitives/buffer'
import { EzCryptoKey, adoptNativeKey, isCryptoKeyLike, isEzCryptoKey, keyMaterial, makeAesKey } from './key'
import { Base64String, AESEncryptResult } from './types'

const AES_KEY_BYTES = 32
const NONCE_BYTES = 16

export const AESMakeKey = async (exportable: boolean = true): Promise<Base64String | CryptoKey> => {
  await sleep(0)

  const key = randomBytes(AES_KEY_BYTES)

  if (!exportable) {
    return makeAesKey(key, false)
  }

  return arrayToBase64(key)
}

export const AESImportKey = async (
  aes_key: Base64String | CryptoKey,
  exportable: boolean = true
): Promise<CryptoKey> => {
  await sleep(0)

  if (isEzCryptoKey(aes_key)) {
    return aes_key
  }

  if (isCryptoKeyLike(aes_key)) {
    // A key from the platform's WebCrypto: lift it into JS once, then never touch subtle again.
    return adoptNativeKey(aes_key, 'AES-GCM')
  }

  return makeAesKey(base64ToArray(aes_key), exportable)
}

/** Both directions need the key as raw bytes; this is the single funnel for that. */
const rawKeyOf = async (key: Base64String | CryptoKey): Promise<Uint8Array> =>
  keyMaterial((await AESImportKey(key)) as EzCryptoKey)

export const AESEncrypt = async (
  base_64_key: Base64String | CryptoKey,
  base_64_data: Base64String,
  base_64_nonce: Base64String | false = false
): Promise<AESEncryptResult> => {
  await sleep(0)

  const key = await rawKeyOf(base_64_key)
  const nonce = base_64_nonce ? base64ToArray(base_64_nonce) : randomBytes(NONCE_BYTES)

  const encrypted = gcmEncrypt(key, nonce, base64ToArray(base_64_data))

  return {
    ciphertext: arrayToBase64(encrypted),
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

  const key = await rawKeyOf(base_64_key)
  const decrypted = gcmDecrypt(key, base64ToArray(base_64_nonce), base64ToArray(base_64_cipher))

  if (!returnText) {
    return toArrayBuffer(decrypted)
  }

  return decodeUtf8(decrypted)
}
