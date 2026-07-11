import { EcdhConvertKey } from './key-conversion'
import { base64ToArray, arrayToBase64, sleep } from './utils'
import { deriveSharedSecret } from './primitives/p256'
import { hkdf } from './primitives/hkdf'
import { gcmEncrypt, gcmDecrypt } from './primitives/aes'
import { randomBytes } from './primitives/random'
import { decodeUtf8 } from './primitives/utf8'
import { toArrayBuffer } from './primitives/buffer'
import { alloc } from './primitives/intrinsics'
import { EzCryptoKey, keyMaterial, publicPointOf } from './key'

import type { Base64String, HKDFEncryptResult } from './types'

const AES_KEY_BYTES = 32
const EMPTY_INFO = alloc(0)

/**
 * ECDH -> HKDF-SHA256 -> AES-GCM, matching what the WebCrypto version derived:
 * the raw shared X coordinate is the HKDF input keying material, with an empty `info`.
 */
const deriveAesKey = async (
  b64Private: Base64String | CryptoKey,
  b64Public: Base64String | CryptoKey,
  salt: Uint8Array
): Promise<Uint8Array> => {
  const [publicKey, privateKey] = await Promise.all([EcdhConvertKey(b64Public), EcdhConvertKey(b64Private)])

  const sharedSecret = deriveSharedSecret(
    keyMaterial(privateKey as EzCryptoKey),
    publicPointOf(publicKey as EzCryptoKey)
  )

  return hkdf('SHA-256', sharedSecret, salt, EMPTY_INFO, AES_KEY_BYTES)
}

export const HKDFEncrypt = async (
  b64Private: Base64String | CryptoKey,
  b64Public: Base64String | CryptoKey,
  b64data: Base64String,
  ivLength: number = 16,
  saltLength: number = 16
): Promise<HKDFEncryptResult> => {
  await sleep(0)

  const salt = randomBytes(saltLength)
  const iv = randomBytes(ivLength)

  const aesKey = await deriveAesKey(b64Private, b64Public, salt)
  const encrypted = gcmEncrypt(aesKey, iv, base64ToArray(b64data))

  return {
    ciphertext: arrayToBase64(encrypted),
    salt: arrayToBase64(salt),
    iv: arrayToBase64(iv),
  }
}

export const HKDFDecrypt = async (
  b64Private: Base64String | CryptoKey,
  b64Public: Base64String | CryptoKey,
  b64Salt: Base64String,
  b64iv: Base64String,
  b64data: Base64String,
  returnText: boolean = false
): Promise<string | ArrayBuffer> => {
  await sleep(0)

  const salt = base64ToArray(b64Salt)
  const iv = base64ToArray(b64iv)
  const data = base64ToArray(b64data)

  const aesKey = await deriveAesKey(b64Private, b64Public, salt)

  try {
    const decrypted = gcmDecrypt(aesKey, iv, data)

    if (!returnText) {
      return toArrayBuffer(decrypted)
    }

    return decodeUtf8(decrypted)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } catch (e: any) {
    // Preserved from the original implementation, and asserted on by the test suite.
    // eslint-disable-next-line no-console
    console.log({ name: e.name, stack: e.stack, message: e.message })
    throw e
  }
}
