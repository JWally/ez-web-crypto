import type { Base64String, ECKeyPair, AESEncryptResult } from './types'

import { arrayToBase64, sleep } from './utils'
import { AESEncrypt, AESDecrypt } from './aes'
import { generateKeyPair, deriveSharedSecret } from './primitives/p256'
import { encodeSpki, encodePkcs8 } from './primitives/der'
import { encodeBase64Url } from './primitives/base64'
import { EcdhConvertKey } from './key-conversion'
import { EzCryptoKey, keyMaterial, makeAesKey, makeEcPrivateKey, publicPointOf } from './key'

/**
 * The ECDH -> AES-GCM key derivation is deliberately *not* an HKDF: WebCrypto's
 * `deriveKey({name:'ECDH'}, ..., {name:'AES-GCM', length: 256})` takes the raw 256-bit
 * X coordinate of the shared point as the AES key, and matching that byte-for-byte is
 * what keeps ciphertext written by earlier versions decryptable. (HKDFEncrypt is the
 * function that runs a real KDF; use it for new designs.)
 */
const deriveAesKey = async (
  b64Private: Base64String | CryptoKey,
  b64Public: Base64String | CryptoKey
): Promise<EzCryptoKey> => {
  const [publicKey, privateKey] = await Promise.all([EcdhConvertKey(b64Public), EcdhConvertKey(b64Private)])

  const shared = deriveSharedSecret(keyMaterial(privateKey as EzCryptoKey), publicPointOf(publicKey as EzCryptoKey))

  return makeAesKey(shared, false)
}

const jwkFor = (point: Uint8Array, scalar?: Uint8Array): JsonWebKey => {
  const jwk: JsonWebKey = {
    crv: 'P-256',
    ext: true,
    key_ops: scalar ? ['deriveKey', 'deriveBits'] : [],
    kty: 'EC',
    x: encodeBase64Url(point.subarray(1, 33)),
    y: encodeBase64Url(point.subarray(33, 65)),
  }

  if (scalar) {
    jwk.d = encodeBase64Url(scalar)
  }

  return jwk
}

// ec.ts
export const EcMakeCryptKeys = async (exportable: boolean = true): Promise<ECKeyPair> => {
  await sleep(0)

  const { privateKey, publicKey } = generateKeyPair()

  const spki = arrayToBase64(encodeSpki(publicKey))
  const rawPublicKey = arrayToBase64(publicKey)
  const rawPublicKeyLite = arrayToBase64(publicKey.subarray(1))

  if (!exportable) {
    return {
      publicKey: spki,
      privateKey: makeEcPrivateKey('ECDH', privateKey, false),
      rawPublicKey,
      rawPublicKeyLite,
    }
  }

  return {
    publicKey: spki,
    privateKey: arrayToBase64(encodePkcs8(privateKey, publicKey)),
    jwkPublicKey: jwkFor(publicKey),
    jwkPrivateKey: jwkFor(publicKey, privateKey),
    rawPublicKey,
    rawPublicKeyLite,
  }
}

export const EcEncrypt = async (
  b64Private: Base64String | CryptoKey,
  b64Public: Base64String | CryptoKey,
  b64data: Base64String
): Promise<AESEncryptResult> => AESEncrypt(await deriveAesKey(b64Private, b64Public), b64data)

export const EcDecrypt = async (
  b64Private: Base64String | CryptoKey,
  b64Public: Base64String | CryptoKey,
  b64Nonce: Base64String,
  b64data: Base64String,
  returnText: boolean = false
): Promise<string | ArrayBuffer> => AESDecrypt(await deriveAesKey(b64Private, b64Public), b64Nonce, b64data, returnText)
