import type { Base64String, ECSignatureKeyPair } from './types'

import { EcdsaConvertKey } from './key-conversion'
import { sleep, arrayToBase64, base64ToArray } from './utils'
import { generateKeyPair, sign, verify } from './primitives/p256'
import { encodeSpki, encodePkcs8 } from './primitives/der'
import { EzCryptoKey, keyMaterial, makeEcPrivateKey, publicPointOf } from './key'

export const EcMakeSigKeys = async (exportable: boolean = true): Promise<ECSignatureKeyPair> => {
  await sleep(0)

  const { privateKey, publicKey } = generateKeyPair()
  const spki = arrayToBase64(encodeSpki(publicKey))

  if (exportable) {
    return { publicKey: spki, privateKey: arrayToBase64(encodePkcs8(privateKey, publicKey)) }
  }

  return { publicKey: spki, privateKey: makeEcPrivateKey('ECDSA', privateKey, false) }
}

export const EcSignData = async (
  b64PrivateKey: Base64String | CryptoKey,
  b64data: Base64String
): Promise<Base64String> => {
  await sleep(0)

  const privateKey = (await EcdsaConvertKey(b64PrivateKey)) as EzCryptoKey
  if (privateKey.type !== 'private') {
    throw new Error('EcSignData requires a private key')
  }

  // Raw r||s, 64 bytes -- the same format crypto.subtle.sign emits for P-256.
  return arrayToBase64(sign(keyMaterial(privateKey), base64ToArray(b64data)))
}

export const EcVerifySig = async (
  b64PublicKey: Base64String | CryptoKey,
  b64Signature: Base64String,
  b64data: Base64String
): Promise<boolean> => {
  await sleep(0)

  const publicKey = (await EcdsaConvertKey(b64PublicKey)) as EzCryptoKey

  return verify(publicPointOf(publicKey), base64ToArray(b64Signature), base64ToArray(b64data))
}
