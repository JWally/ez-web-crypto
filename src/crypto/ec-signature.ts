import type { Base64String, ECSignatureKeyPair } from './types'

import { EcdsaConvertKey } from './key-conversion'
import { sleep, arrayToBase64, base64ToArray } from '../utils'
import { initializeCrypto } from './init'

export const EcMakeSigKeys = async (exportable: boolean = true): Promise<ECSignatureKeyPair> => {
  await sleep(0)

  const { crypto } = await initializeCrypto()

  const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, exportable, ['sign', 'verify'])

  if (exportable) {
    const b64Keys = await Promise.all([
      crypto.subtle.exportKey('spki', keys.publicKey).then((key) => arrayToBase64(new Uint8Array(key))),
      crypto.subtle.exportKey('pkcs8', keys.privateKey).then((key) => arrayToBase64(new Uint8Array(key))),
    ])

    return { publicKey: b64Keys[0], privateKey: b64Keys[1] }
  }

  const b64Keys = await Promise.all([
    crypto.subtle.exportKey('spki', keys.publicKey).then((key) => arrayToBase64(new Uint8Array(key))),
  ])

  return { publicKey: b64Keys[0], privateKey: keys.privateKey }
}

export const EcSignData = async (
  b64PrivateKey: Base64String | CryptoKey,
  b64data: Base64String
): Promise<Base64String> => {
  await sleep(0)

  const privateKey = await EcdsaConvertKey(b64PrivateKey)
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: { name: 'SHA-256' } },
    privateKey,
    base64ToArray(b64data)
  )

  return arrayToBase64(new Uint8Array(signature))
}

export const EcVerifySig = async (
  b64PublicKey: Base64String | CryptoKey,
  b64Signature: Base64String,
  b64data: Base64String
): Promise<boolean> => {
  await sleep(0)

  const publicKey = await EcdsaConvertKey(b64PublicKey)
  const signature = base64ToArray(b64Signature)

  return await crypto.subtle.verify(
    { name: 'ECDSA', hash: { name: 'SHA-256' } },
    publicKey,
    signature,
    base64ToArray(b64data)
  )
}
