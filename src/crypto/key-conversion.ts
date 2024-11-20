import type { Base64String } from './types'
import { initializeCrypto } from './init'
import { base64ToArray, sleep } from './utils'

// key-conversion.ts
export const EcdhConvertKey = async (unknown_key: Base64String | CryptoKey): Promise<CryptoKey> => {
  await sleep(0)

  const { crypto, CryptoKey } = await initializeCrypto()

  // Type guard for CryptoKey
  if (CryptoKey && unknown_key instanceof CryptoKey) {
    return unknown_key
  }

  if (typeof unknown_key !== 'string') {
    throw new Error('Invalid key format')
  }

  try {
    // Try SPKI PUBLIC
    return await crypto.subtle.importKey(
      'spki',
      base64ToArray(unknown_key),
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      []
    )
  } catch (e) {}

  try {
    // Try RAW PUBLIC
    return await crypto.subtle.importKey(
      'raw',
      base64ToArray(unknown_key),
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      []
    )
  } catch (e) {}

  try {
    // Try PKCS8 PRIVATE
    return await crypto.subtle.importKey(
      'pkcs8',
      base64ToArray(unknown_key),
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      ['deriveKey', 'deriveBits']
    )
  } catch (e) {}

  try {
    // Try RAW PUBLIC - PERVERTED
    const longKey = new Uint8Array([4, ...Array.from(base64ToArray(unknown_key))])
    return await crypto.subtle.importKey('raw', longKey, { name: 'ECDH', namedCurve: 'P-256' }, true, [])
  } catch (e) {
    throw new Error('UNRECOGNIZED KEY FORMAT')
  }
}

export const EcdsaConvertKey = async (unknown_key: Base64String | CryptoKey): Promise<CryptoKey> => {
  await sleep(0)

  const { crypto, CryptoKey } = await initializeCrypto()

  // Type guard for CryptoKey
  if (CryptoKey && unknown_key instanceof CryptoKey) {
    return unknown_key
  }

  if (typeof unknown_key !== 'string') {
    throw new Error('Invalid key format')
  }

  try {
    // Try SPKI PUBLIC
    return await crypto.subtle.importKey(
      'spki',
      base64ToArray(unknown_key),
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['verify']
    )
  } catch (e) {}

  try {
    // Try RAW PUBLIC
    return await crypto.subtle.importKey(
      'raw',
      base64ToArray(unknown_key),
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['verify']
    )
  } catch (e) {}

  try {
    // Try PKCS8 PRIVATE
    return await crypto.subtle.importKey(
      'pkcs8',
      base64ToArray(unknown_key),
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign']
    )
  } catch (e) {}

  try {
    // Try RAW PUBLIC - PERVERTED
    const longKey = new Uint8Array([4, ...Array.from(base64ToArray(unknown_key))])
    return await crypto.subtle.importKey('raw', longKey, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign'])
  } catch (e) {
    throw new Error('UNRECOGNIZED KEY FORMAT')
  }
}
