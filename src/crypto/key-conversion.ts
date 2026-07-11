import type { Base64String } from './types'
import { base64ToArray, sleep } from './utils'
import { parseSpki, parsePkcs8 } from './primitives/der'
import { decodePoint } from './primitives/p256'
import { concat } from './primitives/sha'
import { U8 } from './primitives/intrinsics'
import {
  EcAlgorithmName,
  adoptNativeKey,
  isCryptoKeyLike,
  isEzCryptoKey,
  makeEcPrivateKey,
  makeEcPublicKey,
} from './key'

const RAW_POINT_LENGTH = 65 // 0x04 || X || Y
const LITE_POINT_LENGTH = 64 // X || Y, with the 0x04 tag chopped off

/**
 * Accepts every shape this library has ever emitted -- SPKI, PKCS#8, a raw uncompressed
 * point, or a "lite" point missing its 0x04 prefix -- plus keys that we, or the platform,
 * already turned into CryptoKeys.
 *
 * ECDH and ECDSA keys are byte-identical on the wire (both id-ecPublicKey / prime256v1),
 * so the caller's choice of entry point decides the algorithm -- exactly as the
 * `crypto.subtle.importKey` calls this replaces did.
 */
const convertKey = async (algorithm: EcAlgorithmName, unknown_key: Base64String | CryptoKey): Promise<CryptoKey> => {
  await sleep(0)

  if (isEzCryptoKey(unknown_key)) {
    return unknown_key
  }

  if (isCryptoKeyLike(unknown_key)) {
    return adoptNativeKey(unknown_key, algorithm)
  }

  if (typeof unknown_key !== 'string') {
    throw new Error('Invalid key format')
  }

  try {
    const bytes = base64ToArray(unknown_key)

    if (bytes.length === RAW_POINT_LENGTH && bytes[0] === 0x04) {
      decodePoint(bytes) // reject off-curve points before they can reach ECDH
      return makeEcPublicKey(algorithm, bytes)
    }

    if (bytes.length === LITE_POINT_LENGTH) {
      const restored = concat(new U8([0x04]), bytes)
      decodePoint(restored)
      return makeEcPublicKey(algorithm, restored)
    }

    // Anything else is DER: SPKI (public) or PKCS#8 (private). Both open with a SEQUENCE.
    try {
      const point = parseSpki(bytes)
      decodePoint(point)
      return makeEcPublicKey(algorithm, point)
    } catch {
      return makeEcPrivateKey(algorithm, parsePkcs8(bytes), false)
    }
  } catch {
    throw new Error('UNRECOGNIZED KEY FORMAT')
  }
}

export const EcdhConvertKey = async (unknown_key: Base64String | CryptoKey): Promise<CryptoKey> =>
  convertKey('ECDH', unknown_key)

export const EcdsaConvertKey = async (unknown_key: Base64String | CryptoKey): Promise<CryptoKey> =>
  convertKey('ECDSA', unknown_key)
