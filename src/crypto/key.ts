/**
 * `EzCryptoKey` -- the stand-in for `CryptoKey` now that key material lives in JS.
 *
 * Raw bytes are held in a module-scoped WeakMap rather than on the object, so page
 * script holding a key cannot read the material off it, and it will not show up in
 * `JSON.stringify`, `Object.keys`, a console dump, or an error report.
 *
 * IMPORTANT -- `extractable: false` is weaker here than it is in WebCrypto. The browser
 * can keep a non-extractable CryptoKey's bytes outside the JS heap entirely; we cannot.
 * All we can promise is that *we* never hand them back out. Anything that can run code
 * in this realm before us, or wrap our exports, can still get at them. If you need keys
 * the page genuinely cannot reach, you need WebCrypto (or a worker/enclave) -- that is
 * the price of not calling `crypto.subtle`. See README, "What this does not buy you".
 */

import { parsePkcs8 } from './primitives/der'
import { derivePublicKey } from './primitives/p256'
import { U8 } from './primitives/intrinsics'

/* eslint-disable @typescript-eslint/no-explicit-any */

export type EcAlgorithmName = 'ECDH' | 'ECDSA'

/**
 * Key bytes live here, not on the key object. A WeakMap cannot be enumerated and this one
 * is module-scoped, so page script holding a key has no path to the material behind it.
 */
const material = new WeakMap<object, Uint8Array>()

export class EzCryptoKey implements CryptoKey {
  readonly type: KeyType

  readonly extractable: boolean

  readonly algorithm: KeyAlgorithm

  readonly usages: KeyUsage[]

  constructor(type: KeyType, algorithm: KeyAlgorithm, extractable: boolean, usages: KeyUsage[], bytes: Uint8Array) {
    this.type = type
    this.algorithm = algorithm
    this.extractable = extractable
    this.usages = usages

    material.set(this, bytes)
  }
}

export const isEzCryptoKey = (value: unknown): value is EzCryptoKey => value instanceof EzCryptoKey

/** The raw bytes behind a key: an AES key, a P-256 scalar, or an uncompressed point. */
export const keyMaterial = (key: EzCryptoKey): Uint8Array => {
  const bytes = material.get(key)
  if (!bytes) {
    throw new Error('Key material is unavailable')
  }
  return bytes
}

export const makeAesKey = (bytes: Uint8Array, extractable: boolean): EzCryptoKey =>
  new EzCryptoKey(
    'secret',
    { name: 'AES-GCM', length: bytes.length * 8 } as AesKeyAlgorithm,
    extractable,
    ['encrypt', 'decrypt'],
    bytes
  )

const EC_USAGES: Record<EcAlgorithmName, { private: KeyUsage[]; public: KeyUsage[] }> = {
  ECDH: { private: ['deriveKey', 'deriveBits'], public: [] },
  ECDSA: { private: ['sign'], public: ['verify'] },
}

export const makeEcPrivateKey = (algorithm: EcAlgorithmName, scalar: Uint8Array, extractable: boolean): EzCryptoKey =>
  new EzCryptoKey(
    'private',
    { name: algorithm, namedCurve: 'P-256' } as EcKeyAlgorithm,
    extractable,
    EC_USAGES[algorithm].private,
    scalar
  )

export const makeEcPublicKey = (algorithm: EcAlgorithmName, point: Uint8Array): EzCryptoKey =>
  new EzCryptoKey(
    'public',
    { name: algorithm, namedCurve: 'P-256' } as EcKeyAlgorithm,
    true,
    EC_USAGES[algorithm].public,
    point
  )

// --- Interop with the platform's own CryptoKey -----------------------------------
//
// The only code in the library that still touches `crypto.subtle`, and it runs solely
// when a caller hands us a key that *came from* `crypto.subtle`. We lift the material
// into JS once and cache it; from there every operation is pure JS. Nothing we generate
// ourselves takes this path.

const nativeSubtle: SubtleCrypto | undefined = (globalThis as any).crypto?.subtle

export const isCryptoKeyLike = (value: unknown): value is CryptoKey =>
  typeof value === 'object' && value !== null && 'type' in value && 'algorithm' in value

const adopted = new WeakMap<CryptoKey, EzCryptoKey>()

/** Lifts a WebCrypto key into an EzCryptoKey. Requires it to be extractable. */
export const adoptNativeKey = async (key: CryptoKey, algorithm: EcAlgorithmName | 'AES-GCM'): Promise<EzCryptoKey> => {
  const cached = adopted.get(key)
  if (cached) {
    return cached
  }

  if (!nativeSubtle) {
    throw new Error('Cannot adopt a WebCrypto key: crypto.subtle is unavailable')
  }
  if (!key.extractable) {
    throw new Error(
      'Cannot adopt a non-extractable WebCrypto key: its material is held by the platform and cannot be read from JS'
    )
  }

  let lifted: EzCryptoKey

  if (algorithm === 'AES-GCM') {
    lifted = makeAesKey(new U8(await nativeSubtle.exportKey('raw', key)), key.extractable)
  } else if (key.type === 'private') {
    const pkcs8 = new U8(await nativeSubtle.exportKey('pkcs8', key))
    lifted = makeEcPrivateKey(algorithm, parsePkcs8(pkcs8), key.extractable)
  } else {
    lifted = makeEcPublicKey(algorithm, new U8(await nativeSubtle.exportKey('raw', key)))
  }

  adopted.set(key, lifted)
  return lifted
}

/** The public point for an EC private key, recomputed from the scalar. */
export const publicPointOf = (key: EzCryptoKey): Uint8Array =>
  key.type === 'private' ? derivePublicKey(keyMaterial(key)) : keyMaterial(key)
