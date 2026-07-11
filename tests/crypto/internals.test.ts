/**
 * Branch coverage for the primitive internals that the public API and the differential
 * suite don't naturally drive: codec boundary conditions, DER malformations, and the
 * guard rails inside the field/curve code.
 */
import { describe, expect, test } from '@jest/globals'
import { encodeUtf8, decodeUtf8 } from '../../src/crypto/primitives/utf8'
import { hkdfExpand } from '../../src/crypto/primitives/hkdf'
import { parseSpki, parsePkcs8, encodeSpki, DerError } from '../../src/crypto/primitives/der'
import * as p256 from '../../src/crypto/primitives/p256'
import { randomBytes } from '../../src/crypto/primitives/random'
import { concat } from '../../src/crypto/primitives/sha'
import {
  AESMakeKey,
  AESEncrypt,
  AESDecrypt,
  EcMakeCryptKeys,
  EcMakeSigKeys,
  EcEncrypt,
  EcDecrypt,
  HKDFEncrypt,
  HKDFDecrypt,
  arrayToBase64,
} from '../../src'
import { isEzCryptoKey } from '../../src/crypto/key'

const hex = (bytes: Uint8Array): string =>
  Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')

describe('primitive internals', () => {
  describe('utf8 boundaries (checked against the platform)', () => {
    const cases = [
      '\uD800a', // high surrogate followed by a non-low-surrogate
      '\uD800\uD801', // two high surrogates
      '\uDC00', // lone low surrogate
      'a\uDBFF', // high surrogate at end of string
      'ñ', // 2-byte
      '€', // 3-byte
      '中文字符', // 3-byte run
      '😀🦊', // 4-byte run
      '\u0000', // NUL
    ]

    test('encode matches TextEncoder on every surrogate edge case', () => {
      cases.forEach((sample) => {
        expect(hex(encodeUtf8(sample))).toBe(hex(new TextEncoder().encode(sample)))
      })
    })

    test('decode matches TextDecoder on structurally invalid UTF-8', () => {
      const malformed = [
        new Uint8Array([0xc3, 0xb1]), // valid ñ, exercises the 2-byte path
        new Uint8Array([0xed, 0xa0, 0x80]), // encoded surrogate D800 -> must be rejected
        new Uint8Array([0xf4, 0x90, 0x80, 0x80]), // > U+10FFFF -> rejected
        new Uint8Array([0xf0, 0x80, 0x80, 0x80]), // overlong 4-byte
        new Uint8Array([0xe0, 0x80, 0x80]), // overlong 3-byte
        new Uint8Array([0xc0, 0x80]), // overlong 2-byte
        new Uint8Array([0xc2]), // truncated lead byte at EOF
        new Uint8Array([0xe2, 0x82]), // truncated 3-byte at EOF
        new Uint8Array([0xe2, 0x28, 0xa1]), // bad continuation mid-sequence
        new Uint8Array([0xf0, 0x9f, 0x28]), // bad continuation in a 4-byte
      ]

      malformed.forEach((bytes) => {
        expect(decodeUtf8(bytes)).toBe(new TextDecoder().decode(bytes))
      })
    })
  })

  describe('hkdf expand limits', () => {
    test('refuses to expand past 255 blocks', () => {
      const prk = randomBytes(32)
      // 255 * 32 = 8160 bytes is the ceiling for SHA-256.
      expect(() => hkdfExpand('SHA-256', prk, new Uint8Array(0), 256 * 32)).toThrow(/255 blocks/i)
      expect(hkdfExpand('SHA-256', prk, new Uint8Array(0), 255 * 32).length).toBe(255 * 32)
    })
  })

  describe('DER malformations', () => {
    test('rejects a long-form length that runs off the end', () => {
      // 0x30 (SEQUENCE), 0x82 (2 length bytes follow) but the buffer is too short.
      expect(() => parseSpki(new Uint8Array([0x30, 0x82, 0x01]))).toThrow(DerError)
    })

    test('rejects the wrong algorithm OID', () => {
      const { publicKey } = p256.generateKeyPair()
      const spki = encodeSpki(publicKey)
      // The algorithm OID (1.2.840.10045.2.1) starts a few bytes in; corrupt its last byte.
      const idx = spki.indexOf(0x2a) // start of the 1.2.840... OID
      spki[idx + 6] = 0x02 // ...2.1 -> ...2.2
      expect(() => parseSpki(spki)).toThrow(/algorithm OID/i)
    })

    test('rejects a BIT STRING with non-zero unused-bits padding', () => {
      const { publicKey } = p256.generateKeyPair()
      const spki = encodeSpki(publicKey)
      // Find the BIT STRING's unused-bits octet (the byte right before the 0x04 point tag).
      const pointTag = spki.length - 65
      spki[pointTag - 1] = 0x01 // claim 1 unused bit instead of 0
      expect(() => parseSpki(spki)).toThrow(/padding/i)
    })

    test('rejects a PKCS#8 whose inner scalar is the wrong length', () => {
      // A structurally valid PrivateKeyInfo whose ECPrivateKey carries a 31-byte scalar.
      const shortScalar = new Uint8Array(31)
      // SEQUENCE(0x24=36 contents) { INTEGER 1, OCTET STRING(0x1f=31 bytes) }
      const ecPrivateKey = concat(new Uint8Array([0x30, 0x24, 0x02, 0x01, 0x01, 0x04, 0x1f]), shortScalar)
      const algId = new Uint8Array([
        0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x03, 0x01, 0x07,
      ])
      const body = concat(
        new Uint8Array([0x02, 0x01, 0x00]),
        algId,
        new Uint8Array([0x04, ecPrivateKey.length]),
        ecPrivateKey
      )
      const pkcs8 = concat(new Uint8Array([0x30, body.length]), body)

      expect(() => parsePkcs8(pkcs8)).toThrow(/32-byte/i)
    })
  })

  describe('curve guards', () => {
    test('derivePublicKey and sign reject out-of-range scalars', () => {
      const nBytes = new Uint8Array(32)
      const nHex = p256.N.toString(16).padStart(64, '0')
      for (let i = 0; i < 32; i += 1) {
        nBytes[i] = parseInt(nHex.slice(i * 2, i * 2 + 2), 16)
      }

      expect(() => p256.derivePublicKey(nBytes)).toThrow(p256.CurveError) // == n
      expect(() => p256.sign(new Uint8Array(32), randomBytes(8))).toThrow(p256.CurveError) // == 0
    })

    test('deriveSharedSecret rejects a private scalar of the wrong width', () => {
      const { publicKey } = p256.generateKeyPair()
      expect(() => p256.deriveSharedSecret(new Uint8Array(33), publicKey)).toThrow(/32 bytes/i)
    })

    test('encodePoint round-trips through decodePoint', () => {
      const { publicKey } = p256.generateKeyPair()
      const point = p256.decodePoint(publicKey)
      expect(hex(p256.encodePoint(point))).toBe(hex(publicKey))
    })

    test('verify tolerates r or s at the boundary values', () => {
      const { publicKey } = p256.generateKeyPair()

      // s = 0 and s = n are both out of [1, n-1] and must be rejected without throwing.
      const rValid = randomBytes(32)
      rValid[0] &= 0x7f // keep r < n comfortably
      expect(p256.verify(publicKey, concat(rValid, new Uint8Array(32)), randomBytes(8))).toBe(false)
    })

    test('decodePoint rejects coordinates outside the field', () => {
      // X = 0xff..ff is larger than the field prime P, so the point cannot be on the curve
      // and isOnCurve must reject it on the range check, before any modular arithmetic.
      const outOfField = concat(new Uint8Array([0x04]), new Uint8Array(64).fill(0xff))
      expect(() => p256.decodePoint(outOfField)).toThrow(p256.CurveError)
    })
  })

  describe('public-API default parameters', () => {
    const b64 = (text: string): string => arrayToBase64(new TextEncoder().encode(text))

    test('the exportable/returnText defaults are exercised (no explicit flag)', async () => {
      // Calling with the argument omitted takes the *other* side of each `= default` branch
      // from the tests that always pass the flag explicitly.
      const aesKey = await AESMakeKey() // default exportable = true -> base64
      expect(typeof aesKey).toBe('string')

      const enc = await AESEncrypt(aesKey, b64('defaults')) // default nonce = false -> random IV
      const arrayBuffer = await AESDecrypt(aesKey, enc.iv, enc.ciphertext) // default returnText = false
      expect(arrayBuffer).toBeInstanceOf(ArrayBuffer)

      const ecKeys = await EcMakeCryptKeys() // default exportable = true
      expect(typeof ecKeys.privateKey).toBe('string')

      const ecEnc = await EcEncrypt(ecKeys.privateKey, ecKeys.publicKey, b64('defaults'))
      expect(await EcDecrypt(ecKeys.privateKey, ecKeys.publicKey, ecEnc.iv, ecEnc.ciphertext)).toBeInstanceOf(
        ArrayBuffer
      )

      const hkdfEnc = await HKDFEncrypt(ecKeys.privateKey, ecKeys.publicKey, b64('defaults')) // default iv/salt lengths
      expect(
        await HKDFDecrypt(ecKeys.privateKey, ecKeys.publicKey, hkdfEnc.salt, hkdfEnc.iv, hkdfEnc.ciphertext)
      ).toBeInstanceOf(ArrayBuffer)
    })

    test('the non-exportable variants return live keys, not strings', async () => {
      expect(isEzCryptoKey(await AESMakeKey(false))).toBe(true)

      const ecdh = await EcMakeCryptKeys(false)
      expect(isEzCryptoKey(ecdh.privateKey)).toBe(true)

      const ecdsa = await EcMakeSigKeys(false)
      expect(isEzCryptoKey(ecdsa.privateKey)).toBe(true)
    })
  })
})
