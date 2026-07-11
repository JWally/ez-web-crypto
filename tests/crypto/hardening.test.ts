/**
 * The rejection paths.
 *
 * Everything here is a "we must say no" case: malformed DER, points that are not on the
 * curve, scalars outside [1, n-1], keys whose material we cannot legally reach. A crypto
 * library's bugs live in these branches far more often than in the happy path -- an ECDH
 * that accepts an off-curve point leaks the private key one query at a time.
 */
import { describe, expect, test } from '@jest/globals'
import { AESImportKey, AESEncrypt, AESDecrypt } from '../../src/crypto/aes'
import { EcdhConvertKey, EcdsaConvertKey } from '../../src/crypto/key-conversion'
import { EcMakeSigKeys, EcSignData, EcVerifySig } from '../../src/crypto/ec-signature'
import { EcMakeCryptKeys, EcEncrypt } from '../../src/crypto/ec'
import { arrayToBase64, base64ToArray } from '../../src/crypto/utils'
import { encodeSpki, encodePkcs8, parseSpki, parsePkcs8, DerError } from '../../src/crypto/primitives/der'
import * as p256 from '../../src/crypto/primitives/p256'
import { randomBytes } from '../../src/crypto/primitives/random'
import { toArrayBuffer } from '../../src/crypto/primitives/buffer'
import { gcmEncrypt } from '../../src/crypto/primitives/aes'
import { isEzCryptoKey } from '../../src/crypto/key'

const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text)

describe('hardening', () => {
  describe('adopting a WebCrypto key', () => {
    test('an extractable AES key can be adopted and used', async () => {
      const rawKey = crypto.getRandomValues(new Uint8Array(32))
      const native = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', true, ['encrypt', 'decrypt'])

      const encrypted = await AESEncrypt(native, arrayToBase64(utf8('adopted')))
      expect(await AESDecrypt(arrayToBase64(rawKey), encrypted.iv, encrypted.ciphertext, true)).toBe('adopted')
    })

    test('the same native key adopts to the same object twice', async () => {
      const native = await crypto.subtle.importKey('raw', crypto.getRandomValues(new Uint8Array(32)), 'AES-GCM', true, [
        'encrypt',
        'decrypt',
      ])

      const first = await AESImportKey(native)
      const second = await AESImportKey(native)

      expect(first).toBe(second)
      expect(isEzCryptoKey(first)).toBe(true)
    })

    test('an extractable EC private key can be adopted', async () => {
      const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
      const data = arrayToBase64(utf8('sign me'))

      const signature = await EcSignData(pair.privateKey, data)
      const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))

      expect(await EcVerifySig(arrayToBase64(publicKey), signature, data)).toBe(true)
    })

    test('a NON-extractable WebCrypto key is refused, and says why', async () => {
      // The honest failure. The platform holds this material; JS cannot reach it, so a
      // pure-JS implementation cannot use the key -- and must not pretend otherwise.
      const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, [
        'deriveKey',
        'deriveBits',
      ])

      await expect(EcdhConvertKey(pair.privateKey)).rejects.toThrow(/non-extractable/i)
    })
  })

  describe('EC key conversion', () => {
    test('rejects a public key that is not on the curve', async () => {
      const keys = await EcMakeCryptKeys(true)
      const point = base64ToArray(keys.rawPublicKey)
      point[64] ^= 0x01 // perturb the last byte of Y

      await expect(EcdhConvertKey(arrayToBase64(point))).rejects.toThrow('UNRECOGNIZED KEY FORMAT')
    })

    test('rejects an off-curve "lite" point too', async () => {
      const keys = await EcMakeCryptKeys(true)
      const lite = base64ToArray(keys.rawPublicKeyLite)
      lite[63] ^= 0x01

      await expect(EcdhConvertKey(arrayToBase64(lite))).rejects.toThrow('UNRECOGNIZED KEY FORMAT')
    })

    test('an off-curve peer key cannot reach the ECDH exchange', async () => {
      // The invalid-curve attack: feed a point from a weaker curve and read the private
      // key out of the resulting shared secrets. Validation has to happen before the multiply.
      const keys = await EcMakeCryptKeys(true)
      const point = base64ToArray(keys.rawPublicKey)
      point[40] ^= 0xff

      await expect(
        EcEncrypt(keys.privateKey as string, arrayToBase64(point), arrayToBase64(utf8('x')))
      ).rejects.toThrow()
    })

    test('rejects well-formed base64 that is not a key at all', async () => {
      await expect(EcdhConvertKey(arrayToBase64(randomBytes(50)))).rejects.toThrow('UNRECOGNIZED KEY FORMAT')
      await expect(EcdsaConvertKey(arrayToBase64(randomBytes(200)))).rejects.toThrow('UNRECOGNIZED KEY FORMAT')
      await expect(EcdhConvertKey('')).rejects.toThrow('UNRECOGNIZED KEY FORMAT')
    })

    test('rejects a non-string, non-CryptoKey', async () => {
      // @ts-expect-error - deliberately wrong
      await expect(EcdhConvertKey(123)).rejects.toThrow('Invalid key format')
      // @ts-expect-error - deliberately wrong
      await expect(EcdsaConvertKey(null)).rejects.toThrow('Invalid key format')
    })

    test('signing refuses a public key', async () => {
      const keys = await EcMakeSigKeys(true)

      await expect(EcSignData(keys.publicKey, arrayToBase64(utf8('x')))).rejects.toThrow(/private key/i)
    })
  })

  describe('DER', () => {
    test('rejects truncated, empty, and over-long input', () => {
      expect(() => parseSpki(new Uint8Array(0))).toThrow(DerError)
      expect(() => parseSpki(new Uint8Array([0x30]))).toThrow(DerError)
      expect(() => parseSpki(new Uint8Array([0x30, 0x82, 0xff, 0xff, 0x00]))).toThrow(DerError)
      expect(() => parsePkcs8(new Uint8Array([0x30, 0x05, 0x02, 0x01, 0x00]))).toThrow(DerError)
    })

    test('rejects the wrong outer tag', () => {
      const { publicKey } = p256.generateKeyPair()
      const spki = encodeSpki(publicKey)
      spki[0] = 0x31 // SET instead of SEQUENCE

      expect(() => parseSpki(spki)).toThrow(DerError)
    })

    test('rejects a key on the wrong curve', () => {
      const { publicKey } = p256.generateKeyPair()
      const spki = encodeSpki(publicKey)

      // Corrupt the last byte of the prime256v1 OID.
      const curveOidEnd = spki.indexOf(0x07, 15)
      spki[curveOidEnd] = 0x08 // -> some other curve

      expect(() => parseSpki(spki)).toThrow(/curve OID/i)
    })

    test('rejects a compressed point where an uncompressed one belongs', () => {
      const { publicKey } = p256.generateKeyPair()
      const spki = encodeSpki(publicKey)
      spki[spki.length - 65] = 0x02 // uncompressed 0x04 -> compressed 0x02

      expect(() => parseSpki(spki)).toThrow(/uncompressed/i)
    })

    test('refuses to encode a malformed point or scalar', () => {
      const { privateKey, publicKey } = p256.generateKeyPair()

      expect(() => encodeSpki(new Uint8Array(64))).toThrow(DerError)
      expect(() => encodePkcs8(new Uint8Array(31), publicKey)).toThrow(DerError)
      expect(() => encodePkcs8(privateKey, new Uint8Array(64))).toThrow(DerError)
    })
  })

  describe('P-256', () => {
    test('rejects scalars outside [1, n-1]', () => {
      const zero = new Uint8Array(32)
      expect(() => p256.derivePublicKey(zero)).toThrow(p256.CurveError)

      // n itself is out of range; so is anything above it.
      const order = new Uint8Array(32)
      const orderHex = p256.N.toString(16)
      for (let i = 0; i < 32; i += 1) {
        order[i] = parseInt(orderHex.slice(i * 2, i * 2 + 2), 16)
      }
      expect(() => p256.derivePublicKey(order)).toThrow(p256.CurveError)

      expect(() => p256.derivePublicKey(new Uint8Array(31))).toThrow(/32 bytes/i)
    })

    test('rejects malformed point encodings', () => {
      expect(() => p256.decodePoint(new Uint8Array(65))).toThrow(p256.CurveError) // 0x00 tag
      expect(() => p256.decodePoint(new Uint8Array(64))).toThrow(p256.CurveError) // wrong length

      const compressed = new Uint8Array(33)
      compressed[0] = 0x02
      expect(() => p256.decodePoint(compressed)).toThrow(p256.CurveError)
    })

    test('verify() returns false rather than throwing on junk', () => {
      const { publicKey } = p256.generateKeyPair()

      expect(p256.verify(publicKey, new Uint8Array(10), utf8('x'))).toBe(false) // wrong sig length
      expect(p256.verify(new Uint8Array(65), new Uint8Array(64), utf8('x'))).toBe(false) // bad key

      // r and s must both be in [1, n-1]; an all-0xff signature is not.
      expect(p256.verify(publicKey, new Uint8Array(64).fill(0xff), utf8('x'))).toBe(false)
    })
  })

  describe('AES-GCM', () => {
    test('a tampered ciphertext body fails authentication', async () => {
      const key = arrayToBase64(randomBytes(32))
      const encrypted = await AESEncrypt(key, arrayToBase64(utf8('authentic')))

      const tampered = base64ToArray(encrypted.ciphertext)
      tampered[0] ^= 0x01

      await expect(AESDecrypt(key, encrypted.iv, arrayToBase64(tampered), true)).rejects.toThrow(/authentication/i)
    })

    test('the wrong key fails authentication rather than returning garbage', async () => {
      const encrypted = await AESEncrypt(arrayToBase64(randomBytes(32)), arrayToBase64(utf8('secret')))

      await expect(
        AESDecrypt(arrayToBase64(randomBytes(32)), encrypted.iv, encrypted.ciphertext, true)
      ).rejects.toThrow(/authentication/i)
    })

    test('rejects a key that is not a legal AES size', () => {
      expect(() => gcmEncrypt(randomBytes(20), randomBytes(12), utf8('x'))).toThrow(/key length/i)
    })
  })

  describe('misc', () => {
    test('randomBytes rejects a negative or fractional length', () => {
      expect(() => randomBytes(-1)).toThrow()
      expect(() => randomBytes(1.5)).toThrow()
      expect(randomBytes(0).length).toBe(0)
    })

    test('toArrayBuffer copies a view rather than exposing its neighbours', () => {
      const backing = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])
      const view = backing.subarray(2, 5)

      const buffer = toArrayBuffer(view)

      expect(buffer.byteLength).toBe(3)
      expect(Array.from(new Uint8Array(buffer))).toEqual([3, 4, 5])
      expect(buffer).not.toBe(backing.buffer)
    })
  })
})
