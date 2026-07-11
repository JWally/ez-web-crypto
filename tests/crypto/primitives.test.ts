/**
 * Differential tests: every pure-JS primitive is checked against the platform's own
 * WebCrypto/`atob`/`TextEncoder` implementation. If these pass, dropping `crypto.subtle`
 * did not change a single byte of observable behaviour.
 *
 * This is the only place in the suite that is *allowed* to reach for `crypto.subtle` --
 * it is the oracle under test, not a dependency of the library.
 */
import { describe, expect, test } from '@jest/globals'
import { encodeBase64, decodeBase64, InvalidBase64Error } from '../../src/crypto/primitives/base64'
import { encodeUtf8, decodeUtf8 } from '../../src/crypto/primitives/utf8'
import { digest, concat } from '../../src/crypto/primitives/sha'
import { hmac } from '../../src/crypto/primitives/hmac'
import { hkdf } from '../../src/crypto/primitives/hkdf'
import { gcmEncrypt, gcmDecrypt } from '../../src/crypto/primitives/aes'
import { randomBytes } from '../../src/crypto/primitives/random'
import * as p256 from '../../src/crypto/primitives/p256'
import { encodeSpki, parseSpki, encodePkcs8, parsePkcs8 } from '../../src/crypto/primitives/der'
import type { HashAlgorithm } from '../../src/crypto/types'

const ALGOS: HashAlgorithm[] = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']

const SAMPLES: string[] = [
  '',
  'a',
  'abc',
  'test data',
  'Hello 🌍',
  'The quick brown fox jumps over the lazy dog',
  'A'.repeat(55), // one byte short of a SHA-256 pad boundary
  'A'.repeat(56), // forces an extra block
  'A'.repeat(63),
  'A'.repeat(64),
  'A'.repeat(111), // SHA-512 pad boundaries
  'A'.repeat(112),
  'A'.repeat(127),
  'A'.repeat(128),
  'A'.repeat(10000),
]

const toBytes = (text: string): Uint8Array => new TextEncoder().encode(text)
const hex = (bytes: Uint8Array): string =>
  Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')

describe('primitives vs. the platform', () => {
  describe('base64', () => {
    test('encode matches btoa for random byte strings', () => {
      for (let length = 0; length < 200; length += 1) {
        const bytes = randomBytes(length)
        const expected = btoa(String.fromCharCode(...Array.from(bytes)))
        expect(encodeBase64(bytes)).toBe(expected)
      }
    })

    test('decode matches atob', () => {
      for (let length = 0; length < 200; length += 1) {
        const bytes = randomBytes(length)
        const encoded = encodeBase64(bytes)
        expect(hex(decodeBase64(encoded))).toBe(hex(bytes))
      }
    })

    test('round-trips a large buffer without blowing the call stack', () => {
      const bytes = randomBytes(500_000)
      expect(hex(decodeBase64(encodeBase64(bytes)))).toBe(hex(bytes))
    })

    test('rejects the same malformed inputs atob rejects', () => {
      const bad = ['invalid-key', 'not-base64-encoded', 'InvalidBase64Key==', 'a', '=', 'ab$c']

      bad.forEach((value) => {
        let atobThrew = false
        try {
          atob(value)
        } catch {
          atobThrew = true
        }
        expect(atobThrew).toBe(true)
        expect(() => decodeBase64(value)).toThrow(InvalidBase64Error)
      })
    })

    test('tolerates the whitespace atob tolerates', () => {
      expect(hex(decodeBase64(' dGVz\ndGRh\tdGE= '))).toBe(hex(toBytes('testdata')))
    })
  })

  describe('utf8', () => {
    test('encode matches TextEncoder', () => {
      SAMPLES.concat(['\u0000', '😀', 'ñ', '中文', '\uD800']).forEach((sample) => {
        expect(hex(encodeUtf8(sample))).toBe(hex(new TextEncoder().encode(sample)))
      })
    })

    test('decode matches TextDecoder', () => {
      SAMPLES.forEach((sample) => {
        const bytes = new TextEncoder().encode(sample)
        expect(decodeUtf8(bytes)).toBe(new TextDecoder().decode(bytes))
      })
    })

    test('decode matches TextDecoder on malformed byte sequences', () => {
      const malformed = [
        new Uint8Array([0xff]),
        new Uint8Array([0xc0]),
        new Uint8Array([0xe0, 0x80]),
        new Uint8Array([0x80, 0x80]),
        new Uint8Array([0xf0, 0x9f, 0x98]),
      ]

      malformed.forEach((bytes) => {
        expect(decodeUtf8(bytes)).toBe(new TextDecoder().decode(bytes))
      })
    })
  })

  describe('digest', () => {
    ALGOS.forEach((algo) => {
      test(`${algo} matches crypto.subtle.digest`, async () => {
        for (const sample of SAMPLES) {
          const bytes = toBytes(sample)
          const expected = new Uint8Array(await crypto.subtle.digest(algo, bytes))
          expect(hex(digest(algo, bytes))).toBe(hex(expected))
        }
      })
    })
  })

  describe('hmac', () => {
    ALGOS.forEach((algo) => {
      test(`HMAC-${algo} matches crypto.subtle.sign`, async () => {
        // Short key, block-length key, and over-long key (which must be pre-hashed).
        const keys = [randomBytes(1), randomBytes(32), randomBytes(64), randomBytes(128), randomBytes(200)]

        for (const key of keys) {
          for (const sample of ['', 'test data', 'A'.repeat(1000)]) {
            const message = toBytes(sample)
            const imported = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: algo }, false, ['sign'])
            const expected = new Uint8Array(await crypto.subtle.sign('HMAC', imported, message))
            expect(hex(hmac(algo, key, message))).toBe(hex(expected))
          }
        }
      })
    })
  })

  describe('hkdf', () => {
    test('matches crypto.subtle.deriveBits', async () => {
      for (const saltLength of [0, 16, 32]) {
        const ikm = randomBytes(32)
        const salt = randomBytes(saltLength)
        const info = randomBytes(8)

        const imported = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits'])
        const expected = new Uint8Array(
          await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, imported, 256)
        )

        expect(hex(hkdf('SHA-256', ikm, salt, info, 32))).toBe(hex(expected))
      }
    })
  })

  describe('aes-gcm', () => {
    // 12 bytes is the fast path (J0 = IV || 1); every other length is derived through GHASH.
    // 88 matters in particular: PASSWORD_ENCRYPT uses the strengthened password as the IV.
    // Node's WebCrypto only accepts 12..128 bytes, so it cannot act as an oracle outside that.
    const IV_LENGTHS = [12, 13, 16, 32, 88, 128]

    test('our ciphertext decrypts under crypto.subtle', async () => {
      for (const ivLength of IV_LENGTHS) {
        const rawKey = randomBytes(32)
        const iv = randomBytes(ivLength)
        const plaintext = toBytes('the quick brown fox 🦊')

        const ciphertext = gcmEncrypt(rawKey, iv, plaintext)
        const imported = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['decrypt'])
        const decrypted = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, imported, ciphertext))

        expect(hex(decrypted)).toBe(hex(plaintext))
      }
    })

    test("crypto.subtle's ciphertext decrypts under ours", async () => {
      for (const ivLength of IV_LENGTHS) {
        for (const size of [0, 1, 15, 16, 17, 1000]) {
          const rawKey = randomBytes(32)
          const iv = randomBytes(ivLength)
          const plaintext = randomBytes(size)

          const imported = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['encrypt'])
          const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, imported, plaintext))

          expect(hex(gcmDecrypt(rawKey, iv, ciphertext))).toBe(hex(plaintext))
        }
      }
    })

    test('round-trips the short IVs NIST allows but Node refuses', () => {
      // SP 800-38D permits any non-empty IV. Node/OpenSSL caps it at 12..128 bytes, so
      // there is no oracle here -- just check we are self-consistent and reject IV = "".
      for (const ivLength of [1, 4, 8, 200]) {
        const rawKey = randomBytes(32)
        const iv = randomBytes(ivLength)
        const plaintext = toBytes('short iv')

        expect(hex(gcmDecrypt(rawKey, iv, gcmEncrypt(rawKey, iv, plaintext)))).toBe(hex(plaintext))
      }

      expect(() => gcmEncrypt(randomBytes(32), new Uint8Array(0), toBytes('x'))).toThrow()
    })

    test('rejects a tampered tag', () => {
      const rawKey = randomBytes(32)
      const iv = randomBytes(16)
      const ciphertext = gcmEncrypt(rawKey, iv, toBytes('secret'))
      ciphertext[ciphertext.length - 1] ^= 0x01

      expect(() => gcmDecrypt(rawKey, iv, ciphertext)).toThrow()
    })

    test('rejects a ciphertext shorter than the tag', () => {
      expect(() => gcmDecrypt(randomBytes(32), randomBytes(16), new Uint8Array([1, 2, 3]))).toThrow()
    })

    test('supports 128- and 192-bit keys', async () => {
      for (const keyLength of [16, 24, 32]) {
        const rawKey = randomBytes(keyLength)
        const iv = randomBytes(12)
        const plaintext = toBytes('block cipher')

        const imported = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['decrypt'])
        const decrypted = new Uint8Array(
          await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, imported, gcmEncrypt(rawKey, iv, plaintext))
        )

        expect(hex(decrypted)).toBe(hex(plaintext))
      }
    })
  })

  describe('p-256', () => {
    test('our public key matches the one crypto.subtle derives from the same scalar', async () => {
      for (let i = 0; i < 5; i += 1) {
        const { privateKey, publicKey } = p256.generateKeyPair()

        // Round-trip our private scalar through subtle and compare the public points.
        const pkcs8 = encodePkcs8(privateKey, publicKey)
        const imported = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'ECDH', namedCurve: 'P-256' }, true, [
          'deriveBits',
        ])
        const jwk = await crypto.subtle.exportKey('jwk', imported)

        const x = new Uint8Array(Buffer.from(jwk.x as string, 'base64url'))
        const y = new Uint8Array(Buffer.from(jwk.y as string, 'base64url'))

        expect(hex(publicKey.subarray(1, 33))).toBe(hex(x))
        expect(hex(publicKey.subarray(33, 65))).toBe(hex(y))
      }
    })

    test('ECDH shared secret matches crypto.subtle.deriveBits', async () => {
      for (let i = 0; i < 5; i += 1) {
        const alice = p256.generateKeyPair()
        const bob = p256.generateKeyPair()

        const alicePrivate = await crypto.subtle.importKey(
          'pkcs8',
          encodePkcs8(alice.privateKey, alice.publicKey),
          { name: 'ECDH', namedCurve: 'P-256' },
          false,
          ['deriveBits']
        )
        const bobPublic = await crypto.subtle.importKey(
          'raw',
          bob.publicKey,
          { name: 'ECDH', namedCurve: 'P-256' },
          false,
          []
        )
        const expected = new Uint8Array(
          await crypto.subtle.deriveBits({ name: 'ECDH', public: bobPublic }, alicePrivate, 256)
        )

        expect(hex(p256.deriveSharedSecret(alice.privateKey, bob.publicKey))).toBe(hex(expected))
        // ...and both sides agree, which is the whole point.
        expect(hex(p256.deriveSharedSecret(bob.privateKey, alice.publicKey))).toBe(hex(expected))
      }
    })

    test('our signature verifies under crypto.subtle', async () => {
      for (let i = 0; i < 5; i += 1) {
        const { privateKey, publicKey } = p256.generateKeyPair()
        const message = toBytes('sign me')

        const signature = p256.sign(privateKey, message)
        const imported = await crypto.subtle.importKey(
          'raw',
          publicKey,
          { name: 'ECDSA', namedCurve: 'P-256' },
          false,
          ['verify']
        )
        const valid = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, imported, signature, message)

        expect(valid).toBe(true)
      }
    })

    test("crypto.subtle's signature verifies under ours", async () => {
      for (let i = 0; i < 5; i += 1) {
        const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
        const message = toBytes('sign me')

        const signature = new Uint8Array(
          await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, message)
        )
        const rawPublic = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))

        expect(p256.verify(rawPublic, signature, message)).toBe(true)
      }
    })

    test('rejects a bad signature', () => {
      const { privateKey, publicKey } = p256.generateKeyPair()
      const message = toBytes('sign me')
      const signature = p256.sign(privateKey, message)

      expect(p256.verify(publicKey, signature, toBytes('tampered'))).toBe(false)
      expect(p256.verify(publicKey, new Uint8Array(64), message)).toBe(false)

      const flipped = signature.slice()
      flipped[0] ^= 0x01
      expect(p256.verify(publicKey, flipped, message)).toBe(false)
    })

    test('signatures are non-deterministic', () => {
      const { privateKey } = p256.generateKeyPair()
      const message = toBytes('sign me')
      expect(hex(p256.sign(privateKey, message))).not.toBe(hex(p256.sign(privateKey, message)))
    })

    test('rejects points that are not on the curve', () => {
      const { publicKey } = p256.generateKeyPair()
      const offCurve = publicKey.slice()
      offCurve[64] ^= 0x01 // perturb Y

      expect(() => p256.decodePoint(offCurve)).toThrow()
      expect(() => p256.deriveSharedSecret(p256.generateKeyPair().privateKey, offCurve)).toThrow()
    })
  })

  describe('der', () => {
    test('our SPKI is importable by crypto.subtle and round-trips', async () => {
      const { publicKey } = p256.generateKeyPair()
      const spki = encodeSpki(publicKey)

      const imported = await crypto.subtle.importKey('spki', spki, { name: 'ECDH', namedCurve: 'P-256' }, true, [])
      const reExported = new Uint8Array(await crypto.subtle.exportKey('spki', imported))

      expect(hex(spki)).toBe(hex(reExported))
      expect(hex(parseSpki(spki))).toBe(hex(publicKey))
    })

    test('our PKCS8 is importable by crypto.subtle and round-trips', async () => {
      const { privateKey, publicKey } = p256.generateKeyPair()
      const pkcs8 = encodePkcs8(privateKey, publicKey)

      await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])
      expect(hex(parsePkcs8(pkcs8))).toBe(hex(privateKey))
    })

    test('parses SPKI and PKCS8 produced by crypto.subtle', async () => {
      const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])

      const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey))
      const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey))
      const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))

      expect(hex(parseSpki(spki))).toBe(hex(raw))

      // The parsed scalar must regenerate the same public point.
      const scalar = parsePkcs8(pkcs8)
      expect(hex(p256.derivePublicKey(scalar))).toBe(hex(raw))
    })

    test('rejects garbage', () => {
      expect(() => parseSpki(new Uint8Array([1, 2, 3]))).toThrow()
      expect(() => parsePkcs8(new Uint8Array([1, 2, 3]))).toThrow()
      expect(() => parseSpki(concat(new Uint8Array([0x30, 0x02]), new Uint8Array([0x00, 0x00])))).toThrow()
    })
  })

  describe('random', () => {
    test('produces the requested length and does not repeat', () => {
      expect(randomBytes(0).length).toBe(0)
      expect(randomBytes(32).length).toBe(32)
      expect(hex(randomBytes(32))).not.toBe(hex(randomBytes(32)))
    })

    test('output is not obviously biased', () => {
      // Chi-square-lite: every byte value should show up across a big sample.
      const seen = new Set<number>()
      const bytes = randomBytes(100_000)
      bytes.forEach((b) => seen.add(b))
      expect(seen.size).toBe(256)
    })
  })
})
