/**
 * Wire compatibility with the WebCrypto-backed implementation this replaces.
 *
 * The library is already deployed: there are ciphertexts at rest, keys in databases, and
 * peers on the other end of the wire still running `crypto.subtle`. Swapping the engine is
 * only safe if none of that notices. Each test here plays the role of the *old* code using
 * `crypto.subtle` directly, and checks the new code interoperates in both directions.
 *
 * The load-bearing detail is the ECDH -> AES key derivation. WebCrypto's
 * `deriveKey(ECDH -> AES-GCM-256)` uses the raw 256-bit X coordinate of the shared point
 * as the AES key, with no KDF in between. EcEncrypt/EcDecrypt have to do exactly that or
 * every existing ciphertext becomes undecryptable.
 */
import { describe, expect, test } from '@jest/globals'
import {
  AESEncrypt,
  AESDecrypt,
  EcMakeCryptKeys,
  EcEncrypt,
  EcDecrypt,
  EcMakeSigKeys,
  EcSignData,
  EcVerifySig,
  HKDFDecrypt,
  PASSWORD_DECRYPT,
  arrayToBase64,
  base64ToArray,
} from '../../src'
import type { ECKeyPairExportable } from '../../src/crypto/types'

const b64 = (bytes: ArrayBuffer | Uint8Array): string =>
  arrayToBase64(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes))

const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text)

/** What the old implementation did to turn a keypair into an AES key. */
const legacyDeriveAesKey = async (privateKeyB64: string, publicKeyB64: string): Promise<CryptoKey> => {
  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    base64ToArray(privateKeyB64),
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveKey', 'deriveBits']
  )
  const publicKey = await crypto.subtle.importKey(
    'spki',
    base64ToArray(publicKeyB64),
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    []
  )

  return crypto.subtle.deriveKey(
    { name: 'ECDH', public: publicKey },
    privateKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
}

describe('compatibility with the crypto.subtle implementation', () => {
  describe('keys we generate are readable by WebCrypto', () => {
    test('EcMakeCryptKeys emits importable SPKI and PKCS#8', async () => {
      const keys = await EcMakeCryptKeys(true)

      await expect(
        crypto.subtle.importKey('spki', base64ToArray(keys.publicKey), { name: 'ECDH', namedCurve: 'P-256' }, true, [])
      ).resolves.toBeDefined()

      await expect(
        crypto.subtle.importKey(
          'pkcs8',
          base64ToArray(keys.privateKey as string),
          { name: 'ECDH', namedCurve: 'P-256' },
          true,
          ['deriveBits']
        )
      ).resolves.toBeDefined()
    })

    test('rawPublicKey is an importable uncompressed point, and Lite is it minus the 0x04 tag', async () => {
      const keys = await EcMakeCryptKeys(true)

      const raw = base64ToArray(keys.rawPublicKey)
      const lite = base64ToArray(keys.rawPublicKeyLite)

      expect(raw.length).toBe(65)
      expect(raw[0]).toBe(0x04)
      expect(lite.length).toBe(64)
      expect(b64(raw.subarray(1))).toBe(keys.rawPublicKeyLite)

      await expect(
        crypto.subtle.importKey('raw', raw, { name: 'ECDH', namedCurve: 'P-256' }, true, [])
      ).resolves.toBeDefined()
    })

    test('the JWK we export describes the same point as the SPKI', async () => {
      const keys = (await EcMakeCryptKeys(true)) as ECKeyPairExportable

      const imported = await crypto.subtle.importKey(
        'spki',
        base64ToArray(keys.publicKey),
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        []
      )
      const jwk = await crypto.subtle.exportKey('jwk', imported)

      expect(keys.jwkPublicKey.x).toBe(jwk.x)
      expect(keys.jwkPublicKey.y).toBe(jwk.y)
      expect(keys.jwkPublicKey.crv).toBe('P-256')
    })
  })

  describe('AES-GCM', () => {
    test('ciphertext from the old implementation still decrypts', async () => {
      const rawKey = crypto.getRandomValues(new Uint8Array(32))
      const iv = crypto.getRandomValues(new Uint8Array(16))
      const plaintext = 'legacy payload 🔐'

      const legacyKey = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['encrypt'])
      const legacyCiphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, legacyKey, utf8(plaintext))

      const decrypted = await AESDecrypt(b64(rawKey), b64(iv), b64(legacyCiphertext), true)
      expect(decrypted).toBe(plaintext)
    })

    test('our ciphertext is readable by the old implementation', async () => {
      const rawKey = crypto.getRandomValues(new Uint8Array(32))
      const plaintext = 'forward payload'

      const encrypted = await AESEncrypt(b64(rawKey), b64(utf8(plaintext)))

      const legacyKey = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['decrypt'])
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: base64ToArray(encrypted.iv) },
        legacyKey,
        base64ToArray(encrypted.ciphertext)
      )

      expect(new TextDecoder().decode(new Uint8Array(decrypted))).toBe(plaintext)
    })
  })

  describe('ECDH (EcEncrypt / EcDecrypt)', () => {
    test('ciphertext from the old ECDH+AES path still decrypts', async () => {
      const keys = await EcMakeCryptKeys(true)
      const plaintext = 'legacy ec payload'

      const legacyKey = await legacyDeriveAesKey(keys.privateKey as string, keys.publicKey)
      const iv = crypto.getRandomValues(new Uint8Array(16))
      const legacyCiphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, legacyKey, utf8(plaintext))

      const decrypted = await EcDecrypt(keys.privateKey as string, keys.publicKey, b64(iv), b64(legacyCiphertext), true)

      expect(decrypted).toBe(plaintext)
    })

    test('our ECDH ciphertext is readable by the old path', async () => {
      const keys = await EcMakeCryptKeys(true)
      const plaintext = 'forward ec payload'

      const encrypted = await EcEncrypt(keys.privateKey as string, keys.publicKey, b64(utf8(plaintext)))

      const legacyKey = await legacyDeriveAesKey(keys.privateKey as string, keys.publicKey)
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: base64ToArray(encrypted.iv) },
        legacyKey,
        base64ToArray(encrypted.ciphertext)
      )

      expect(new TextDecoder().decode(new Uint8Array(decrypted))).toBe(plaintext)
    })

    test('a peer still running WebCrypto agrees on the shared key', async () => {
      // The realistic case: two different keypairs, one side upgraded and one not.
      const us = await EcMakeCryptKeys(true)
      const them = await EcMakeCryptKeys(true)
      const plaintext = 'cross-version handshake'

      // They encrypt with their private key + our public key, using the old code path.
      const theirKey = await legacyDeriveAesKey(them.privateKey as string, us.publicKey)
      const iv = crypto.getRandomValues(new Uint8Array(16))
      const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, theirKey, utf8(plaintext))

      // We decrypt with our private key + their public key, using the new code path.
      const decrypted = await EcDecrypt(us.privateKey as string, them.publicKey, b64(iv), b64(ciphertext), true)

      expect(decrypted).toBe(plaintext)
    })
  })

  describe('HKDF', () => {
    test('ciphertext from the old HKDF path still decrypts', async () => {
      const keys = await EcMakeCryptKeys(true)
      const plaintext = 'legacy hkdf payload'

      const privateKey = await crypto.subtle.importKey(
        'pkcs8',
        base64ToArray(keys.privateKey as string),
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        ['deriveBits']
      )
      const publicKey = await crypto.subtle.importKey(
        'spki',
        base64ToArray(keys.publicKey),
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        []
      )

      const sharedSecret = await crypto.subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256)
      const hkdfKey = await crypto.subtle.importKey('raw', sharedSecret, { name: 'HKDF' }, false, ['deriveBits'])

      const salt = crypto.getRandomValues(new Uint8Array(16))
      const iv = crypto.getRandomValues(new Uint8Array(16))

      const derived = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt, info: new Uint8Array([]) },
        hkdfKey,
        256
      )
      const aesKey = await crypto.subtle.importKey('raw', derived, 'AES-GCM', false, ['encrypt'])
      const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, utf8(plaintext))

      const decrypted = await HKDFDecrypt(
        keys.privateKey as string,
        keys.publicKey,
        b64(salt),
        b64(iv),
        b64(ciphertext),
        true
      )

      expect(decrypted).toBe(plaintext)
    })
  })

  describe('ECDSA', () => {
    test('a signature from the old implementation still verifies', async () => {
      const keys = await EcMakeSigKeys(true)
      const data = b64(utf8('sign me'))

      const privateKey = await crypto.subtle.importKey(
        'pkcs8',
        base64ToArray(keys.privateKey as string),
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign']
      )
      const legacySignature = await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        privateKey,
        base64ToArray(data)
      )

      expect(await EcVerifySig(keys.publicKey, b64(legacySignature), data)).toBe(true)
    })

    test('our signature still verifies under the old implementation', async () => {
      const keys = await EcMakeSigKeys(true)
      const data = b64(utf8('sign me'))

      const signature = await EcSignData(keys.privateKey as string, data)

      const publicKey = await crypto.subtle.importKey(
        'spki',
        base64ToArray(keys.publicKey),
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['verify']
      )
      const valid = await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        publicKey,
        base64ToArray(signature),
        base64ToArray(data)
      )

      expect(valid).toBe(true)
    })
  })

  describe('PASSWORD_ENCRYPT', () => {
    test('a payload from the old implementation still decrypts', async () => {
      // Replay the old algorithm exactly: 5,000 rounds of SHA-512 over the base64 digest,
      // btoa'd into an 88-byte GCM IV, wrapping a random AES key.
      const password = 'testPassword123'
      const plaintext = 'sensitive data'

      let strengthened = password
      for (let i = 0; i < 5000; i += 1) {
        const bytes = await crypto.subtle.digest('SHA-512', utf8(strengthened))
        strengthened = b64(bytes)
      }

      const rawKey = crypto.getRandomValues(new Uint8Array(32))
      const aes = b64(rawKey)
      const iv = base64ToArray(btoa(strengthened))

      const key = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['encrypt'])
      const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, utf8(plaintext))

      const legacyPayload = btoa(JSON.stringify({ ciphertext: b64(ciphertext), aes }))

      expect(await PASSWORD_DECRYPT(password, legacyPayload)).toBe(plaintext)
    })
  })
})
