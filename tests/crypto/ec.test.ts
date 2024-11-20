import { describe, expect, test } from '@jest/globals'
import { EcMakeCryptKeys, EcEncrypt, EcDecrypt } from '../../src/crypto/ec'
import { arrayToBase64 } from '../../src/crypto/utils'
import type { ECKeyPair } from '../../src/crypto/types'

describe('EC Encryption Operations', () => {
  describe('EcMakeCryptKeys', () => {
    test('should generate fully exportable key pair', async () => {
      const keys = await EcMakeCryptKeys(true)
      expect(keys).toHaveProperty('publicKey')
      expect(keys).toHaveProperty('privateKey')
      expect(keys).toHaveProperty('rawPublicKey')
      expect(keys).toHaveProperty('rawPublicKeyLite')

      // Verify string formats
      expect(typeof keys.publicKey).toBe('string')
      expect(typeof keys.privateKey).toBe('string')
      expect(typeof keys.rawPublicKey).toBe('string')
      expect(typeof keys.rawPublicKeyLite).toBe('string')

      // Verify base64 format
      expect(() => Buffer.from(keys.publicKey, 'base64')).not.toThrow()
      expect(() => Buffer.from(keys.privateKey as string, 'base64')).not.toThrow()
      expect(() => Buffer.from(keys.rawPublicKey, 'base64')).not.toThrow()
      expect(() => Buffer.from(keys.rawPublicKeyLite, 'base64')).not.toThrow()
    })

    test('should generate partially exportable key pair', async () => {
      const keys = await EcMakeCryptKeys(false)
      expect(keys).toHaveProperty('publicKey')
      expect(keys).toHaveProperty('privateKey')
      expect(keys).toHaveProperty('rawPublicKey')
      expect(keys).toHaveProperty('rawPublicKeyLite')

      // Public key and raw keys should be strings
      expect(typeof keys.publicKey).toBe('string')
      expect(typeof keys.rawPublicKey).toBe('string')
      expect(typeof keys.rawPublicKeyLite).toBe('string')

      // Private key should be CryptoKey
      expect(keys.privateKey).toHaveProperty('type')
      expect(keys.privateKey).toHaveProperty('algorithm')
      const privateKey = keys.privateKey as CryptoKey
      expect(privateKey.type).toBe('private')
      expect((privateKey.algorithm as EcKeyAlgorithm).name).toBe('ECDH')
      expect((privateKey.algorithm as EcKeyAlgorithm).namedCurve).toBe('P-256')
    })

    test('rawPublicKeyLite should be shorter than rawPublicKey', async () => {
      const keys = await EcMakeCryptKeys(true)
      const rawLength = Buffer.from(keys.rawPublicKey, 'base64').length
      const liteLength = Buffer.from(keys.rawPublicKeyLite, 'base64').length
      expect(liteLength).toBeLessThan(rawLength)
    })

    test('should generate unique key pairs', async () => {
      const keys1 = await EcMakeCryptKeys(true)
      const keys2 = await EcMakeCryptKeys(true)
      expect(keys1.publicKey).not.toBe(keys2.publicKey)
      expect(keys1.privateKey).not.toBe(keys2.privateKey)
      expect(keys1.rawPublicKey).not.toBe(keys2.rawPublicKey)
      expect(keys1.rawPublicKeyLite).not.toBe(keys2.rawPublicKeyLite)
    })
  })

  describe('EcEncrypt and EcDecrypt', () => {
    test('should encrypt and decrypt with base64 keys', async () => {
      const keys = await EcMakeCryptKeys(true)
      const data = arrayToBase64(new TextEncoder().encode('test data'))

      const encrypted = await EcEncrypt(keys.privateKey as string, keys.publicKey, data)

      expect(encrypted).toHaveProperty('ciphertext')
      expect(encrypted).toHaveProperty('iv')

      const decrypted = await EcDecrypt(
        keys.privateKey as string,
        keys.publicKey,
        encrypted.iv,
        encrypted.ciphertext,
        true
      )

      expect(decrypted).toBe('test data')
    })

    test('should encrypt and decrypt with CryptoKey format', async () => {
      const keys = await EcMakeCryptKeys(false)
      const data = arrayToBase64(new TextEncoder().encode('test data'))

      const encrypted = await EcEncrypt(keys.privateKey, keys.publicKey, data)

      const decrypted = await EcDecrypt(keys.privateKey, keys.publicKey, encrypted.iv, encrypted.ciphertext, true)

      expect(decrypted).toBe('test data')
    })

    test('should handle various key format combinations', async () => {
      const keys = await EcMakeCryptKeys(true)
      const data = arrayToBase64(new TextEncoder().encode('test data'))

      // Test with raw public key
      const encryptedRaw = await EcEncrypt(keys.privateKey as string, keys.rawPublicKey, data)

      let decrypted = await EcDecrypt(
        keys.privateKey as string,
        keys.rawPublicKey,
        encryptedRaw.iv,
        encryptedRaw.ciphertext,
        true
      )
      expect(decrypted).toBe('test data')

      // Test with raw public key lite
      const encryptedLite = await EcEncrypt(keys.privateKey as string, keys.rawPublicKeyLite, data)

      decrypted = await EcDecrypt(
        keys.privateKey as string,
        keys.rawPublicKeyLite,
        encryptedLite.iv,
        encryptedLite.ciphertext,
        true
      )
      expect(decrypted).toBe('test data')
    })

    test('should return ArrayBuffer when returnText is false', async () => {
      const keys = await EcMakeCryptKeys(true)
      const data = arrayToBase64(new TextEncoder().encode('test data'))

      const encrypted = await EcEncrypt(keys.privateKey as string, keys.publicKey, data)

      const decrypted = await EcDecrypt(
        keys.privateKey as string,
        keys.publicKey,
        encrypted.iv,
        encrypted.ciphertext,
        false
      )

      expect(decrypted).toBeInstanceOf(ArrayBuffer)
      expect(new TextDecoder().decode(new Uint8Array(decrypted as ArrayBuffer))).toBe('test data')
    })

    test('should throw error for invalid keys', async () => {
      const invalidKey = 'invalid-key'
      const data = arrayToBase64(new TextEncoder().encode('test data'))

      await expect(EcEncrypt(invalidKey, invalidKey, data)).rejects.toThrow()
    })
  })

  describe('End-to-end encryption cycle', () => {
    test('should handle various data types and sizes', async () => {
      const testCases = [
        'Simple text',
        'Unicode text 🔐',
        'A'.repeat(1000), // Large text
        JSON.stringify({ key: 'value', nested: { array: [1, 2, 3] } }), // JSON data
        Buffer.from([1, 2, 3, 4, 5]).toString('base64'), // Binary data
      ]

      const keys = await EcMakeCryptKeys(true)

      for (const testCase of testCases) {
        const data = arrayToBase64(new TextEncoder().encode(testCase))
        const encrypted = await EcEncrypt(keys.privateKey as string, keys.publicKey, data)
        const decrypted = await EcDecrypt(
          keys.privateKey as string,
          keys.publicKey,
          encrypted.iv,
          encrypted.ciphertext,
          true
        )
        expect(decrypted).toBe(testCase)
      }
    })

    test('should work with different key pairs', async () => {
      const keys1 = await EcMakeCryptKeys(true)
      const keys2 = await EcMakeCryptKeys(true)
      const data = arrayToBase64(new TextEncoder().encode('test data'))

      // Encrypt with keys1 private and keys2 public
      const encrypted = await EcEncrypt(keys1.privateKey as string, keys2.publicKey, data)

      // Decrypt with keys2 private and keys1 public
      const decrypted = await EcDecrypt(
        keys2.privateKey as string,
        keys1.publicKey,
        encrypted.iv,
        encrypted.ciphertext,
        true
      )

      expect(decrypted).toBe('test data')
    })
  })
})
