import { describe, expect, test } from '@jest/globals'
import { AESMakeKey, AESImportKey, AESEncrypt, AESDecrypt } from '../../src/crypto/aes'
import { initializeCrypto } from '../../src/crypto/init'
import { arrayToBase64, base64ToArray } from '../../src/crypto/utils'

describe('AES Cryptographic Operations', () => {
  describe('AESMakeKey', () => {
    test('should generate exportable key in base64 format', async () => {
      const key = await AESMakeKey(true)
      expect(typeof key).toBe('string')
      // AES-256 key should be 32 bytes (256 bits)
      expect(base64ToArray(key as string).length).toBe(32)
    })

    test('should generate non-exportable CryptoKey', async () => {
      const key = await AESMakeKey(false)
      expect(key).toHaveProperty('type')
      expect(key).toHaveProperty('algorithm')
      const algorithm = (key as CryptoKey).algorithm as AesKeyAlgorithm
      expect(algorithm.name).toBe('AES-GCM')
      expect(algorithm.length).toBe(256)
    })

    test('generated key should have correct usage rights', async () => {
      const key = (await AESMakeKey(false)) as CryptoKey
      expect(key.usages).toContain('encrypt')
      expect(key.usages).toContain('decrypt')
      expect(key.usages.length).toBe(2)
    })
  })

  describe('AESImportKey', () => {
    test('should import base64 key', async () => {
      const originalKey = await AESMakeKey(true)
      const importedKey = await AESImportKey(originalKey as string)
      expect(importedKey).toHaveProperty('type')
      expect(importedKey).toHaveProperty('algorithm')
      expect((importedKey.algorithm as AesKeyAlgorithm).name).toBe('AES-GCM')
    })

    test('should return same key if CryptoKey is provided', async () => {
      const cryptoKey = await AESImportKey(await AESMakeKey(true))
      const reimportedKey = await AESImportKey(cryptoKey)
      expect(reimportedKey).toBe(cryptoKey)
    })

    test('should respect exportable flag', async () => {
      const originalKey = await AESMakeKey(true)
      const nonExportableKey = await AESImportKey(originalKey as string, false)
      expect(nonExportableKey.extractable).toBe(false)
    })

    test('should throw error for invalid key format', async () => {
      const invalidKey = 'invalid-base64-key'
      await expect(AESImportKey(invalidKey)).rejects.toThrow()
    })
  })

  describe('AESEncrypt', () => {
    test('should encrypt data with generated IV', async () => {
      const key = await AESMakeKey(true)
      const data = arrayToBase64(new TextEncoder().encode('test data'))
      const result = await AESEncrypt(key, data)

      expect(result).toHaveProperty('ciphertext')
      expect(result).toHaveProperty('iv')
      expect(base64ToArray(result.iv).length).toBe(16) // IV should be 16 bytes
    })

    test('should encrypt data with provided IV', async () => {
      const key = await AESMakeKey(true)
      const data = arrayToBase64(new TextEncoder().encode('test data'))
      const customIV = arrayToBase64(new Uint8Array(16))
      const result = await AESEncrypt(key, data, customIV)

      expect(result.iv).toBe(customIV)
      expect(result.ciphertext).toBeTruthy()
    })

    test('should produce different ciphertext with different IVs', async () => {
      const key = await AESMakeKey(true)
      const data = arrayToBase64(new TextEncoder().encode('test data'))
      const result1 = await AESEncrypt(key, data)
      const result2 = await AESEncrypt(key, data)

      expect(result1.ciphertext).not.toBe(result2.ciphertext)
      expect(result1.iv).not.toBe(result2.iv)
    })

    test('should work with non-exportable CryptoKey', async () => {
      const key = await AESMakeKey(false)
      const data = arrayToBase64(new TextEncoder().encode('test data'))
      const result = await AESEncrypt(key, data)

      expect(result.ciphertext).toBeTruthy()
      expect(result.iv).toBeTruthy()
    })
  })

  describe('AESDecrypt', () => {
    test('should decrypt to original text when returnText is true', async () => {
      const key = await AESMakeKey(true)
      const originalText = 'test data'
      const data = arrayToBase64(new TextEncoder().encode(originalText))
      const encrypted = await AESEncrypt(key, data)
      const decrypted = await AESDecrypt(key, encrypted.iv, encrypted.ciphertext, true)

      expect(decrypted).toBe(originalText)
    })

    test('should decrypt to ArrayBuffer when returnText is false', async () => {
      const key = await AESMakeKey(true)
      const originalText = 'test data'
      const data = arrayToBase64(new TextEncoder().encode(originalText))
      const encrypted = await AESEncrypt(key, data)
      const decrypted = await AESDecrypt(key, encrypted.iv, encrypted.ciphertext, false)

      expect(decrypted).toBeInstanceOf(ArrayBuffer)
      expect(new TextDecoder().decode(new Uint8Array(decrypted as ArrayBuffer))).toBe(originalText)
    })

    test('should work with imported keys', async () => {
      const exportableKey = await AESMakeKey(true)
      const importedKey = await AESImportKey(exportableKey)
      const data = arrayToBase64(new TextEncoder().encode('test data'))
      const encrypted = await AESEncrypt(exportableKey, data)
      const decrypted = await AESDecrypt(importedKey, encrypted.iv, encrypted.ciphertext, true)

      expect(decrypted).toBe('test data')
    })

    test('should throw error for invalid ciphertext', async () => {
      const key = await AESMakeKey(true)
      const invalidCiphertext = arrayToBase64(new Uint8Array([1, 2, 3]))
      const validIV = arrayToBase64(new Uint8Array(16))

      await expect(AESDecrypt(key, validIV, invalidCiphertext, true)).rejects.toThrow()
    })

    test('should throw error for invalid IV', async () => {
      const key = await AESMakeKey(true)
      const data = arrayToBase64(new TextEncoder().encode('test data'))
      const encrypted = await AESEncrypt(key, data)
      const invalidIV = arrayToBase64(new Uint8Array([1, 2, 3])) // Wrong size IV

      await expect(AESDecrypt(key, invalidIV, encrypted.ciphertext, true)).rejects.toThrow()
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

      const key = await AESMakeKey(true)

      for (const testCase of testCases) {
        const data = arrayToBase64(new TextEncoder().encode(testCase))
        const encrypted = await AESEncrypt(key, data)
        const decrypted = await AESDecrypt(key, encrypted.iv, encrypted.ciphertext, true)
        expect(decrypted).toBe(testCase)
      }
    })
  })
})
