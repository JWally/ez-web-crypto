import { HKDFEncrypt, HKDFDecrypt } from '../../src/crypto/hkdf'
import { EcMakeCryptKeys } from '../../src/crypto/ec'
import { arrayToBase64 } from '../../src/crypto/utils'
import { describe, expect, test, jest } from '@jest/globals'

describe('HKDF Cryptographic Operations', () => {
  describe('Basic Encryption/Decryption', () => {
    test('should encrypt and decrypt with base64 keys', async () => {
      const keys = await EcMakeCryptKeys(true)
      const data = arrayToBase64(new TextEncoder().encode('test data'))

      const encrypted = await HKDFEncrypt(keys.privateKey as string, keys.publicKey, data)

      expect(encrypted).toHaveProperty('ciphertext')
      expect(encrypted).toHaveProperty('salt')
      expect(encrypted).toHaveProperty('iv')

      const decrypted = await HKDFDecrypt(
        keys.privateKey as string,
        keys.publicKey,
        encrypted.salt,
        encrypted.iv,
        encrypted.ciphertext,
        true
      )

      expect(decrypted).toBe('test data')
    })

    test('should encrypt and decrypt with CryptoKey format', async () => {
      const keys = await EcMakeCryptKeys(false)
      const data = arrayToBase64(new TextEncoder().encode('test data'))

      const encrypted = await HKDFEncrypt(keys.privateKey, keys.publicKey, data)

      const decrypted = await HKDFDecrypt(
        keys.privateKey,
        keys.publicKey,
        encrypted.salt,
        encrypted.iv,
        encrypted.ciphertext,
        true
      )

      expect(decrypted).toBe('test data')
    })

    test('should return ArrayBuffer when returnText is false', async () => {
      const keys = await EcMakeCryptKeys(true)
      const data = arrayToBase64(new TextEncoder().encode('test data'))

      const encrypted = await HKDFEncrypt(keys.privateKey as string, keys.publicKey, data)

      const decrypted = await HKDFDecrypt(
        keys.privateKey as string,
        keys.publicKey,
        encrypted.salt,
        encrypted.iv,
        encrypted.ciphertext,
        false
      )

      expect(decrypted).toBeInstanceOf(ArrayBuffer)
      expect(new TextDecoder().decode(new Uint8Array(decrypted as ArrayBuffer))).toBe('test data')
    })
  })

  describe('Key Format Handling', () => {
    test('should work with raw public key format', async () => {
      const keys = await EcMakeCryptKeys(true)
      const data = arrayToBase64(new TextEncoder().encode('test data'))

      const encrypted = await HKDFEncrypt(keys.privateKey as string, keys.rawPublicKey, data)

      const decrypted = await HKDFDecrypt(
        keys.privateKey as string,
        keys.rawPublicKey,
        encrypted.salt,
        encrypted.iv,
        encrypted.ciphertext,
        true
      )

      expect(decrypted).toBe('test data')
    })

    test('should work with raw public key lite format', async () => {
      const keys = await EcMakeCryptKeys(true)
      const data = arrayToBase64(new TextEncoder().encode('test data'))

      const encrypted = await HKDFEncrypt(keys.privateKey as string, keys.rawPublicKeyLite, data)

      const decrypted = await HKDFDecrypt(
        keys.privateKey as string,
        keys.rawPublicKeyLite,
        encrypted.salt,
        encrypted.iv,
        encrypted.ciphertext,
        true
      )

      expect(decrypted).toBe('test data')
    })
  })

  describe('Cross-Key Operations', () => {
    test('should work with different key pairs', async () => {
      const keys1 = await EcMakeCryptKeys(true)
      const keys2 = await EcMakeCryptKeys(true)
      const data = arrayToBase64(new TextEncoder().encode('test data'))

      // Encrypt with keys1 private and keys2 public
      const encrypted = await HKDFEncrypt(keys1.privateKey as string, keys2.publicKey, data)

      // Decrypt with keys2 private and keys1 public
      const decrypted = await HKDFDecrypt(
        keys2.privateKey as string,
        keys1.publicKey,
        encrypted.salt,
        encrypted.iv,
        encrypted.ciphertext,
        true
      )

      expect(decrypted).toBe('test data')
    })
  })

  describe('Error Handling', () => {
    test('should throw error for invalid keys', async () => {
      const invalidKey = 'invalid-key'
      const data = arrayToBase64(new TextEncoder().encode('test data'))

      await expect(HKDFEncrypt(invalidKey, invalidKey, data)).rejects.toThrow()
    })

    test('should throw error for invalid salt', async () => {
      const keys = await EcMakeCryptKeys(true)
      const data = arrayToBase64(new TextEncoder().encode('test data'))
      const encrypted = await HKDFEncrypt(keys.privateKey as string, keys.publicKey, data)

      await expect(
        HKDFDecrypt(keys.privateKey as string, keys.publicKey, 'invalid-salt', encrypted.iv, encrypted.ciphertext, true)
      ).rejects.toThrow()
    })

    test('should throw error for invalid IV', async () => {
      const keys = await EcMakeCryptKeys(true)
      const data = arrayToBase64(new TextEncoder().encode('test data'))
      const encrypted = await HKDFEncrypt(keys.privateKey as string, keys.publicKey, data)

      await expect(
        HKDFDecrypt(keys.privateKey as string, keys.publicKey, encrypted.salt, 'invalid-iv', encrypted.ciphertext, true)
      ).rejects.toThrow()
    })

    test('should throw error for invalid ciphertext', async () => {
      const keys = await EcMakeCryptKeys(true)
      const data = arrayToBase64(new TextEncoder().encode('test data'))
      const encrypted = await HKDFEncrypt(keys.privateKey as string, keys.publicKey, data)

      await expect(
        HKDFDecrypt(keys.privateKey as string, keys.publicKey, encrypted.salt, encrypted.iv, 'invalid-ciphertext', true)
      ).rejects.toThrow()
    })
  })

  describe('Data Handling', () => {
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
        const encrypted = await HKDFEncrypt(keys.privateKey as string, keys.publicKey, data)
        const decrypted = await HKDFDecrypt(
          keys.privateKey as string,
          keys.publicKey,
          encrypted.salt,
          encrypted.iv,
          encrypted.ciphertext,
          true
        )
        expect(decrypted).toBe(testCase)
      }
    })

    test('should produce different ciphertexts for same data', async () => {
      const keys = await EcMakeCryptKeys(true)
      const data = arrayToBase64(new TextEncoder().encode('test data'))

      const encrypted1 = await HKDFEncrypt(keys.privateKey as string, keys.publicKey, data)
      const encrypted2 = await HKDFEncrypt(keys.privateKey as string, keys.publicKey, data)

      expect(encrypted1.ciphertext).not.toBe(encrypted2.ciphertext)
      expect(encrypted1.salt).not.toBe(encrypted2.salt)
      expect(encrypted1.iv).not.toBe(encrypted2.iv)
    })
  })

  describe('Salt and IV Properties', () => {
    test('should generate proper length salt', async () => {
      const keys = await EcMakeCryptKeys(true)
      const data = arrayToBase64(new TextEncoder().encode('test data'))

      const encrypted = await HKDFEncrypt(keys.privateKey as string, keys.publicKey, data)
      const saltBytes = Buffer.from(encrypted.salt, 'base64')

      expect(saltBytes.length).toBe(16) // HKDF salt should be 16 bytes
    })

    test('should generate proper length IV', async () => {
      const keys = await EcMakeCryptKeys(true)
      const data = arrayToBase64(new TextEncoder().encode('test data'))

      const encrypted = await HKDFEncrypt(keys.privateKey as string, keys.publicKey, data)
      const ivBytes = Buffer.from(encrypted.iv, 'base64')

      expect(ivBytes.length).toBe(16) // AES-GCM IV should be 16 bytes
    })
  })
})

describe('Error Logging', () => {
  test('should log error details before rethrowing', async () => {
    const keys = await EcMakeCryptKeys(true)
    const data = arrayToBase64(new TextEncoder().encode('test data'))

    // Mock console.log
    const consoleSpy = jest.spyOn(console, 'log')
    consoleSpy.mockImplementation(() => {}) // Suppress actual console output in tests

    // Trigger a crypto error by using invalid inputs that will definitely fail decryption
    await expect(async () => {
      await HKDFDecrypt(
        keys.privateKey as string,
        keys.publicKey,
        'AA==', // 1-byte invalid salt (should be 16 bytes)
        'AA==', // 1-byte invalid IV (should be 16 bytes)
        'AAAA', // Invalid ciphertext
        true
      )
    }).rejects.toThrow()

    // Verify console.log was called
    expect(consoleSpy).toHaveBeenCalled()

    // Verify the structure of the logged error
    const loggedError = consoleSpy.mock.calls[0][0]
    expect(loggedError).toEqual(
      expect.objectContaining({
        name: expect.any(String),
        message: expect.any(String),
        stack: expect.any(String),
      })
    )

    consoleSpy.mockRestore()
  })

  test('should preserve original error properties when logging and rethrowing', async () => {
    const keys = await EcMakeCryptKeys(true)
    const data = arrayToBase64(new TextEncoder().encode('test data'))

    const consoleSpy = jest.spyOn(console, 'log')
    consoleSpy.mockImplementation(() => {}) // Suppress actual console output in tests

    let thrownError: Error | undefined

    try {
      await HKDFDecrypt(
        keys.privateKey as string,
        keys.publicKey,
        'AA==', // 1-byte invalid salt
        'AA==', // 1-byte invalid IV
        'AAAA', // Invalid ciphertext
        true
      )
    } catch (error) {
      thrownError = error as Error
    }

    // Verify error was caught and logged
    expect(thrownError).toBeDefined()
    expect(consoleSpy).toHaveBeenCalled()

    // Get the logged error
    const loggedError = consoleSpy.mock.calls[0][0]

    // Verify error properties were preserved
    expect(loggedError).toEqual({
      name: thrownError?.name,
      message: thrownError?.message,
      stack: thrownError?.stack,
    })

    consoleSpy.mockRestore()
  })
})
