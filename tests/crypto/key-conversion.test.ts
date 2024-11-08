import { EcdhConvertKey, EcdsaConvertKey } from '../../src/crypto/key-conversion'
import { EcMakeCryptKeys, EcMakeSigKeys } from '../../src'
import { initializeCrypto } from '../../src/crypto/init'
import { describe, expect, test } from '@jest/globals'

describe('Key Conversion Operations', () => {
  describe('EcdhConvertKey', () => {
    test('should handle existing CryptoKey instances', async () => {
      const keys = await EcMakeCryptKeys(true)
      // First conversion creates a CryptoKey
      const cryptoKey = await EcdhConvertKey(keys.publicKey)
      // Second conversion should return the same CryptoKey
      const result = await EcdhConvertKey(cryptoKey)
      expect(result).toBe(cryptoKey)
    })

    test('should handle SPKI format public keys', async () => {
      const keys = await EcMakeCryptKeys(true)
      const converted = await EcdhConvertKey(keys.publicKey)
      expect(converted).toBeTruthy()
      // Verify it's a CryptoKey by checking for key-specific properties
      expect('algorithm' in converted).toBe(true)
      expect('type' in converted).toBe(true)
      expect('extractable' in converted).toBe(true)
    })

    test('should handle PKCS8 format private keys', async () => {
      const keys = await EcMakeCryptKeys(true)
      const converted = await EcdhConvertKey(keys.privateKey)
      expect(converted).toBeTruthy()
      expect('algorithm' in converted).toBe(true)
      expect('type' in converted).toBe(true)
      expect('extractable' in converted).toBe(true)
    })

    test('should handle RAW format public keys', async () => {
      // Create a raw public key by stripping the first byte
      const keys = await EcMakeCryptKeys(true)
      const rawKey = Buffer.from(keys.publicKey, 'base64').slice(0).toString('base64')
      const converted = await EcdhConvertKey(rawKey)
      expect(converted).toBeTruthy()
      expect('algorithm' in converted).toBe(true)
      expect('type' in converted).toBe(true)
    })

    test('should throw error for non-string non-CryptoKey input', async () => {
      // @ts-ignore - Testing invalid input
      await expect(EcdhConvertKey(123)).rejects.toThrow('Invalid key format')
    })

    test('should throw error for unrecognized key format', async () => {
      const invalidKey = 'InvalidBase64Key=='
      await expect(EcdhConvertKey(invalidKey)).rejects.toThrow('UNRECOGNIZED KEY FORMAT')
    })
  })

  describe('EcdsaConvertKey', () => {
    test('should handle existing CryptoKey instances', async () => {
      const keys = await EcMakeSigKeys(true)
      // First conversion creates a CryptoKey
      const cryptoKey = await EcdsaConvertKey(keys.publicKey)
      // Second conversion should return the same CryptoKey
      const result = await EcdsaConvertKey(cryptoKey)
      expect(result).toBe(cryptoKey)
    })

    test('should handle SPKI format public keys', async () => {
      const keys = await EcMakeSigKeys(true)
      const converted = await EcdsaConvertKey(keys.publicKey)
      expect(converted).toBeTruthy()
      expect('algorithm' in converted).toBe(true)
      expect('type' in converted).toBe(true)
    })

    test('should handle PKCS8 format private keys', async () => {
      const keys = await EcMakeSigKeys(true)
      const converted = await EcdsaConvertKey(keys.privateKey)
      expect(converted).toBeTruthy()
      expect('algorithm' in converted).toBe(true)
      expect('type' in converted).toBe(true)
    })

    test('should handle RAW format public keys', async () => {
      // Create a raw public key by stripping the first byte
      const keys = await EcMakeSigKeys(true)
      const rawKey = Buffer.from(keys.publicKey, 'base64').slice(0).toString('base64')
      const converted = await EcdsaConvertKey(rawKey)
      expect(converted).toBeTruthy()
      expect('algorithm' in converted).toBe(true)
      expect('type' in converted).toBe(true)
    })

    test('should throw error for non-string non-CryptoKey input', async () => {
      // @ts-ignore - Testing invalid input
      await expect(EcdsaConvertKey(123)).rejects.toThrow('Invalid key format')
    })

    test('should throw error for unrecognized key format', async () => {
      const invalidKey = 'InvalidBase64Key=='
      await expect(EcdsaConvertKey(invalidKey)).rejects.toThrow('UNRECOGNIZED KEY FORMAT')
    })
  })

  describe('Key Usage Rights', () => {
    test('ECDH public key should have no usage rights', async () => {
      const keys = await EcMakeCryptKeys(true)
      const converted = await EcdhConvertKey(keys.publicKey)
      expect(converted.usages).toHaveLength(0)
    })

    test('ECDH private key should have derive rights', async () => {
      const keys = await EcMakeCryptKeys(true)
      const converted = await EcdhConvertKey(keys.privateKey)
      expect(converted.usages).toContain('deriveKey')
      expect(converted.usages).toContain('deriveBits')
    })

    test('ECDSA public key should have verify rights', async () => {
      const keys = await EcMakeSigKeys(true)
      const converted = await EcdsaConvertKey(keys.publicKey)
      expect(converted.usages).toContain('verify')
    })

    test('ECDSA private key should have sign rights', async () => {
      const keys = await EcMakeSigKeys(true)
      const converted = await EcdsaConvertKey(keys.privateKey)
      expect(converted.usages).toContain('sign')
    })
  })
})
