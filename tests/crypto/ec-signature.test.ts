import { EcMakeSigKeys, EcSignData, EcVerifySig } from '../../src/crypto/ec-signature'
import { arrayToBase64 } from '../../src/utils'
import { describe, expect, test } from '@jest/globals'
import type { ECSignatureKeyPair } from '../../src/crypto/types'

describe('EC Signature Operations', () => {
  describe('EcMakeSigKeys', () => {
    test('should generate exportable key pair', async () => {
      const keys = await EcMakeSigKeys(true)
      expect(keys).toHaveProperty('publicKey')
      expect(keys).toHaveProperty('privateKey')
      expect(typeof keys.publicKey).toBe('string')
      expect(typeof keys.privateKey).toBe('string')
    })

    test('should generate partially exportable key pair when exportable is false', async () => {
      const keys = await EcMakeSigKeys(false)
      expect(typeof keys.publicKey).toBe('string')
      expect(keys.privateKey).toHaveProperty('type')
      expect(keys.privateKey).toHaveProperty('algorithm')
      const privateKey = keys.privateKey as CryptoKey
      expect(privateKey.type).toBe('private')
      expect((privateKey.algorithm as EcKeyAlgorithm).name).toBe('ECDSA')
      expect((privateKey.algorithm as EcKeyAlgorithm).namedCurve).toBe('P-256')
    })

    test('should generate keys with correct usage rights', async () => {
      // Test exportable keys
      const exportableKeys = await EcMakeSigKeys(true)
      const publicKey = await crypto.subtle.importKey(
        'spki',
        new Uint8Array(Buffer.from(exportableKeys.publicKey, 'base64')).buffer,
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['verify']
      )
      const privateKey = await crypto.subtle.importKey(
        'pkcs8',
        new Uint8Array(Buffer.from(exportableKeys.privateKey as string, 'base64')).buffer,
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign']
      )

      expect(publicKey.usages).toContain('verify')
      expect(privateKey.usages).toContain('sign')
    })

    test('should generate unique key pairs', async () => {
      const keys1 = await EcMakeSigKeys(true)
      const keys2 = await EcMakeSigKeys(true)
      expect(keys1.publicKey).not.toBe(keys2.publicKey)
      expect(keys1.privateKey).not.toBe(keys2.privateKey)
    })
  })

  describe('EcSignData', () => {
    test('should sign data with base64 private key', async () => {
      const keys = await EcMakeSigKeys(true)
      const data = arrayToBase64(new TextEncoder().encode('test data'))
      const signature = await EcSignData(keys.privateKey as string, data)
      expect(typeof signature).toBe('string')
      // ECDSA P-256 signatures are 64 bytes (512 bits)
      expect(Buffer.from(signature, 'base64').length).toBe(64)
    })

    test('should sign data with CryptoKey private key', async () => {
      const keys = await EcMakeSigKeys(false)
      const data = arrayToBase64(new TextEncoder().encode('test data'))
      const signature = await EcSignData(keys.privateKey, data)
      expect(typeof signature).toBe('string')
      expect(Buffer.from(signature, 'base64').length).toBe(64)
    })

    test('should generate different signatures for same data', async () => {
      const keys = await EcMakeSigKeys(true)
      const data = arrayToBase64(new TextEncoder().encode('test data'))
      const sig1 = await EcSignData(keys.privateKey as string, data)
      const sig2 = await EcSignData(keys.privateKey as string, data)
      // ECDSA signatures should be different even for the same data
      expect(sig1).not.toBe(sig2)
    })

    test('should throw error for invalid private key', async () => {
      const invalidKey = 'invalid-key'
      const data = arrayToBase64(new TextEncoder().encode('test data'))
      await expect(EcSignData(invalidKey, data)).rejects.toThrow()
    })
  })

  describe('EcVerifySig', () => {
    test('should verify valid signature with base64 public key', async () => {
      const keys = await EcMakeSigKeys(true)
      const data = arrayToBase64(new TextEncoder().encode('test data'))
      const signature = await EcSignData(keys.privateKey as string, data)
      const isValid = await EcVerifySig(keys.publicKey, signature, data)
      expect(isValid).toBe(true)
    })

    test('should verify valid signature with CryptoKey public key', async () => {
      const keys = await EcMakeSigKeys(false)
      const data = arrayToBase64(new TextEncoder().encode('test data'))
      const signature = await EcSignData(keys.privateKey, data)
      const importedPublicKey = await crypto.subtle.importKey(
        'spki',
        new Uint8Array(Buffer.from(keys.publicKey, 'base64')).buffer,
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['verify']
      )
      const isValid = await EcVerifySig(importedPublicKey, signature, data)
      expect(isValid).toBe(true)
    })

    test('should reject invalid signature', async () => {
      const keys = await EcMakeSigKeys(true)
      const data = arrayToBase64(new TextEncoder().encode('test data'))
      const invalidSignature = arrayToBase64(new Uint8Array(64)) // Zero signature
      const isValid = await EcVerifySig(keys.publicKey, invalidSignature, data)
      expect(isValid).toBe(false)
    })

    test('should reject modified data', async () => {
      const keys = await EcMakeSigKeys(true)
      const data = arrayToBase64(new TextEncoder().encode('test data'))
      const signature = await EcSignData(keys.privateKey as string, data)
      const modifiedData = arrayToBase64(new TextEncoder().encode('modified data'))
      const isValid = await EcVerifySig(keys.publicKey, signature, modifiedData)
      expect(isValid).toBe(false)
    })

    test('should reject signature from different key pair', async () => {
      const keys1 = await EcMakeSigKeys(true)
      const keys2 = await EcMakeSigKeys(true)
      const data = arrayToBase64(new TextEncoder().encode('test data'))
      const signature = await EcSignData(keys1.privateKey as string, data)
      const isValid = await EcVerifySig(keys2.publicKey, signature, data)
      expect(isValid).toBe(false)
    })
  })

  describe('End-to-end signing cycle', () => {
    test('should handle various data types and sizes', async () => {
      const testCases = [
        'Simple text',
        'Unicode text 🔑',
        'A'.repeat(1000), // Large text
        JSON.stringify({ key: 'value', nested: { array: [1, 2, 3] } }), // JSON data
        Buffer.from([1, 2, 3, 4, 5]).toString('base64'), // Binary data
      ]

      const keys = await EcMakeSigKeys(true)

      for (const testCase of testCases) {
        const data = arrayToBase64(new TextEncoder().encode(testCase))
        const signature = await EcSignData(keys.privateKey as string, data)
        const isValid = await EcVerifySig(keys.publicKey, signature, data)
        expect(isValid).toBe(true)
      }
    })

    test('should work with mixed key formats', async () => {
      // Generate exportable keys and convert to different formats
      const keys = await EcMakeSigKeys(true)
      const importedPrivateKey = await crypto.subtle.importKey(
        'pkcs8',
        new Uint8Array(Buffer.from(keys.privateKey as string, 'base64')).buffer,
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign']
      )
      const importedPublicKey = await crypto.subtle.importKey(
        'spki',
        new Uint8Array(Buffer.from(keys.publicKey, 'base64')).buffer,
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['verify']
      )

      const data = arrayToBase64(new TextEncoder().encode('test data'))

      // Test all combinations of key formats
      const testCases = [
        { privKey: keys.privateKey, pubKey: keys.publicKey },
        { privKey: importedPrivateKey, pubKey: keys.publicKey },
        { privKey: keys.privateKey, pubKey: importedPublicKey },
        { privKey: importedPrivateKey, pubKey: importedPublicKey },
      ]

      for (const { privKey, pubKey } of testCases) {
        const signature = await EcSignData(privKey, data)
        const isValid = await EcVerifySig(pubKey, signature, data)
        expect(isValid).toBe(true)
      }
    })
  })
})
