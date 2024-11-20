import { describe, expect, test } from '@jest/globals'
import { HASH } from '../../src/crypto/hash'
import { base64ToArray } from '../../src/crypto/utils'
import type { HashAlgorithm } from '../../src/crypto/types'

describe('Hash Functions', () => {
  describe('HASH', () => {
    test('should generate consistent SHA-256 hashes', async () => {
      const data = 'test data'
      const hash1 = await HASH('SHA-256', data)
      const hash2 = await HASH('SHA-256', data)
      expect(hash1).toBe(hash2)
      // Known SHA-256 hash for 'test data'
      expect(hash1).toBe('kW8AJ6V1B0znKjMXd8NHjWUT94alkb2JLaGld78jNfk=')
    })

    test('should generate consistent SHA-512 hashes', async () => {
      const data = 'test data'
      const hash1 = await HASH('SHA-512', data)
      const hash2 = await HASH('SHA-512', data)
      expect(hash1).toBe(hash2)
    })

    test('should generate consistent SHA-1 hashes', async () => {
      const data = 'test data'
      const hash1 = await HASH('SHA-1', data)
      const hash2 = await HASH('SHA-1', data)
      expect(hash1).toBe(hash2)
    })

    test('should handle empty strings', async () => {
      const data = ''
      const hash = await HASH('SHA-256', data)
      // Known SHA-256 hash for empty string
      expect(hash).toBe('47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=')
    })

    test('should handle unicode strings', async () => {
      const data = 'Hello 🌍'
      const hash1 = await HASH('SHA-256', data)
      const hash2 = await HASH('SHA-256', data)
      expect(hash1).toBe(hash2)
    })

    test('should handle long strings', async () => {
      const data = 'A'.repeat(10000)
      const hash1 = await HASH('SHA-256', data)
      const hash2 = await HASH('SHA-256', data)
      expect(hash1).toBe(hash2)
    })

    describe('Length-specified hashes', () => {
      test('should generate hash of specified length', async () => {
        const data = 'test data'
        const len = 16
        const hash = await HASH('SHA-256', data, len)
        const hashBytes = base64ToArray(hash)
        expect(hashBytes.length).toBe(len)
      })

      test('should be consistent for same input and length', async () => {
        const data = 'test data'
        const len = 16
        const hash1 = await HASH('SHA-256', data, len)
        const hash2 = await HASH('SHA-256', data, len)
        expect(hash1).toBe(hash2)
      })

      test('should handle length longer than hash', async () => {
        const data = 'test data'
        const len = 64 // Longer than SHA-256 output
        const hash = await HASH('SHA-256', data, len)
        const hashBytes = base64ToArray(hash)
        expect(hashBytes.length).toBe(len)
      })

      test('should handle length shorter than hash', async () => {
        const data = 'test data'
        const len = 16 // Shorter than SHA-256 output
        const hash = await HASH('SHA-256', data, len)
        const hashBytes = base64ToArray(hash)
        expect(hashBytes.length).toBe(len)
      })

      test('should produce different outputs for different lengths', async () => {
        const data = 'test data'
        const hash1 = await HASH('SHA-256', data, 16)
        const hash2 = await HASH('SHA-256', data, 32)
        expect(hash1).not.toBe(hash2)
      })
    })

    describe('Different algorithms comparison', () => {
      const algorithms: HashAlgorithm[] = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']

      test('should produce different hashes for different algorithms', async () => {
        const data = 'test data'
        const hashes = await Promise.all(algorithms.map((algo) => HASH(algo, data)))

        // Compare each hash with every other hash
        for (let i = 0; i < hashes.length; i++) {
          for (let j = i + 1; j < hashes.length; j++) {
            expect(hashes[i]).not.toBe(hashes[j])
          }
        }
      })

      test('should handle length specification for all algorithms', async () => {
        const data = 'test data'
        const len = 16
        const hashes = await Promise.all(algorithms.map((algo) => HASH(algo, data, len)))

        // All hashes should be the specified length
        hashes.forEach((hash) => {
          expect(base64ToArray(hash).length).toBe(len)
        })
      })
    })

    describe('Edge cases', () => {
      test('should handle very short lengths', async () => {
        const data = 'test data'
        const len = 1
        const hash = await HASH('SHA-256', data, len)
        const hashBytes = base64ToArray(hash)
        expect(hashBytes.length).toBe(len)
      })

      test('should handle negative length', async () => {
        const data = 'test data'
        await expect(HASH('SHA-256', data, -1)).rejects.toThrow()
      })

      test('should handle special characters', async () => {
        const specialChars = '!@#$%^&*()_+-=[]{}|;:,.<>?`~'
        const hash1 = await HASH('SHA-256', specialChars)
        const hash2 = await HASH('SHA-256', specialChars)
        expect(hash1).toBe(hash2)
      })
    })
  })
})
