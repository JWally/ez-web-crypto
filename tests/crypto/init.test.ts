import { initializeCrypto } from '../../src/crypto/init'
import { describe, expect, test, beforeEach, jest } from '@jest/globals'

describe('Crypto Initialization', () => {
  let originalCrypto: Crypto | undefined
  let originalCryptoKey: typeof CryptoKey | undefined
  let originalRequire: NodeRequire | undefined

  beforeEach(() => {
    // Store original values
    originalCrypto = globalThis.crypto
    originalCryptoKey = globalThis.CryptoKey
    originalRequire = (globalThis as any).require

    // Clear the properties for each test
    delete (globalThis as any).crypto
    delete (globalThis as any).CryptoKey
    delete (globalThis as any).require

    // Clear Jest modules cache
    jest.resetModules()
  })

  afterEach(() => {
    // Restore original values
    if (originalCrypto) {
      globalThis.crypto = originalCrypto
    } else {
      delete (globalThis as any).crypto
    }

    if (originalCryptoKey) {
      globalThis.CryptoKey = originalCryptoKey
    } else {
      delete (globalThis as any).CryptoKey
    }

    if (originalRequire) {
      (globalThis as any).require = originalRequire
    } else {
      delete (globalThis as any).require
    }
  })

  describe('Browser Environment', () => {
    test('should initialize with browser crypto and CryptoKey', async () => {
      // Mock browser environment
      const mockCrypto = {
        subtle: {
          digest: jest.fn(),
          encrypt: jest.fn(),
          decrypt: jest.fn(),
        },
        getRandomValues: jest.fn(),
      }
      const mockCryptoKey = function() {} as any

      globalThis.crypto = mockCrypto as any
      globalThis.CryptoKey = mockCryptoKey

      const result = await initializeCrypto()

      expect(result.crypto).toBe(mockCrypto)
      expect(result.CryptoKey).toBe(mockCryptoKey)
    })

    test('should initialize with browser crypto but without CryptoKey', async () => {
      // Mock browser environment without CryptoKey
      const mockCrypto = {
        subtle: {
          digest: jest.fn(),
          encrypt: jest.fn(),
          decrypt: jest.fn(),
        },
        getRandomValues: jest.fn(),
      }

      globalThis.crypto = mockCrypto as any

      const result = await initializeCrypto()

      expect(result.crypto).toBe(mockCrypto)
      expect(result.CryptoKey).toBeNull()
    })
  })

  describe('Node.js Environment', () => {
    test('should initialize with Node.js webcrypto', async () => {
      // Mock Node.js environment
      const mockWebCrypto = {
        subtle: {
          digest: jest.fn(),
          encrypt: jest.fn(),
          decrypt: jest.fn(),
        },
        getRandomValues: jest.fn(),
      }

      // Mock require function and crypto module
      jest.mock('crypto', () => ({
        webcrypto: mockWebCrypto
      }), { virtual: true })

      ;(globalThis as any).require = () => {}

      const result = await initializeCrypto()

      expect(result.crypto).toHaveProperty('subtle')
      expect(result.crypto).toHaveProperty('getRandomValues')
      expect(result.CryptoKey).toBeNull()
    })
  })

  describe('Unsupported Environment', () => {
    test('should throw error when crypto is not available', async () => {
      await expect(initializeCrypto()).rejects.toThrow('Crypto API is not available in this environment')
    })
  })

  describe('Crypto API Functionality', () => {
    test('should provide working crypto.subtle', async () => {
      const context = await initializeCrypto()
      expect(context.crypto.subtle).toBeDefined()
      expect(typeof context.crypto.subtle.digest).toBe('function')
      expect(typeof context.crypto.subtle.encrypt).toBe('function')
      expect(typeof context.crypto.subtle.decrypt).toBe('function')
    })

    test('should provide working getRandomValues', async () => {
      const context = await initializeCrypto()
      const randomBuffer = new Uint8Array(16)
      context.crypto.getRandomValues(randomBuffer)
      
      // Check if values were actually randomized (not all zeros)
      const allZeros = randomBuffer.every(byte => byte === 0)
      expect(allZeros).toBe(false)
    })

    test('should generate unique random values', async () => {
      const context = await initializeCrypto()
      const buffer1 = new Uint8Array(16)
      const buffer2 = new Uint8Array(16)
      
      context.crypto.getRandomValues(buffer1)
      context.crypto.getRandomValues(buffer2)
      
      // Convert to strings for comparison
      const str1 = Array.from(buffer1).join(',')
      const str2 = Array.from(buffer2).join(',')
      
      expect(str1).not.toBe(str2)
    })
  })

  describe('Environment Detection', () => {
    test('should prefer browser crypto over Node.js crypto', async () => {
      // Mock both browser and Node.js environments
      const mockBrowserCrypto = {
        subtle: {
          digest: jest.fn(),
        },
        getRandomValues: jest.fn(),
      }

      const mockNodeCrypto = {
        subtle: {
          digest: jest.fn(),
        },
        getRandomValues: jest.fn(),
      }

      globalThis.crypto = mockBrowserCrypto as any
      ;(globalThis as any).require = () => ({
        webcrypto: mockNodeCrypto
      })

      const result = await initializeCrypto()
      expect(result.crypto).toBe(mockBrowserCrypto)
    })
  })

  describe('Error Handling', () => {
    test('should handle missing subtle crypto', async () => {
      globalThis.crypto = {} as any
      await expect(async () => {
        const context = await initializeCrypto()
        await context.crypto.subtle.digest('SHA-256', new Uint8Array([]))
      }).rejects.toThrow()
    })

    test('should handle invalid require', async () => {
      ;(globalThis as any).require = null
      await expect(initializeCrypto()).rejects.toThrow('Crypto API is not available in this environment')
    })

    test('should handle broken require function', async () => {
      ;(globalThis as any).require = () => {
        throw new Error('Require failed')
      }
      await expect(initializeCrypto()).rejects.toThrow()
    })
  })
})