import { 
    HASH,
    HMAC,
    AESMakeKey,
    AESEncrypt,
    AESDecrypt,
    PASSWORD_ENCRYPT,
    PASSWORD_DECRYPT,
    EcMakeCryptKeys,
    EcEncrypt,
    EcDecrypt,
    HKDFEncrypt,
    HKDFDecrypt,
    EcMakeSigKeys,
    EcSignData,
    EcVerifySig
  } from '../src';

  import { describe, expect, test } from '@jest/globals';
  
  describe('Cryptographic Operations', () => {
    describe('Basic Operations', () => {
      test('HASH should generate consistent SHA-256 hashes', async () => {
        const testData = 'test data';
        const actual = 'kW8AJ6V1B0znKjMXd8NHjWUT94alkb2JLaGld78jNfk='
        const hash1 = await HASH('SHA-256', testData);
        const hash2 = await HASH('SHA-256', testData);
        expect(hash1).toBe(hash2);
        expect(hash1).toBe(actual)
      });
  
      test('HMAC should generate valid signatures', async () => {
        const secret = 'secret key';
        const data = 'test data';
        const signature = await HMAC(secret, data);
        expect(signature).toBeTruthy();
        expect(typeof signature).toBe('string');
      });

      test('HMAC should align with the real world', async () => {

        const secret = 'secret key';
        const data = 'test data';
        const signature = 'd51c4289e6eea49db00925bb7a948d31309550040f88bc4aba39bb3107c071be'
        const results = await HMAC(secret,data);
        expect(signature).toEqual(results)

      })
    });
  
    describe('AES Operations', () => {
      test('AES encryption/decryption cycle should work', async () => {
        const testData = btoa('test data');
        const key = await AESMakeKey(true);
        const encrypted = await AESEncrypt(key, testData);
        
        expect(encrypted.ciphertext).toBeTruthy();
        expect(encrypted.iv).toBeTruthy();
        
        const decrypted = await AESDecrypt(key, encrypted.iv, encrypted.ciphertext, true);
        expect(decrypted).toBe('test data');
      });
    });
  
    describe('Password Operations', () => {
      test('Password encryption/decryption cycle should work', async () => {
        const password = 'testPassword123';
        const testData = btoa('sensitive data');
        
        const encrypted = await PASSWORD_ENCRYPT(password, testData);
        const decrypted = await PASSWORD_DECRYPT(password, encrypted);
        
        expect(decrypted).toBe('sensitive data');
      });
    });
  
    describe('Elliptic Curve Operations', () => {
      test('EC key generation and encryption cycle should work', async () => {
        const keys = await EcMakeCryptKeys(true);
        expect(keys.publicKey).toBeTruthy();
        expect(keys.privateKey).toBeTruthy();
  
        const testData = btoa('test data');
        const encrypted = await EcEncrypt(keys.privateKey, keys.publicKey, testData);
        
        expect(encrypted.ciphertext).toBeTruthy();
        expect(encrypted.iv).toBeTruthy();
        
        const decrypted = await EcDecrypt(
          keys.privateKey,
          keys.publicKey,
          encrypted.iv,
          encrypted.ciphertext,
          true
        );
        expect(decrypted).toBe('test data');
      });
  
      test('HKDF encryption/decryption cycle should work', async () => {
        const keys = await EcMakeCryptKeys(true);
        const testData = btoa('test data');
        
        const encrypted = await HKDFEncrypt(keys.privateKey, keys.publicKey, testData);
        expect(encrypted.ciphertext).toBeTruthy();
        expect(encrypted.salt).toBeTruthy();
        expect(encrypted.iv).toBeTruthy();
        
        const decrypted = await HKDFDecrypt(
          keys.privateKey,
          keys.publicKey,
          encrypted.salt,
          encrypted.iv,
          encrypted.ciphertext,
          true
        );
        expect(decrypted).toBe('test data');
      });
    });
  
    describe('Digital Signatures', () => {
      test('EC signature operations should work', async () => {
        const keys = await EcMakeSigKeys(true);
        const testData = btoa('test data');
        
        const signature = await EcSignData(keys.privateKey, testData);
        expect(signature).toBeTruthy();
        
        const isValid = await EcVerifySig(keys.publicKey, signature, testData);
        expect(isValid).toBe(true);
      });
    });
  
    describe('Error Cases', () => {
      test('Should handle invalid keys appropriately', async () => {
        const invalidKey = 'invalid-key';
        const testData = btoa('test data');
        
        await expect(AESEncrypt(invalidKey, testData))
          .rejects
          .toThrow();
      });
  
      test('Should handle invalid data in password operations', async () => {
        const password = 'testPassword123';
        const invalidData = 'not-base64-encoded';
        
        await expect(PASSWORD_ENCRYPT(password, invalidData))
          .rejects
          .toThrow();
      });
    });
  });