// src/types/crypto/index.d.ts
declare module '@/types/crypto' {
    export type Base64String = string;
    export type HexString = string;
    
    export interface CryptoContext {
      crypto: Crypto;
      CryptoKey: typeof CryptoKey | null;
    }
  
    export interface AESEncryptResult {
      ciphertext: Base64String;
      iv: Base64String;
    }
  
    export interface PasswordEncryptResult {
      ciphertext: Base64String;
      aes: Base64String;
    }
  
    export interface ECKeyPairExportable {
      publicKey: Base64String;
      privateKey: Base64String;
      jwkPublicKey: JsonWebKey;
      jwkPrivateKey: JsonWebKey;
      rawPublicKey: Base64String;
      rawPublicKeyLite: Base64String;
    }
  
    export interface ECKeyPairNonExportable {
      publicKey: Base64String;
      privateKey: CryptoKey;
      rawPublicKey: Base64String;
      rawPublicKeyLite: Base64String;
    }
  
    export type ECKeyPair = ECKeyPairExportable | ECKeyPairNonExportable;
    
    export type HashAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512';
  }