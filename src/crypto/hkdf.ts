import { initializeCrypto } from "./init";
import { EcdhConvertKey } from "./key-conversion";
import { sleep } from "../utils";
import { base64ToArray, arrayToBase64 } from "../utils";

import type { Base64String, HKDFEncryptResult } from "./types";



export const HKDFEncrypt = async (
    b64Private: Base64String | CryptoKey,
    b64Public: Base64String | CryptoKey,
    b64data: Base64String
  ): Promise<HKDFEncryptResult> => {
    await sleep(0);
  
    const { crypto } = await initializeCrypto();
  
    // Convert keys
    const publicKey = await EcdhConvertKey(b64Public);
    const privateKey = await EcdhConvertKey(b64Private);
    
    // Generate shared secret for HKDF
    const sharedSecret = await crypto.subtle.deriveBits({ 
      name: "ECDH", 
      public: publicKey 
    }, privateKey, 256);
    
    // Convert shared-secret into a key
    const sharedSecretKey = await crypto.subtle.importKey(
      "raw", 
      sharedSecret, 
      { name: 'HKDF' }, 
      false, 
      ['deriveKey', 'deriveBits']
    );
    
    // Create SALT
    const salt = crypto.getRandomValues(new Uint8Array(16));
    
    // Convert the live-shared-secret-key into an aes key
    const derivedKey = await crypto.subtle.deriveBits({
      name: 'HKDF',
      hash: 'SHA-256',
      salt: salt,
      info: new Uint8Array([])
    }, sharedSecretKey, 256);
    
    // Convert the Key-Array to a live Key
    const aes_key = await crypto.subtle.importKey(
      "raw",
      derivedKey,
      "AES-GCM",
      false,
      ["encrypt", "decrypt"]
    );
    
    // Init Vector
    const iv = crypto.getRandomValues(new Uint8Array(16));
    
    // Encrypt
    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      aes_key,
      base64ToArray(b64data)
    );
    
    return {
      ciphertext: arrayToBase64(new Uint8Array(encrypted)),
      salt: arrayToBase64(salt),
      iv: arrayToBase64(iv)
    };
  };
  
  export const HKDFDecrypt = async (
    b64Private: Base64String | CryptoKey,
    b64Public: Base64String | CryptoKey,
    b64Salt: Base64String,
    b64iv: Base64String,
    b64data: Base64String,
    returnText: boolean = false
  ): Promise<string | ArrayBuffer> => {
    await sleep(0);
  
    const { crypto } = await initializeCrypto();
  
    const publicKey = await EcdhConvertKey(b64Public);
    const privateKey = await EcdhConvertKey(b64Private);
    const salt = base64ToArray(b64Salt);
    const iv = base64ToArray(b64iv);
    const data = base64ToArray(b64data);
    
    // Generate shared secret for HKDF
    const sharedSecret = await crypto.subtle.deriveBits({ 
      name: "ECDH", 
      public: publicKey 
    }, privateKey, 256);
    
    // Convert shared-secret into a key
    const sharedSecretKey = await crypto.subtle.importKey(
      "raw",
      sharedSecret, 
      { name: 'HKDF' }, 
      false, 
      ['deriveKey', 'deriveBits']
    );
    
    // Convert the live-shared-secret-key into an aes key
    const derivedKey = await crypto.subtle.deriveBits({
      name: 'HKDF',
      hash: 'SHA-256',
      salt: salt,
      info: new Uint8Array([])
    }, sharedSecretKey, 256);
  
    // Convert the Key-Array to a live Key
    const aes_key = await crypto.subtle.importKey(
      "raw",
      derivedKey,
      "AES-GCM",
      false,
      ["encrypt", "decrypt"]
    );
  
    try {
      const aes_data = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        aes_key,
        data
      );
  
      if (!returnText) {
        return aes_data;
      }
  
      const decrypted = new Uint8Array(aes_data);
      return new TextDecoder().decode(decrypted);
    } catch (e:any) {
      console.log({name: e.name, stack: e.stack, message: e.message});
      throw e;
    }
  };