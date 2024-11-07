import type { Base64String } from "./types";
import { AESMakeKey, AESDecrypt, AESEncrypt, AESImportKey } from "./aes";
import { HASH } from "./hash";
import { sleep } from "../utils";

// password.ts
export const PASSWORD_ENCRYPT = async (
    password: string,
    base64data: Base64String
  ): Promise<Base64String> => {
    await sleep(0);
  
    let hashedPassword = password;
    
    for (let i = 0; i < 10; i++) {
      hashedPassword = await HASH("SHA-512", hashedPassword);
    }
    
    const passwordHash = btoa(hashedPassword);
    const aes = await AESMakeKey(true) as Base64String;
    const output = await AESEncrypt(aes, base64data, passwordHash);
  
    return btoa(JSON.stringify({
      ciphertext: output.ciphertext,
      aes
    }));
  };
  
  export const PASSWORD_DECRYPT = async (
    password: string,
    base64data: Base64String
  ): Promise<string> => {
    await sleep(0);
  
    let hashedPassword = password;
    
    for (let i = 0; i < 10; i++) {
      hashedPassword = await HASH("SHA-512", hashedPassword);
    }
    
    const passwordHash = btoa(hashedPassword);
    const encryptedDataObject = JSON.parse(atob(base64data));
    const aes = await AESImportKey(encryptedDataObject.aes, false);
    const plaintext = await AESDecrypt(
      aes,
      passwordHash,
      encryptedDataObject.ciphertext,
      true
    ) as string;
  
    return plaintext;
  };