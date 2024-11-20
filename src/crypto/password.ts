import type { Base64String } from './types'
import { AESMakeKey, AESDecrypt, AESEncrypt, AESImportKey } from './aes'
import { HASH } from './hash'
import { sleep } from './utils'

const iterations = 5_000

export const PASSWORD_ENCRYPT = async (password: string, base64data: Base64String): Promise<Base64String> => {
  await sleep(0)

  // 1. Strengthen the password through multiple rounds of hashing
  let strengthenedPassword = password
  for (let i = 0; i < iterations; i++) {
    strengthenedPassword = await HASH('SHA-512', strengthenedPassword)
  }

  // 2. Generate an AES key for the actual encryption
  const aes = (await AESMakeKey(true)) as Base64String

  // 3. Use the strengthened password as the IV for encryption
  const strengthenedPasswordHash = btoa(strengthenedPassword)

  // 4. Encrypt the data using the AES key and strengthened password as IV
  const output = await AESEncrypt(aes, base64data, strengthenedPasswordHash)

  // 5. Bundle everything needed for decryption
  return btoa(
    JSON.stringify({
      ciphertext: output.ciphertext,
      aes,
    })
  )
}

export const PASSWORD_DECRYPT = async (password: string, base64data: Base64String): Promise<string> => {
  await sleep(0)

  // 1. Strengthen the password the same way
  let strengthenedPassword = password
  for (let i = 0; i < iterations; i++) {
    strengthenedPassword = await HASH('SHA-512', strengthenedPassword)
  }

  // 2. Get the strengthened password hash
  const strengthenedPasswordHash = btoa(strengthenedPassword)

  // 3. Parse the encrypted data
  const encryptedDataObject = JSON.parse(atob(base64data))

  // 4. Import the AES key
  const aes = await AESImportKey(encryptedDataObject.aes, false)

  // 5. Decrypt using the same strengthened password as IV
  const plaintext = (await AESDecrypt(aes, strengthenedPasswordHash, encryptedDataObject.ciphertext, true)) as string

  return plaintext
}
