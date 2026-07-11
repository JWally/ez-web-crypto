import type { Base64String } from './types'
import { AESMakeKey, AESDecrypt, AESEncrypt, AESImportKey } from './aes'
import { HASH } from './hash'
import { sleep, base64ToArray } from './utils'
import { encodeBase64, decodeBase64 } from './primitives/base64'
import { encodeUtf8, decodeUtf8 } from './primitives/utf8'
import { join, indexOf, slice } from './primitives/intrinsics'

const iterations = 5_000

/** btoa/atob over an already-ASCII string, without reaching for btoa/atob. */
const asciiToBase64 = (text: string): Base64String => encodeBase64(encodeUtf8(text))
const base64ToAscii = (text: Base64String): string => decodeUtf8(decodeBase64(text))

/**
 * The password payload is a fixed two-field record of base64 strings, `{ ciphertext, aes }`,
 * and `aes` is the AES key. We serialize and parse it by hand instead of through the global
 * `JSON`, so the key never transits a hookable builtin.
 *
 * The output is byte-identical to `JSON.stringify({ ciphertext, aes })`: base64's alphabet
 * contains no JSON metacharacters, so there is nothing to escape -- which keeps blobs written
 * by every earlier version decryptable. Parsing locates each field by its `"key":"` marker
 * and reads to the next quote (base64 can't contain one), so field order doesn't matter.
 */
const serializePayload = (ciphertext: Base64String, aes: Base64String): string =>
  join(['{"ciphertext":"', ciphertext, '","aes":"', aes, '"}'], '')

const readField = (text: string, key: string): Base64String => {
  const marker = join(['"', key, '":"'], '')
  const start = indexOf(text, marker, 0)
  if (start === -1) {
    throw new Error(`Malformed password payload: missing "${key}"`)
  }

  const from = start + marker.length
  const end = indexOf(text, '"', from)
  if (end === -1) {
    throw new Error(`Malformed password payload: unterminated "${key}"`)
  }

  return slice(text, from, end)
}

export const PASSWORD_ENCRYPT = async (password: string, base64data: Base64String): Promise<Base64String> => {
  await sleep(0)

  // Reject malformed input up front, as the old implementation's atob() did.
  base64ToArray(base64data)

  // 1. Strengthen the password through multiple rounds of hashing
  let strengthenedPassword = password
  for (let i = 0; i < iterations; i += 1) {
    strengthenedPassword = await HASH('SHA-512', strengthenedPassword)
  }

  // 2. Generate an AES key for the actual encryption
  const aes = (await AESMakeKey(true)) as Base64String

  // 3. Use the strengthened password as the IV for encryption
  const strengthenedPasswordHash = asciiToBase64(strengthenedPassword)

  // 4. Encrypt the data using the AES key and strengthened password as IV
  const output = await AESEncrypt(aes, base64data, strengthenedPasswordHash)

  // 5. Bundle everything needed for decryption
  return asciiToBase64(serializePayload(output.ciphertext, aes))
}

export const PASSWORD_DECRYPT = async (password: string, base64data: Base64String): Promise<string> => {
  await sleep(0)

  // 1. Strengthen the password the same way
  let strengthenedPassword = password
  for (let i = 0; i < iterations; i += 1) {
    strengthenedPassword = await HASH('SHA-512', strengthenedPassword)
  }

  // 2. Get the strengthened password hash
  const strengthenedPasswordHash = asciiToBase64(strengthenedPassword)

  // 3. Parse the encrypted data
  const payload = base64ToAscii(base64data)
  const ciphertext = readField(payload, 'ciphertext')

  // 4. Import the AES key
  const aes = await AESImportKey(readField(payload, 'aes'), false)

  // 5. Decrypt using the same strengthened password as IV
  return (await AESDecrypt(aes, strengthenedPasswordHash, ciphertext, true)) as string
}
