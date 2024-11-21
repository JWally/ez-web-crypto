// hash.ts
import { initializeCrypto } from './init'
import { arrayToBase64 } from './utils'
import { HashAlgorithm, Base64String } from './types'

export const HASH = async (algo: HashAlgorithm, data: string, len?: number): Promise<Base64String> => {
  const { crypto } = await initializeCrypto()
  const hash = await crypto.subtle.digest(algo, new TextEncoder().encode(data))
  const ary = new Uint8Array(hash)

  if (!len) {
    return arrayToBase64(ary)
  }

  const outAry = new Uint8Array(len)
  const max = Math.max(len, ary.length)

  for (let i = 0; i < max; i += 1) {
    /* eslint-disable no-bitwise, no-empty */
    outAry[i % len] = outAry[i % len] ^ ary[i % ary.length]
  }

  return arrayToBase64(outAry)
}
