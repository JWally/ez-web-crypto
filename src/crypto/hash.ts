// hash.ts
import { arrayToBase64 } from './utils'
import { digest } from './primitives/sha'
import { encodeUtf8 } from './primitives/utf8'
import { alloc } from './primitives/intrinsics'
import { HashAlgorithm, Base64String } from './types'

export const HASH = async (algo: HashAlgorithm, data: string, len?: number): Promise<Base64String> => {
  const ary = digest(algo, encodeUtf8(data))

  if (!len) {
    return arrayToBase64(ary)
  }

  // Folds the digest down to `len` bytes (or repeats it out to `len`) with XOR.
  // A negative `len` still has to throw, which alloc() does.
  const outAry = alloc(len)
  const max = len > ary.length ? len : ary.length

  for (let i = 0; i < max; i += 1) {
    /* eslint-disable no-bitwise */
    outAry[i % len] = outAry[i % len] ^ ary[i % ary.length]
  }

  return arrayToBase64(outAry)
}
