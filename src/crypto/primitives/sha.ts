/**
 * SHA-1 / SHA-256 / SHA-384 / SHA-512. Replaces `crypto.subtle.digest`.
 *
 * 64-bit words in the SHA-512 family are carried as hi/lo 32-bit halves rather than
 * BigInt: PASSWORD_ENCRYPT chains 5,000 SHA-512 rounds, and BigInt is an order of
 * magnitude too slow for that. Sums accumulate as doubles (each term < 2^32, at most
 * six terms, so well inside the 53-bit mantissa) and are folded back with `>>> 0`.
 */

import { U32, alloc } from './intrinsics'
import type { HashAlgorithm } from '../types'

/* eslint-disable no-bitwise */

const K256 = new U32([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
  0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
  0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
  0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
  0xc67178f2,
])

const K512_HI = new U32([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
  0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
  0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
  0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
  0xc67178f2, 0xca273ece, 0xd186b8c7, 0xeada7dd6, 0xf57d4f7f, 0x06f067aa, 0x0a637dc5, 0x113f9804, 0x1b710b35,
  0x28db77f5, 0x32caab7b, 0x3c9ebe0a, 0x431d67c4, 0x4cc5d4be, 0x597f299c, 0x5fcb6fab, 0x6c44198c,
])

const K512_LO = new U32([
  0xd728ae22, 0x23ef65cd, 0xec4d3b2f, 0x8189dbbc, 0xf348b538, 0xb605d019, 0xaf194f9b, 0xda6d8118, 0xa3030242,
  0x45706fbe, 0x4ee4b28c, 0xd5ffb4e2, 0xf27b896f, 0x3b1696b1, 0x25c71235, 0xcf692694, 0x9ef14ad2, 0x384f25e3,
  0x8b8cd5b5, 0x77ac9c65, 0x592b0275, 0x6ea6e483, 0xbd41fbd4, 0x831153b5, 0xee66dfab, 0x2db43210, 0x98fb213f,
  0xbeef0ee4, 0x3da88fc2, 0x930aa725, 0xe003826f, 0x0a0e6e70, 0x46d22ffc, 0x5c26c926, 0x5ac42aed, 0x9d95b3df,
  0x8baf63de, 0x3c77b2a8, 0x47edaee6, 0x1482353b, 0x4cf10364, 0xbc423001, 0xd0f89791, 0x0654be30, 0xd6ef5218,
  0x5565a910, 0x5771202a, 0x32bbd1b8, 0xb8d2d0c8, 0x5141ab53, 0xdf8eeb99, 0xe19b48a8, 0xc5c95a63, 0xe3418acb,
  0x7763e373, 0xd6b2b8a3, 0x5defb2fc, 0x43172f60, 0xa1f0ab72, 0x1a6439ec, 0x23631e28, 0xde82bde9, 0xb2c67915,
  0xe372532b, 0xea26619c, 0x21c0c207, 0xcde0eb1e, 0xee6ed178, 0x72176fba, 0xa2c898a6, 0xbef90dae, 0x131c471b,
  0x23047d84, 0x40c72493, 0x15c9bebc, 0x9c100d4c, 0xcb3e42b6, 0xfc657e2a, 0x3ad6faec, 0x4a475817,
])

const H1 = new U32([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0])

const H256 = new U32([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19])

const H512_HI = new U32([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
])
const H512_LO = new U32([
  0xf3bcc908, 0x84caa73b, 0xfe94f82b, 0x5f1d36f1, 0xade682d1, 0x2b3e6c1f, 0xfb41bd6b, 0x137e2179,
])

const H384_HI = new U32([
  0xcbbb9d5d, 0x629a292a, 0x9159015a, 0x152fecd8, 0x67332667, 0x8eb44a87, 0xdb0c2e0d, 0x47b5481d,
])
const H384_LO = new U32([
  0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
])

/** message || 0x80 || 0x00* || bigEndian(bitLength), padded out to a whole number of blocks. */
const padMessage = (message: Uint8Array, blockSize: number, lengthFieldSize: number): Uint8Array => {
  const { length } = message
  const totalLength = (((length + lengthFieldSize + 1 + blockSize - 1) / blockSize) | 0) * blockSize

  const padded = alloc(totalLength)
  padded.set(message)
  padded[length] = 0x80

  // Bit lengths beyond 2^53 are unreachable from a Uint8Array, so only the low 64 bits
  // of the (64- or 128-bit) length field are ever non-zero.
  const bitLength = length * 8
  const hi = (bitLength / 0x100000000) | 0
  const lo = bitLength >>> 0

  padded[totalLength - 8] = (hi >>> 24) & 0xff
  padded[totalLength - 7] = (hi >>> 16) & 0xff
  padded[totalLength - 6] = (hi >>> 8) & 0xff
  padded[totalLength - 5] = hi & 0xff
  padded[totalLength - 4] = (lo >>> 24) & 0xff
  padded[totalLength - 3] = (lo >>> 16) & 0xff
  padded[totalLength - 2] = (lo >>> 8) & 0xff
  padded[totalLength - 1] = lo & 0xff

  return padded
}

const rotr32 = (x: number, n: number): number => (x >>> n) | (x << (32 - n))

const sha1 = (message: Uint8Array): Uint8Array => {
  const padded = padMessage(message, 64, 8)
  const w = new U32(80)

  let h0 = H1[0]
  let h1 = H1[1]
  let h2 = H1[2]
  let h3 = H1[3]
  let h4 = H1[4]

  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let t = 0; t < 16; t += 1) {
      const i = offset + t * 4
      w[t] = ((padded[i] << 24) | (padded[i + 1] << 16) | (padded[i + 2] << 8) | padded[i + 3]) >>> 0
    }
    for (let t = 16; t < 80; t += 1) {
      const x = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]
      w[t] = ((x << 1) | (x >>> 31)) >>> 0
    }

    let a = h0
    let b = h1
    let c = h2
    let d = h3
    let e = h4

    for (let t = 0; t < 80; t += 1) {
      let f: number
      let k: number

      if (t < 20) {
        f = (b & c) | (~b & d)
        k = 0x5a827999
      } else if (t < 40) {
        f = b ^ c ^ d
        k = 0x6ed9eba1
      } else if (t < 60) {
        f = (b & c) | (b & d) | (c & d)
        k = 0x8f1bbcdc
      } else {
        f = b ^ c ^ d
        k = 0xca62c1d6
      }

      const temp = (rotr32(a, 27) + (f >>> 0) + e + k + w[t]) >>> 0
      e = d
      d = c
      c = rotr32(b, 2)
      b = a
      a = temp
    }

    h0 = (h0 + a) >>> 0
    h1 = (h1 + b) >>> 0
    h2 = (h2 + c) >>> 0
    h3 = (h3 + d) >>> 0
    h4 = (h4 + e) >>> 0
  }

  const digest = alloc(20)
  const words = new U32([h0, h1, h2, h3, h4])
  for (let i = 0; i < 5; i += 1) {
    digest[i * 4] = (words[i] >>> 24) & 0xff
    digest[i * 4 + 1] = (words[i] >>> 16) & 0xff
    digest[i * 4 + 2] = (words[i] >>> 8) & 0xff
    digest[i * 4 + 3] = words[i] & 0xff
  }
  return digest
}

const sha256 = (message: Uint8Array): Uint8Array => {
  const padded = padMessage(message, 64, 8)
  const w = new U32(64)
  const h = new U32(H256)

  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let t = 0; t < 16; t += 1) {
      const i = offset + t * 4
      w[t] = ((padded[i] << 24) | (padded[i + 1] << 16) | (padded[i + 2] << 8) | padded[i + 3]) >>> 0
    }
    for (let t = 16; t < 64; t += 1) {
      const x = w[t - 15]
      const y = w[t - 2]
      const s0 = (rotr32(x, 7) ^ rotr32(x, 18) ^ (x >>> 3)) >>> 0
      const s1 = (rotr32(y, 17) ^ rotr32(y, 19) ^ (y >>> 10)) >>> 0
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0
    }

    let a = h[0]
    let b = h[1]
    let c = h[2]
    let d = h[3]
    let e = h[4]
    let f = h[5]
    let g = h[6]
    let hh = h[7]

    for (let t = 0; t < 64; t += 1) {
      const s1 = (rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)) >>> 0
      const ch = ((e & f) ^ (~e & g)) >>> 0
      const temp1 = (hh + s1 + ch + K256[t] + w[t]) >>> 0
      const s0 = (rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)) >>> 0
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0
      const temp2 = (s0 + maj) >>> 0

      hh = g
      g = f
      f = e
      e = (d + temp1) >>> 0
      d = c
      c = b
      b = a
      a = (temp1 + temp2) >>> 0
    }

    h[0] = (h[0] + a) >>> 0
    h[1] = (h[1] + b) >>> 0
    h[2] = (h[2] + c) >>> 0
    h[3] = (h[3] + d) >>> 0
    h[4] = (h[4] + e) >>> 0
    h[5] = (h[5] + f) >>> 0
    h[6] = (h[6] + g) >>> 0
    h[7] = (h[7] + hh) >>> 0
  }

  const digest = alloc(32)
  for (let i = 0; i < 8; i += 1) {
    digest[i * 4] = (h[i] >>> 24) & 0xff
    digest[i * 4 + 1] = (h[i] >>> 16) & 0xff
    digest[i * 4 + 2] = (h[i] >>> 8) & 0xff
    digest[i * 4 + 3] = h[i] & 0xff
  }
  return digest
}

/**
 * Shared SHA-512 core; SHA-384 is the same permutation with a different IV, truncated.
 */
const sha512Core = (message: Uint8Array, initialHi: Uint32Array, initialLo: Uint32Array, outputBytes: number) => {
  const padded = padMessage(message, 128, 16)

  const wHi = new U32(80)
  const wLo = new U32(80)
  const hHi = new U32(initialHi)
  const hLo = new U32(initialLo)

  for (let offset = 0; offset < padded.length; offset += 128) {
    for (let t = 0; t < 16; t += 1) {
      const i = offset + t * 8
      wHi[t] = ((padded[i] << 24) | (padded[i + 1] << 16) | (padded[i + 2] << 8) | padded[i + 3]) >>> 0
      wLo[t] = ((padded[i + 4] << 24) | (padded[i + 5] << 16) | (padded[i + 6] << 8) | padded[i + 7]) >>> 0
    }

    for (let t = 16; t < 80; t += 1) {
      const x15Hi = wHi[t - 15]
      const x15Lo = wLo[t - 15]
      // s0 = ROTR(x,1) ^ ROTR(x,8) ^ SHR(x,7)
      const s0Hi = ((x15Hi >>> 1) | (x15Lo << 31)) ^ ((x15Hi >>> 8) | (x15Lo << 24)) ^ (x15Hi >>> 7)
      const s0Lo = ((x15Lo >>> 1) | (x15Hi << 31)) ^ ((x15Lo >>> 8) | (x15Hi << 24)) ^ ((x15Lo >>> 7) | (x15Hi << 25))

      const x2Hi = wHi[t - 2]
      const x2Lo = wLo[t - 2]
      // s1 = ROTR(x,19) ^ ROTR(x,61) ^ SHR(x,6); ROTR 61 crosses the word boundary.
      const s1Hi = ((x2Hi >>> 19) | (x2Lo << 13)) ^ ((x2Lo >>> 29) | (x2Hi << 3)) ^ (x2Hi >>> 6)
      const s1Lo = ((x2Lo >>> 19) | (x2Hi << 13)) ^ ((x2Hi >>> 29) | (x2Lo << 3)) ^ ((x2Lo >>> 6) | (x2Hi << 26))

      const loSum = (wLo[t - 16] >>> 0) + (s0Lo >>> 0) + (wLo[t - 7] >>> 0) + (s1Lo >>> 0)
      const carry = (loSum / 0x100000000) | 0
      wLo[t] = loSum >>> 0
      wHi[t] = ((wHi[t - 16] >>> 0) + (s0Hi >>> 0) + (wHi[t - 7] >>> 0) + (s1Hi >>> 0) + carry) >>> 0
    }

    let aHi = hHi[0]
    let aLo = hLo[0]
    let bHi = hHi[1]
    let bLo = hLo[1]
    let cHi = hHi[2]
    let cLo = hLo[2]
    let dHi = hHi[3]
    let dLo = hLo[3]
    let eHi = hHi[4]
    let eLo = hLo[4]
    let fHi = hHi[5]
    let fLo = hLo[5]
    let gHi = hHi[6]
    let gLo = hLo[6]
    let hiH = hHi[7]
    let loH = hLo[7]

    for (let t = 0; t < 80; t += 1) {
      // Sigma1(e) = ROTR(e,14) ^ ROTR(e,18) ^ ROTR(e,41)
      const sig1Hi = ((eHi >>> 14) | (eLo << 18)) ^ ((eHi >>> 18) | (eLo << 14)) ^ ((eLo >>> 9) | (eHi << 23))
      const sig1Lo = ((eLo >>> 14) | (eHi << 18)) ^ ((eLo >>> 18) | (eHi << 14)) ^ ((eHi >>> 9) | (eLo << 23))

      const chHi = (eHi & fHi) ^ (~eHi & gHi)
      const chLo = (eLo & fLo) ^ (~eLo & gLo)

      // Sigma0(a) = ROTR(a,28) ^ ROTR(a,34) ^ ROTR(a,39)
      const sig0Hi = ((aHi >>> 28) | (aLo << 4)) ^ ((aLo >>> 2) | (aHi << 30)) ^ ((aLo >>> 7) | (aHi << 25))
      const sig0Lo = ((aLo >>> 28) | (aHi << 4)) ^ ((aHi >>> 2) | (aLo << 30)) ^ ((aHi >>> 7) | (aLo << 25))

      const majHi = (aHi & bHi) ^ (aHi & cHi) ^ (bHi & cHi)
      const majLo = (aLo & bLo) ^ (aLo & cLo) ^ (bLo & cLo)

      const t1Lo = (loH >>> 0) + (sig1Lo >>> 0) + (chLo >>> 0) + K512_LO[t] + (wLo[t] >>> 0)
      const t1Carry = (t1Lo / 0x100000000) | 0
      const t1LoOut = t1Lo >>> 0
      const t1HiOut = ((hiH >>> 0) + (sig1Hi >>> 0) + (chHi >>> 0) + K512_HI[t] + (wHi[t] >>> 0) + t1Carry) >>> 0

      const t2Lo = (sig0Lo >>> 0) + (majLo >>> 0)
      const t2Carry = (t2Lo / 0x100000000) | 0
      const t2LoOut = t2Lo >>> 0
      const t2HiOut = ((sig0Hi >>> 0) + (majHi >>> 0) + t2Carry) >>> 0

      hiH = gHi
      loH = gLo
      gHi = fHi
      gLo = fLo
      fHi = eHi
      fLo = eLo

      const eLoSum = (dLo >>> 0) + t1LoOut
      const eCarry = (eLoSum / 0x100000000) | 0
      eLo = eLoSum >>> 0
      eHi = ((dHi >>> 0) + t1HiOut + eCarry) >>> 0

      dHi = cHi
      dLo = cLo
      cHi = bHi
      cLo = bLo
      bHi = aHi
      bLo = aLo

      const aLoSum = t1LoOut + t2LoOut
      const aCarry = (aLoSum / 0x100000000) | 0
      aLo = aLoSum >>> 0
      aHi = (t1HiOut + t2HiOut + aCarry) >>> 0
    }

    const nextHi = [aHi, bHi, cHi, dHi, eHi, fHi, gHi, hiH]
    const nextLo = [aLo, bLo, cLo, dLo, eLo, fLo, gLo, loH]

    for (let i = 0; i < 8; i += 1) {
      const loSum = (hLo[i] >>> 0) + (nextLo[i] >>> 0)
      const carry = (loSum / 0x100000000) | 0
      hLo[i] = loSum >>> 0
      hHi[i] = ((hHi[i] >>> 0) + (nextHi[i] >>> 0) + carry) >>> 0
    }
  }

  const full = alloc(64)
  for (let i = 0; i < 8; i += 1) {
    full[i * 8] = (hHi[i] >>> 24) & 0xff
    full[i * 8 + 1] = (hHi[i] >>> 16) & 0xff
    full[i * 8 + 2] = (hHi[i] >>> 8) & 0xff
    full[i * 8 + 3] = hHi[i] & 0xff
    full[i * 8 + 4] = (hLo[i] >>> 24) & 0xff
    full[i * 8 + 5] = (hLo[i] >>> 16) & 0xff
    full[i * 8 + 6] = (hLo[i] >>> 8) & 0xff
    full[i * 8 + 7] = hLo[i] & 0xff
  }

  return full.slice(0, outputBytes)
}

const sha512 = (message: Uint8Array): Uint8Array => sha512Core(message, H512_HI, H512_LO, 64)
const sha384 = (message: Uint8Array): Uint8Array => sha512Core(message, H384_HI, H384_LO, 48)

export const BLOCK_SIZE: Record<HashAlgorithm, number> = {
  'SHA-1': 64,
  'SHA-256': 64,
  'SHA-384': 128,
  'SHA-512': 128,
}

export const DIGEST_SIZE: Record<HashAlgorithm, number> = {
  'SHA-1': 20,
  'SHA-256': 32,
  'SHA-384': 48,
  'SHA-512': 64,
}

export const digest = (algorithm: HashAlgorithm, message: Uint8Array): Uint8Array => {
  switch (algorithm) {
    case 'SHA-1':
      return sha1(message)
    case 'SHA-256':
      return sha256(message)
    case 'SHA-384':
      return sha384(message)
    case 'SHA-512':
      return sha512(message)
    default:
      throw new Error(`Unsupported hash algorithm: ${algorithm as string}`)
  }
}

export const concat = (...parts: Uint8Array[]): Uint8Array => {
  let total = 0
  for (let i = 0; i < parts.length; i += 1) {
    total += parts[i].length
  }

  const output = alloc(total)
  let offset = 0
  for (let i = 0; i < parts.length; i += 1) {
    output.set(parts[i], offset)
    offset += parts[i].length
  }

  return output
}
