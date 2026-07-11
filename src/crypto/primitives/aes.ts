/**
 * AES-GCM. Replaces `crypto.subtle.encrypt/decrypt({name: 'AES-GCM'})`.
 *
 * Only the forward block cipher is implemented -- GCM is counter mode, so decryption
 * uses the same direction. The S-box is derived at load time from the GF(2^8) inverse
 * plus the affine transform rather than pasted in as a 256-entry table: a transcription
 * slip in a lookup table is silent, a wrong construction is not.
 *
 * Tag length is fixed at 128 bits and the tag is appended to the ciphertext, matching
 * what WebCrypto does by default.
 */

import { U8, U32, alloc } from './intrinsics'

/* eslint-disable no-bitwise */

const BLOCK = 16
const TAG_LENGTH = 16

// --- GF(2^8) tables -------------------------------------------------------------

const xtime = (a: number): number => ((a << 1) ^ (a & 0x80 ? 0x1b : 0)) & 0xff

const EXP = new U8(256)
const LOG = new U8(256)

{
  let x = 1
  for (let i = 0; i < 255; i += 1) {
    EXP[i] = x
    LOG[x] = i
    x = (x ^ xtime(x)) & 0xff // multiply by the generator 3
  }
  // 3^255 == 3^0 == 1. inverse(1) indexes EXP[255 - LOG[1]] = EXP[255], so it has to be here.
  EXP[255] = 1
}

const inverse = (a: number): number => (a === 0 ? 0 : EXP[255 - LOG[a]])

const rotl8 = (a: number, n: number): number => ((a << n) | (a >>> (8 - n))) & 0xff

const SBOX = new U8(256)
for (let i = 0; i < 256; i += 1) {
  const b = inverse(i)
  SBOX[i] = (b ^ rotl8(b, 1) ^ rotl8(b, 2) ^ rotl8(b, 3) ^ rotl8(b, 4) ^ 0x63) & 0xff
}

const RCON = new U8([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d])

// --- Block cipher ---------------------------------------------------------------

interface AesKey {
  roundKeys: Uint8Array
  rounds: number
}

const expandKey = (key: Uint8Array): AesKey => {
  const nk = key.length / 4
  if (nk !== 4 && nk !== 6 && nk !== 8) {
    throw new Error(`Invalid AES key length: ${key.length} bytes`)
  }

  const rounds = nk + 6
  const totalWords = 4 * (rounds + 1)
  const roundKeys = alloc(totalWords * 4)
  roundKeys.set(key)

  for (let i = nk; i < totalWords; i += 1) {
    let t0 = roundKeys[(i - 1) * 4]
    let t1 = roundKeys[(i - 1) * 4 + 1]
    let t2 = roundKeys[(i - 1) * 4 + 2]
    let t3 = roundKeys[(i - 1) * 4 + 3]

    if (i % nk === 0) {
      // RotWord + SubWord + Rcon
      const temp = t0
      t0 = SBOX[t1] ^ RCON[i / nk - 1]
      t1 = SBOX[t2]
      t2 = SBOX[t3]
      t3 = SBOX[temp]
    } else if (nk > 6 && i % nk === 4) {
      t0 = SBOX[t0]
      t1 = SBOX[t1]
      t2 = SBOX[t2]
      t3 = SBOX[t3]
    }

    roundKeys[i * 4] = roundKeys[(i - nk) * 4] ^ t0
    roundKeys[i * 4 + 1] = roundKeys[(i - nk) * 4 + 1] ^ t1
    roundKeys[i * 4 + 2] = roundKeys[(i - nk) * 4 + 2] ^ t2
    roundKeys[i * 4 + 3] = roundKeys[(i - nk) * 4 + 3] ^ t3
  }

  return { roundKeys, rounds }
}

/** Encrypts `block` in place. */
const encryptBlock = (key: AesKey, block: Uint8Array): void => {
  const { roundKeys, rounds } = key

  for (let i = 0; i < BLOCK; i += 1) {
    block[i] ^= roundKeys[i]
  }

  for (let round = 1; round <= rounds; round += 1) {
    // SubBytes
    for (let i = 0; i < BLOCK; i += 1) {
      block[i] = SBOX[block[i]]
    }

    // ShiftRows -- the state is column-major, so row r shifts left by r.
    let t = block[1]
    block[1] = block[5]
    block[5] = block[9]
    block[9] = block[13]
    block[13] = t

    t = block[2]
    block[2] = block[10]
    block[10] = t
    t = block[6]
    block[6] = block[14]
    block[14] = t

    t = block[15]
    block[15] = block[11]
    block[11] = block[7]
    block[7] = block[3]
    block[3] = t

    // MixColumns (skipped in the final round)
    if (round !== rounds) {
      for (let c = 0; c < 4; c += 1) {
        const i = c * 4
        const a0 = block[i]
        const a1 = block[i + 1]
        const a2 = block[i + 2]
        const a3 = block[i + 3]
        const all = a0 ^ a1 ^ a2 ^ a3

        block[i] = a0 ^ all ^ xtime(a0 ^ a1)
        block[i + 1] = a1 ^ all ^ xtime(a1 ^ a2)
        block[i + 2] = a2 ^ all ^ xtime(a2 ^ a3)
        block[i + 3] = a3 ^ all ^ xtime(a3 ^ a0)
      }
    }

    // AddRoundKey
    const offset = round * BLOCK
    for (let i = 0; i < BLOCK; i += 1) {
      block[i] ^= roundKeys[offset + i]
    }
  }
}

// --- GHASH ----------------------------------------------------------------------

/** Z := Z * H over GF(2^128), with the bit-reversed convention GCM uses. */
const ghashMultiply = (z: Uint32Array, h: Uint32Array): void => {
  const result = new U32(4)
  const v = new U32(h)

  for (let i = 0; i < 128; i += 1) {
    if ((z[i >>> 5] >>> (31 - (i & 31))) & 1) {
      result[0] ^= v[0]
      result[1] ^= v[1]
      result[2] ^= v[2]
      result[3] ^= v[3]
    }

    const lsb = v[3] & 1
    v[3] = (v[3] >>> 1) | ((v[2] & 1) << 31)
    v[2] = (v[2] >>> 1) | ((v[1] & 1) << 31)
    v[1] = (v[1] >>> 1) | ((v[0] & 1) << 31)
    v[0] >>>= 1

    if (lsb) {
      v[0] ^= 0xe1000000
    }
  }

  z.set(result)
}

const wordAt = (bytes: Uint8Array, offset: number): number =>
  ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0

/** GHASH over zero-padded `data`, folded into the accumulator `y`. */
const ghashInto = (y: Uint32Array, h: Uint32Array, data: Uint8Array): void => {
  const { length } = data

  for (let offset = 0; offset < length; offset += BLOCK) {
    const remaining = length - offset

    if (remaining >= BLOCK) {
      y[0] ^= wordAt(data, offset)
      y[1] ^= wordAt(data, offset + 4)
      y[2] ^= wordAt(data, offset + 8)
      y[3] ^= wordAt(data, offset + 12)
    } else {
      const block = alloc(BLOCK)
      block.set(data.subarray(offset))
      y[0] ^= wordAt(block, 0)
      y[1] ^= wordAt(block, 4)
      y[2] ^= wordAt(block, 8)
      y[3] ^= wordAt(block, 12)
    }

    ghashMultiply(y, h)
  }
}

/** The trailing GHASH block: two big-endian 64-bit bit-lengths, [len(A) || len(C)]. */
const lengthBlock = (aadBits: number, cipherBits: number): Uint8Array => {
  const block = alloc(BLOCK)

  const write64 = (offset: number, bits: number): void => {
    // `>>>` coerces to uint32, so the high half has to be split off with division first.
    const hi = (bits / 0x100000000) | 0
    const lo = bits >>> 0

    block[offset] = (hi >>> 24) & 0xff
    block[offset + 1] = (hi >>> 16) & 0xff
    block[offset + 2] = (hi >>> 8) & 0xff
    block[offset + 3] = hi & 0xff
    block[offset + 4] = (lo >>> 24) & 0xff
    block[offset + 5] = (lo >>> 16) & 0xff
    block[offset + 6] = (lo >>> 8) & 0xff
    block[offset + 7] = lo & 0xff
  }

  write64(0, aadBits)
  write64(8, cipherBits)

  return block
}

const incrementCounter = (counter: Uint8Array): void => {
  for (let i = 15; i >= 12; i -= 1) {
    counter[i] = (counter[i] + 1) & 0xff
    if (counter[i] !== 0) {
      return
    }
  }
}

/** GCTR: XOR `data` with the AES keystream starting at `counter` (which is advanced). */
const gctr = (key: AesKey, counter: Uint8Array, data: Uint8Array): Uint8Array => {
  const output = alloc(data.length)
  const keystream = alloc(BLOCK)

  for (let offset = 0; offset < data.length; offset += BLOCK) {
    keystream.set(counter)
    encryptBlock(key, keystream)

    const remaining = data.length - offset
    const size = remaining < BLOCK ? remaining : BLOCK
    for (let i = 0; i < size; i += 1) {
      output[offset + i] = data[offset + i] ^ keystream[i]
    }

    incrementCounter(counter)
  }

  return output
}

interface GcmContext {
  key: AesKey
  h: Uint32Array
  j0: Uint8Array
}

const initGcm = (rawKey: Uint8Array, iv: Uint8Array): GcmContext => {
  if (iv.length === 0) {
    throw new Error('AES-GCM: IV must not be empty')
  }

  const key = expandKey(rawKey)

  // H = AES_K(0^128)
  const hBytes = alloc(BLOCK)
  encryptBlock(key, hBytes)
  const h = new U32([wordAt(hBytes, 0), wordAt(hBytes, 4), wordAt(hBytes, 8), wordAt(hBytes, 12)])

  let j0: Uint8Array
  if (iv.length === 12) {
    j0 = alloc(BLOCK)
    j0.set(iv)
    j0[15] = 1
  } else {
    // Any other IV length gets folded through GHASH, per NIST SP 800-38D.
    const y = new U32(4)
    ghashInto(y, h, iv)
    ghashInto(y, h, lengthBlock(0, iv.length * 8))

    j0 = alloc(BLOCK)
    for (let i = 0; i < 4; i += 1) {
      j0[i * 4] = (y[i] >>> 24) & 0xff
      j0[i * 4 + 1] = (y[i] >>> 16) & 0xff
      j0[i * 4 + 2] = (y[i] >>> 8) & 0xff
      j0[i * 4 + 3] = y[i] & 0xff
    }
  }

  return { key, h, j0 }
}

const computeTag = (context: GcmContext, ciphertext: Uint8Array, aad: Uint8Array): Uint8Array => {
  const { key, h, j0 } = context

  const y = new U32(4)
  ghashInto(y, h, aad)
  ghashInto(y, h, ciphertext)
  ghashInto(y, h, lengthBlock(aad.length * 8, ciphertext.length * 8))

  const s = alloc(BLOCK)
  for (let i = 0; i < 4; i += 1) {
    s[i * 4] = (y[i] >>> 24) & 0xff
    s[i * 4 + 1] = (y[i] >>> 16) & 0xff
    s[i * 4 + 2] = (y[i] >>> 8) & 0xff
    s[i * 4 + 3] = y[i] & 0xff
  }

  return gctr(key, j0.slice(), s)
}

const EMPTY = alloc(0)

export const gcmEncrypt = (
  rawKey: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array = EMPTY
): Uint8Array => {
  const context = initGcm(rawKey, iv)

  const counter = context.j0.slice()
  incrementCounter(counter)
  const ciphertext = gctr(context.key, counter, plaintext)

  const tag = computeTag(context, ciphertext, aad)

  const output = alloc(ciphertext.length + TAG_LENGTH)
  output.set(ciphertext)
  output.set(tag, ciphertext.length)

  return output
}

class AuthenticationError extends Error {
  constructor(message: string = 'AES-GCM: authentication tag mismatch') {
    super(message)
    this.name = 'AuthenticationError'
  }
}

export const gcmDecrypt = (
  rawKey: Uint8Array,
  iv: Uint8Array,
  ciphertextWithTag: Uint8Array,
  aad: Uint8Array = EMPTY
): Uint8Array => {
  if (ciphertextWithTag.length < TAG_LENGTH) {
    throw new AuthenticationError('AES-GCM: ciphertext is shorter than the authentication tag')
  }

  const context = initGcm(rawKey, iv)

  const split = ciphertextWithTag.length - TAG_LENGTH
  const ciphertext = ciphertextWithTag.subarray(0, split)
  const tag = ciphertextWithTag.subarray(split)

  const expected = computeTag(context, ciphertext, aad)

  // Constant-time compare: never branch on tag content.
  let diff = 0
  for (let i = 0; i < TAG_LENGTH; i += 1) {
    diff |= expected[i] ^ tag[i]
  }
  if (diff !== 0) {
    throw new AuthenticationError()
  }

  const counter = context.j0.slice()
  incrementCounter(counter)

  return gctr(context.key, counter, ciphertext)
}
