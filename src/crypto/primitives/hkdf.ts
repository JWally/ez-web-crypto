/**
 * HKDF (RFC 5869). Replaces `crypto.subtle.deriveBits({name: 'HKDF'})`.
 */

import { hmac } from './hmac'
import { concat, DIGEST_SIZE } from './sha'
import { alloc, U8 } from './intrinsics'
import type { HashAlgorithm } from '../types'

const hkdfExtract = (algorithm: HashAlgorithm, salt: Uint8Array, ikm: Uint8Array): Uint8Array =>
  // An empty salt is equivalent to hashLen zero bytes: HMAC zero-pads the key either way.
  hmac(algorithm, salt, ikm)

export const hkdfExpand = (algorithm: HashAlgorithm, prk: Uint8Array, info: Uint8Array, length: number): Uint8Array => {
  const hashLength = DIGEST_SIZE[algorithm]
  const blocks = ((length + hashLength - 1) / hashLength) | 0 // eslint-disable-line no-bitwise

  if (blocks > 255) {
    throw new Error('HKDF: requested output exceeds 255 blocks')
  }

  const output = alloc(length)
  let previous = alloc(0)
  let offset = 0

  for (let i = 1; i <= blocks; i += 1) {
    previous = hmac(algorithm, prk, concat(previous, info, new U8([i])))

    const remaining = length - offset
    output.set(previous.subarray(0, remaining < hashLength ? remaining : hashLength), offset)
    offset += hashLength
  }

  return output
}

export const hkdf = (
  algorithm: HashAlgorithm,
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number
): Uint8Array => hkdfExpand(algorithm, hkdfExtract(algorithm, salt, ikm), info, length)
