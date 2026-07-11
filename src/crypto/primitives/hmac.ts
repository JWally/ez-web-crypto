/**
 * HMAC (RFC 2104). Replaces `crypto.subtle.sign({name: 'HMAC'})`.
 */

import { digest, concat, BLOCK_SIZE } from './sha'
import { alloc } from './intrinsics'
import type { HashAlgorithm } from '../types'

/* eslint-disable no-bitwise */

export const hmac = (algorithm: HashAlgorithm, key: Uint8Array, message: Uint8Array): Uint8Array => {
  const blockSize = BLOCK_SIZE[algorithm]

  // Keys longer than the block size are hashed down; shorter ones are zero-padded.
  const normalized = alloc(blockSize)
  normalized.set(key.length > blockSize ? digest(algorithm, key) : key)

  const inner = alloc(blockSize)
  const outer = alloc(blockSize)

  for (let i = 0; i < blockSize; i += 1) {
    inner[i] = normalized[i] ^ 0x36
    outer[i] = normalized[i] ^ 0x5c
  }

  return digest(algorithm, concat(outer, digest(algorithm, concat(inner, message))))
}
