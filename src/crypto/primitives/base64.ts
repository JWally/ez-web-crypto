/**
 * Base64 codec. Replaces `btoa`/`atob`.
 *
 * Decoding matches the WHATWG "forgiving-base64" rules that `atob` implements --
 * ASCII whitespace is stripped, everything else outside the alphabet is an error --
 * because callers (notably key conversion) rely on a malformed string throwing.
 */

import { U8, charCodeAt, fromCharCodes, join, alloc } from './intrinsics'
import type { Base64String } from '../types'

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

const ENCODE = new U8(64)
for (let i = 0; i < 64; i += 1) {
  ENCODE[i] = charCodeAt(ALPHABET, i)
}

// 0xff = not a base64 character.
const DECODE = new U8(256)
for (let i = 0; i < 256; i += 1) {
  DECODE[i] = 0xff
}
for (let i = 0; i < 64; i += 1) {
  DECODE[ENCODE[i]] = i
}

const isAsciiWhitespace = (code: number): boolean =>
  code === 0x20 || code === 0x09 || code === 0x0a || code === 0x0c || code === 0x0d

export class InvalidBase64Error extends Error {
  constructor(message: string = 'Invalid base64 string') {
    super(message)
    this.name = 'InvalidBase64Error'
  }
}

export const encodeBase64 = (bytes: Uint8Array): Base64String => {
  const { length } = bytes
  const chunks: string[] = []
  const codes: number[] = []

  let i = 0
  for (; i + 2 < length; i += 3) {
    const triple = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2]
    codes[codes.length] = ENCODE[(triple >>> 18) & 63]
    codes[codes.length] = ENCODE[(triple >>> 12) & 63]
    codes[codes.length] = ENCODE[(triple >>> 6) & 63]
    codes[codes.length] = ENCODE[triple & 63]

    // fromCharCode is applied to the accumulator, so keep it under the arg limit.
    if (codes.length >= 4096) {
      chunks[chunks.length] = fromCharCodes(codes)
      codes.length = 0
    }
  }

  const remaining = length - i
  if (remaining === 1) {
    const chunk = bytes[i] << 16
    codes[codes.length] = ENCODE[(chunk >>> 18) & 63]
    codes[codes.length] = ENCODE[(chunk >>> 12) & 63]
    codes[codes.length] = 0x3d // '='
    codes[codes.length] = 0x3d
  } else if (remaining === 2) {
    const chunk = (bytes[i] << 16) | (bytes[i + 1] << 8)
    codes[codes.length] = ENCODE[(chunk >>> 18) & 63]
    codes[codes.length] = ENCODE[(chunk >>> 12) & 63]
    codes[codes.length] = ENCODE[(chunk >>> 6) & 63]
    codes[codes.length] = 0x3d
  }

  if (codes.length > 0) {
    chunks[chunks.length] = fromCharCodes(codes)
  }

  return join(chunks, '')
}

/** Unpadded base64url, as JWK requires for its coordinate fields. */
export const encodeBase64Url = (bytes: Uint8Array): string => {
  const standard = encodeBase64(bytes)

  let out = ''
  for (let i = 0; i < standard.length; i += 1) {
    const code = charCodeAt(standard, i)
    if (code === 0x3d) {
      break // '=' -- base64url is unpadded
    }
    if (code === 0x2b) {
      out += '-'
    } else if (code === 0x2f) {
      out += '_'
    } else {
      out += standard[i]
    }
  }

  return out
}

export const decodeBase64 = (text: Base64String): Uint8Array => {
  if (typeof text !== 'string') {
    throw new InvalidBase64Error('Expected a base64 string')
  }

  // Strip ASCII whitespace, then peel the padding, exactly as forgiving-base64 does.
  const sanitized: number[] = []
  for (let i = 0; i < text.length; i += 1) {
    const code = charCodeAt(text, i)
    if (!isAsciiWhitespace(code)) {
      sanitized[sanitized.length] = code
    }
  }

  // Peel up to two '=' from a properly-padded string, matching forgiving-base64.
  let { length } = sanitized
  if (length % 4 === 0 && length > 0 && sanitized[length - 1] === 0x3d) {
    length -= 1
    if (length > 0 && sanitized[length - 1] === 0x3d) {
      length -= 1
    }
  }

  if (length % 4 === 1) {
    throw new InvalidBase64Error('Invalid base64 length')
  }

  const outputLength = ((length * 3) / 4) | 0
  const output = alloc(outputLength)

  let accumulator = 0
  let bits = 0
  let written = 0

  for (let i = 0; i < length; i += 1) {
    const code = sanitized[i]
    // Out-of-range indices read back as undefined from the table, so gate on the code first.
    const value = code < 256 ? DECODE[code] : 0xff
    if (value === 0xff) {
      throw new InvalidBase64Error('Invalid base64 character')
    }

    accumulator = (accumulator << 6) | value
    bits += 6

    if (bits >= 8) {
      bits -= 8
      output[written] = (accumulator >>> bits) & 0xff
      written += 1
    }
  }

  return output
}
