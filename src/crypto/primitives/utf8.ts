/**
 * UTF-8 codec. Replaces `TextEncoder`/`TextDecoder`.
 *
 * Lone surrogates encode as U+FFFD and malformed sequences decode to U+FFFD, which
 * is what the WHATWG encoding standard requires of the classes we're standing in for.
 */

import { charCodeAt, fromCharCodes, join, alloc } from './intrinsics'

const REPLACEMENT = 0xfffd

export const encodeUtf8 = (text: string): Uint8Array => {
  const { length } = text

  // Worst case is 3 bytes per UTF-16 unit; a surrogate pair is 2 units -> 4 bytes.
  const scratch = alloc(length * 3)
  let written = 0

  for (let i = 0; i < length; i += 1) {
    let codePoint = charCodeAt(text, i)

    if (codePoint >= 0xd800 && codePoint <= 0xdbff) {
      const low = i + 1 < length ? charCodeAt(text, i + 1) : 0
      if (low >= 0xdc00 && low <= 0xdfff) {
        codePoint = 0x10000 + ((codePoint - 0xd800) << 10) + (low - 0xdc00)
        i += 1
      } else {
        codePoint = REPLACEMENT
      }
    } else if (codePoint >= 0xdc00 && codePoint <= 0xdfff) {
      codePoint = REPLACEMENT
    }

    if (codePoint < 0x80) {
      scratch[written] = codePoint
      written += 1
    } else if (codePoint < 0x800) {
      scratch[written] = 0xc0 | (codePoint >>> 6)
      scratch[written + 1] = 0x80 | (codePoint & 0x3f)
      written += 2
    } else if (codePoint < 0x10000) {
      scratch[written] = 0xe0 | (codePoint >>> 12)
      scratch[written + 1] = 0x80 | ((codePoint >>> 6) & 0x3f)
      scratch[written + 2] = 0x80 | (codePoint & 0x3f)
      written += 3
    } else {
      scratch[written] = 0xf0 | (codePoint >>> 18)
      scratch[written + 1] = 0x80 | ((codePoint >>> 12) & 0x3f)
      scratch[written + 2] = 0x80 | ((codePoint >>> 6) & 0x3f)
      scratch[written + 3] = 0x80 | (codePoint & 0x3f)
      written += 4
    }
  }

  return scratch.subarray(0, written)
}

/**
 * The WHATWG UTF-8 decoder state machine, verbatim.
 *
 * The subtlety worth spelling out: a malformed sequence yields one U+FFFD per *maximal
 * subpart*, not one per byte. `[0xf0, 0x9f, 0x98]` is a truncated emoji and decodes to a
 * single U+FFFD, not three. Byte-at-a-time error handling silently disagrees with
 * TextDecoder here, which is exactly the kind of drift this whole exercise is meant to avoid.
 */
export const decodeUtf8 = (bytes: Uint8Array): string => {
  const { length } = bytes
  const chunks: string[] = []
  const codes: number[] = []

  let codePoint = 0
  let bytesNeeded = 0
  let bytesSeen = 0
  let lowerBoundary = 0x80
  let upperBoundary = 0xbf

  const emit = (value: number): void => {
    if (value > 0xffff) {
      const offset = value - 0x10000
      codes[codes.length] = 0xd800 + (offset >>> 10)
      codes[codes.length] = 0xdc00 + (offset & 0x3ff)
    } else {
      codes[codes.length] = value
    }

    if (codes.length >= 4096) {
      chunks[chunks.length] = fromCharCodes(codes)
      codes.length = 0
    }
  }

  const reset = (): void => {
    codePoint = 0
    bytesNeeded = 0
    bytesSeen = 0
    lowerBoundary = 0x80
    upperBoundary = 0xbf
  }

  let i = 0
  while (i < length) {
    const byte = bytes[i]

    if (bytesNeeded === 0) {
      i += 1

      if (byte <= 0x7f) {
        emit(byte)
      } else if (byte >= 0xc2 && byte <= 0xdf) {
        bytesNeeded = 1
        codePoint = byte & 0x1f
      } else if (byte >= 0xe0 && byte <= 0xef) {
        if (byte === 0xe0) {
          lowerBoundary = 0xa0 // reject overlong
        }
        if (byte === 0xed) {
          upperBoundary = 0x9f // reject surrogates
        }
        bytesNeeded = 2
        codePoint = byte & 0x0f
      } else if (byte >= 0xf0 && byte <= 0xf4) {
        if (byte === 0xf0) {
          lowerBoundary = 0x90 // reject overlong
        }
        if (byte === 0xf4) {
          upperBoundary = 0x8f // reject > U+10FFFF
        }
        bytesNeeded = 3
        codePoint = byte & 0x07
      } else {
        emit(REPLACEMENT)
      }

      continue
    }

    if (byte < lowerBoundary || byte > upperBoundary) {
      // Bail out and re-examine this byte as a fresh lead byte -- do not advance `i`.
      reset()
      emit(REPLACEMENT)
      continue
    }

    lowerBoundary = 0x80
    upperBoundary = 0xbf
    codePoint = (codePoint << 6) | (byte & 0x3f)
    bytesSeen += 1
    i += 1

    if (bytesSeen === bytesNeeded) {
      emit(codePoint)
      reset()
    }
  }

  if (bytesNeeded !== 0) {
    emit(REPLACEMENT) // truncated trailing sequence
  }

  if (codes.length > 0) {
    chunks[chunks.length] = fromCharCodes(codes)
  }

  return join(chunks, '')
}
