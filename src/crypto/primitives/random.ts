/**
 * HMAC-DRBG (NIST SP 800-90A) over SHA-512.
 *
 * Entropy is the one thing JS genuinely cannot manufacture, so `crypto.getRandomValues`
 * stays in the picture -- but it is a *seed source*, not the output. Consequences:
 *
 *   - The reference is captured at module load (see intrinsics), so a hook installed
 *     afterwards never sees a call.
 *   - It is mixed with ambient noise (performance.now, Date.now, Math.random) and a
 *     call counter, so an attacker has to own every source, not just one.
 *   - State is carried forward across reseeds, so once we have been seeded with real
 *     entropy even a fully attacker-controlled reseed cannot rewind us to a known state.
 *
 * What this does not fix: if `getRandomValues` is already compromised at load time and
 * the ambient sources are predictable, the initial seed is weak. Nothing running inside
 * the page can fix that.
 */

import { hmac } from './hmac'
import { concat } from './sha'
import { U8, F64, alloc, getHostEntropy, ambientNoise } from './intrinsics'

const HASH = 'SHA-512' as const
const OUTPUT_LENGTH = 64
const RESEED_INTERVAL = 1024

let key = alloc(OUTPUT_LENGTH) // K
let value = alloc(OUTPUT_LENGTH) // V
let seeded = false
let counter = 0
let calls = 0

const ONE = new U8([0x01])
const ZERO = new U8([0x00])

/** The DRBG update step: fold `seed` (possibly empty) into (K, V). */
const update = (seed: Uint8Array): void => {
  key = hmac(HASH, key, concat(value, ZERO, seed))
  value = hmac(HASH, key, value)

  if (seed.length > 0) {
    key = hmac(HASH, key, concat(value, ONE, seed))
    value = hmac(HASH, key, value)
  }
}

const gatherEntropy = (): Uint8Array => {
  const hostBytes = alloc(48)
  const haveHostEntropy = getHostEntropy(hostBytes)

  if (!haveHostEntropy && !seeded) {
    // Refusing beats silently handing back guessable key material.
    throw new Error('No secure random source: crypto.getRandomValues is unavailable')
  }

  counter += 1

  // Fold the ambient noise in through its raw IEEE-754 bytes rather than a textual
  // encoding -- no serializer, no hookable string method, and it all gets hashed anyway.
  const noise = ambientNoise()
  const noiseFloats = new F64([noise[0], noise[1], noise[2], counter, calls])
  const noiseBytes = new U8(noiseFloats.buffer)

  return concat(hostBytes, noiseBytes)
}

const reseed = (): void => {
  update(gatherEntropy())
  seeded = true
  calls = 0
}

export const randomBytes = (length: number): Uint8Array => {
  if (!Number.isInteger(length) || length < 0) {
    throw new Error('randomBytes: length must be a non-negative integer')
  }

  if (!seeded || calls >= RESEED_INTERVAL) {
    reseed()
  }
  calls += 1

  const output = alloc(length)
  let offset = 0

  while (offset < length) {
    value = hmac(HASH, key, value)

    const remaining = length - offset
    output.set(value.subarray(0, remaining < OUTPUT_LENGTH ? remaining : OUTPUT_LENGTH), offset)
    offset += OUTPUT_LENGTH
  }

  // Rotate the state so this output cannot be replayed from a later state leak.
  update(alloc(0))

  return output
}
