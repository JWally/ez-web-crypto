/**
 * NIST P-256 (secp256r1): ECDH and ECDSA. Replaces `crypto.subtle`'s ECDH/ECDSA.
 *
 * Field arithmetic is BigInt; points are carried in Jacobian coordinates so the inner
 * loop never inverts. Scalar multiplication is a plain left-to-right double-and-add,
 * which is *not* constant-time -- see the caveat in README. BigInt is not constant-time
 * in any JS engine, so a timing-hardened ladder here would be security theatre; the
 * honest mitigation is to keep long-lived private keys off the client.
 */

import { digest } from './sha'
import { randomBytes } from './random'
import { alloc } from './intrinsics'

/* eslint-disable no-bitwise */

const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn
export const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n

const A = P - 3n
const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn
const GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n
const GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n

const FIELD_BYTES = 32

export class CurveError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'CurveError'
  }
}

const mod = (value: bigint, modulus: bigint = P): bigint => {
  const result = value % modulus
  return result >= 0n ? result : result + modulus
}

/** Extended Euclid; `value` must be non-zero mod `modulus`. */
const invert = (value: bigint, modulus: bigint = P): bigint => {
  let a = mod(value, modulus)
  let b = modulus
  let x = 0n
  let y = 1n

  if (a === 0n) {
    throw new CurveError('Cannot invert zero')
  }

  while (a !== 0n) {
    const quotient = b / a
    const remainder = b % a

    const nextX = x - quotient * y

    b = a
    a = remainder
    x = y
    y = nextX
  }

  if (b !== 1n) {
    throw new CurveError('Value is not invertible')
  }

  return mod(x, modulus)
}

// --- Points ---------------------------------------------------------------------

interface Jacobian {
  x: bigint
  y: bigint
  z: bigint
}

interface AffinePoint {
  x: bigint
  y: bigint
}

const INFINITY: Jacobian = { x: 0n, y: 1n, z: 0n }

const toJacobian = (point: AffinePoint): Jacobian => ({ x: point.x, y: point.y, z: 1n })

const double = (point: Jacobian): Jacobian => {
  const { x, y, z } = point

  if (z === 0n || y === 0n) {
    return INFINITY
  }

  // dbl-2001-b, which assumes a = -3 (true for P-256).
  const delta = mod(z * z)
  const gamma = mod(y * y)
  const beta = mod(x * gamma)
  const alpha = mod(3n * mod(x - delta) * mod(x + delta))

  const x3 = mod(alpha * alpha - 8n * beta)
  const z3 = mod(mod(y + z) * mod(y + z) - gamma - delta)
  const y3 = mod(alpha * mod(4n * beta - x3) - 8n * mod(gamma * gamma))

  return { x: x3, y: y3, z: z3 }
}

const add = (p1: Jacobian, p2: Jacobian): Jacobian => {
  if (p1.z === 0n) {
    return p2
  }
  if (p2.z === 0n) {
    return p1
  }

  // add-2007-bl
  const z1z1 = mod(p1.z * p1.z)
  const z2z2 = mod(p2.z * p2.z)
  const u1 = mod(p1.x * z2z2)
  const u2 = mod(p2.x * z1z1)
  const s1 = mod(p1.y * p2.z * z2z2)
  const s2 = mod(p2.y * p1.z * z1z1)

  const h = mod(u2 - u1)
  const r = mod(2n * mod(s2 - s1))

  if (h === 0n) {
    // Same x: either the same point (double it) or mutual inverses (result is infinity).
    return r === 0n ? double(p1) : INFINITY
  }

  const i = mod(mod(2n * h) * mod(2n * h))
  const j = mod(h * i)
  const v = mod(u1 * i)

  const x3 = mod(r * r - j - 2n * v)
  const y3 = mod(r * mod(v - x3) - 2n * mod(s1 * j))
  const z3 = mod(mod(mod(p1.z + p2.z) * mod(p1.z + p2.z) - z1z1 - z2z2) * h)

  return { x: x3, y: y3, z: z3 }
}

const toAffine = (point: Jacobian): AffinePoint => {
  if (point.z === 0n) {
    throw new CurveError('Point at infinity has no affine representation')
  }

  const zInv = invert(point.z)
  const zInv2 = mod(zInv * zInv)

  return {
    x: mod(point.x * zInv2),
    y: mod(point.y * zInv2 * zInv),
  }
}

const multiply = (scalar: bigint, point: AffinePoint): Jacobian => {
  if (scalar <= 0n || scalar >= N) {
    throw new CurveError('Scalar out of range')
  }

  const base = toJacobian(point)
  let result = INFINITY

  for (let i = 255; i >= 0; i -= 1) {
    result = double(result)
    if ((scalar >> BigInt(i)) & 1n) {
      result = add(result, base)
    }
  }

  return result
}

const G: AffinePoint = { x: GX, y: GY }

const isOnCurve = (point: AffinePoint): boolean => {
  const { x, y } = point
  if (x < 0n || x >= P || y < 0n || y >= P) {
    return false
  }

  // y^2 == x^3 + ax + b
  return mod(y * y) === mod(mod(x * x * x) + mod(A * x) + B)
}

// --- Encoding -------------------------------------------------------------------

const bytesToBigInt = (bytes: Uint8Array): bigint => {
  let value = 0n
  for (let i = 0; i < bytes.length; i += 1) {
    value = (value << 8n) | BigInt(bytes[i])
  }
  return value
}

const bigIntToBytes = (value: bigint, length: number): Uint8Array => {
  const bytes = alloc(length)
  let remaining = value

  for (let i = length - 1; i >= 0; i -= 1) {
    bytes[i] = Number(remaining & 0xffn)
    remaining >>= 8n
  }

  if (remaining !== 0n) {
    throw new CurveError('Value does not fit in the requested width')
  }

  return bytes
}

/** Parses an uncompressed SEC1 point (0x04 || X || Y) and rejects anything off-curve. */
export const decodePoint = (bytes: Uint8Array): AffinePoint => {
  if (bytes.length !== 1 + FIELD_BYTES * 2 || bytes[0] !== 0x04) {
    throw new CurveError('Expected an uncompressed P-256 point (0x04 || X || Y)')
  }

  const point = {
    x: bytesToBigInt(bytes.subarray(1, 1 + FIELD_BYTES)),
    y: bytesToBigInt(bytes.subarray(1 + FIELD_BYTES)),
  }

  if (!isOnCurve(point)) {
    throw new CurveError('Point is not on the P-256 curve')
  }
  if (point.x === 0n && point.y === 0n) {
    throw new CurveError('Point is the identity')
  }

  return point
}

export const encodePoint = (point: AffinePoint): Uint8Array => {
  const bytes = alloc(1 + FIELD_BYTES * 2)
  bytes[0] = 0x04
  bytes.set(bigIntToBytes(point.x, FIELD_BYTES), 1)
  bytes.set(bigIntToBytes(point.y, FIELD_BYTES), 1 + FIELD_BYTES)
  return bytes
}

const decodeScalar = (bytes: Uint8Array): bigint => {
  if (bytes.length !== FIELD_BYTES) {
    throw new CurveError('P-256 private keys are 32 bytes')
  }

  const scalar = bytesToBigInt(bytes)
  if (scalar <= 0n || scalar >= N) {
    throw new CurveError('Private key is out of range')
  }

  return scalar
}

// --- Key agreement and signing --------------------------------------------------

const randomScalar = (): bigint => {
  // Rejection sampling: uniform over [1, n-1], no modular bias.
  for (let attempt = 0; attempt < 64; attempt += 1) {
    const candidate = bytesToBigInt(randomBytes(FIELD_BYTES))
    if (candidate > 0n && candidate < N) {
      return candidate
    }
  }

  throw new CurveError('Failed to sample a scalar')
}

interface KeyPair {
  privateKey: Uint8Array
  publicKey: Uint8Array
}

export const derivePublicKey = (privateKey: Uint8Array): Uint8Array =>
  encodePoint(toAffine(multiply(decodeScalar(privateKey), G)))

export const generateKeyPair = (): KeyPair => {
  const scalar = randomScalar()
  const privateKey = bigIntToBytes(scalar, FIELD_BYTES)

  return { privateKey, publicKey: encodePoint(toAffine(multiply(scalar, G))) }
}

/** ECDH: the X coordinate of d*Q, which is what WebCrypto's deriveBits returns. */
export const deriveSharedSecret = (privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array => {
  const scalar = decodeScalar(privateKey)
  const point = decodePoint(publicKey) // validates -- this is the invalid-curve defence

  const shared = toAffine(multiply(scalar, point))
  return bigIntToBytes(shared.x, FIELD_BYTES)
}

/** The leftmost min(bitlen(n), bitlen(hash)) bits of the digest, as an integer. */
const hashToInt = (message: Uint8Array): bigint => bytesToBigInt(digest('SHA-256', message))

export const sign = (privateKey: Uint8Array, message: Uint8Array): Uint8Array => {
  const d = decodeScalar(privateKey)
  const e = hashToInt(message)

  for (let attempt = 0; attempt < 64; attempt += 1) {
    const k = randomScalar()

    const point = toAffine(multiply(k, G))
    const r = mod(point.x, N)
    if (r === 0n) {
      continue
    }

    const s = mod(invert(k, N) * mod(e + r * d, N), N)
    if (s === 0n) {
      continue
    }

    const signature = alloc(FIELD_BYTES * 2)
    signature.set(bigIntToBytes(r, FIELD_BYTES))
    signature.set(bigIntToBytes(s, FIELD_BYTES), FIELD_BYTES)
    return signature
  }

  throw new CurveError('Failed to produce a signature')
}

export const verify = (publicKey: Uint8Array, signature: Uint8Array, message: Uint8Array): boolean => {
  if (signature.length !== FIELD_BYTES * 2) {
    return false
  }

  let point: AffinePoint
  try {
    point = decodePoint(publicKey)
  } catch {
    return false
  }

  const r = bytesToBigInt(signature.subarray(0, FIELD_BYTES))
  const s = bytesToBigInt(signature.subarray(FIELD_BYTES))

  if (r <= 0n || r >= N || s <= 0n || s >= N) {
    return false
  }

  const e = hashToInt(message)

  try {
    const w = invert(s, N)
    const u1 = mod(e * w, N)
    const u2 = mod(r * w, N)

    // u1*G + u2*Q; either scalar can legitimately be zero, which multiply() rejects.
    const term1 = u1 === 0n ? INFINITY : multiply(u1, G)
    const term2 = u2 === 0n ? INFINITY : multiply(u2, point)
    const sum = add(term1, term2)

    if (sum.z === 0n) {
      return false
    }

    return mod(toAffine(sum).x, N) === r
  } catch {
    return false
  }
}
