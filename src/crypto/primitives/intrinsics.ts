/**
 * Snapshots of the platform intrinsics the primitives rely on, taken at
 * module-evaluation time.
 *
 * Everything under primitives/ goes through these bindings instead of touching a
 * live global, so a script that later swaps out `Uint8Array`, patches
 * `String.prototype.charCodeAt`, or wraps `crypto.getRandomValues` sees nothing and
 * steers nothing. The window is "before this module is evaluated" -- import the
 * library early.
 *
 * Deliberately absent: `crypto.subtle`, `btoa`/`atob`, `TextEncoder`/`TextDecoder`, and
 * `JSON`. Those are implemented in JS under this directory rather than borrowed from the
 * host -- `JSON` because the password payload carries the AES key, and stringify/parse
 * are as hookable as everything else here.
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

export const U8 = Uint8Array
export const U32 = Uint32Array
export const F64 = Float64Array

const reflectApply = Reflect.apply
const stringCharCodeAt = String.prototype.charCodeAt
const stringFromCharCode = String.fromCharCode
const stringSlice = String.prototype.slice
const stringIndexOf = String.prototype.indexOf
const arrayJoin = Array.prototype.join

// Reused so the hot paths (base64/utf8 codecs) don't allocate an argument array per
// character. Safe to share: every call reads the result before yielding.
const arg1: [number] = [0]

export const charCodeAt = (text: string, index: number): number => {
  arg1[0] = index
  return reflectApply(stringCharCodeAt, text, arg1) as number
}

export const fromCharCodes = (codes: number[]): string =>
  reflectApply(stringFromCharCode, null, codes) as unknown as string

export const join = (parts: string[], separator: string): string =>
  reflectApply(arrayJoin, parts, [separator]) as unknown as string

/** `String.prototype.slice`, snapshotted -- so parsing the key payload never touches a live method. */
export const slice = (text: string, start: number, end: number): string =>
  reflectApply(stringSlice, text, [start, end]) as unknown as string

/** `String.prototype.indexOf`, snapshotted. Returns -1 when not found. */
export const indexOf = (text: string, search: string, from: number): number =>
  reflectApply(stringIndexOf, text, [search, from]) as unknown as number

/** `crypto.getRandomValues`, pre-bound. The one host capability JS cannot replace. */
const hostCrypto: Crypto | undefined = (globalThis as any).crypto
const hostGetRandomValues: ((array: Uint8Array) => Uint8Array) | undefined =
  hostCrypto && typeof hostCrypto.getRandomValues === 'function'
    ? (hostCrypto.getRandomValues.bind(hostCrypto) as (array: Uint8Array) => Uint8Array)
    : undefined

export const getHostEntropy = (bytes: Uint8Array): boolean => {
  if (!hostGetRandomValues) {
    return false
  }
  hostGetRandomValues(bytes)
  return true
}

/** Ambient noise to fold in alongside the host RNG, so no single hooked source decides the seed. */
const hostPerformance: Performance | undefined = (globalThis as any).performance
const performanceNow: (() => number) | undefined =
  hostPerformance && typeof hostPerformance.now === 'function'
    ? (hostPerformance.now.bind(hostPerformance) as () => number)
    : undefined
const dateNow = Date.now
const mathRandom = Math.random

export const ambientNoise = (): number[] => [
  performanceNow ? performanceNow() : 0,
  reflectApply(dateNow, Date, []) as unknown as number,
  reflectApply(mathRandom, Math, []) as unknown as number,
]

export const setTimeoutRef = globalThis.setTimeout

export const alloc = (length: number): Uint8Array => new U8(length)
