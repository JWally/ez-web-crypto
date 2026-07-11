import { alloc } from './intrinsics'

/**
 * The public API hands back an ArrayBuffer when `returnText` is false, so views have to
 * be unwrapped carefully: a subarray shares its parent's buffer, and returning that would
 * expose neighbouring bytes.
 */
export const toArrayBuffer = (bytes: Uint8Array): ArrayBuffer => {
  if (bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength) {
    return bytes.buffer as ArrayBuffer
  }

  const copy = alloc(bytes.byteLength)
  copy.set(bytes)
  return copy.buffer as ArrayBuffer
}
