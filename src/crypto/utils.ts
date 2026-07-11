import type { Base64String } from './types'
import { decodeBase64, encodeBase64 } from './primitives/base64'
import { setTimeoutRef } from './primitives/intrinsics'

export const base64ToArray = (strng: Base64String): Uint8Array => decodeBase64(strng)

export const arrayToBase64 = (utf8Bytes: Uint8Array): Base64String => encodeBase64(utf8Bytes)

export const sleep = async (duration: number): Promise<void> => {
  await new Promise((resolve) => {
    setTimeoutRef(resolve, duration)
  })
}
