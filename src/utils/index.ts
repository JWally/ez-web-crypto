import type { Base64String } from '@/types/crypto'
export const base64ToArray = (strng: Base64String): Uint8Array => {
  return Uint8Array.from(atob(strng), (c) => c.charCodeAt(0))
}

export const arrayToBase64 = (utf8Bytes: Uint8Array): Base64String => {
  const chunkSize = 8192
  const chunks: string[] = []

  for (let i = 0; i < utf8Bytes.length; i += chunkSize) {
    const chunk = utf8Bytes.subarray(i, i + chunkSize)
    chunks.push(String.fromCharCode.apply(null, [...chunk]))
  }

  return btoa(chunks.join(''))
}

export const sleep = async (duration: number): Promise<void> => {
  await new Promise((resolve) => setTimeout(resolve, duration))
}
