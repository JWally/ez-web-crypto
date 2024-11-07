// hmac.ts
import { initializeCrypto } from './init'
import { HexString } from './types'

export const HMAC = async (secret: string, data: string): Promise<HexString> => {
  const { crypto } = await initializeCrypto()
  const encoder = new TextEncoder()
  const encodedSecret = encoder.encode(secret)
  const encodedData = encoder.encode(data)

  const key = await crypto.subtle.importKey('raw', encodedSecret, { name: 'HMAC', hash: { name: 'SHA-256' } }, false, [
    'sign',
    'verify',
  ])

  const sig = await crypto.subtle.sign('HMAC', key, encodedData)
  const b = new Uint8Array(sig)

  return Array.prototype.map.call(b, (x: number) => ('00' + x.toString(16)).slice(-2)).join('')
}
