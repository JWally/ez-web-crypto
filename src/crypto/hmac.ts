// hmac.ts
import { hmac } from './primitives/hmac'
import { encodeUtf8 } from './primitives/utf8'
import { HexString } from './types'

const HEX = '0123456789abcdef'

export const HMAC = async (secret: string, data: string): Promise<HexString> => {
  const signature = hmac('SHA-256', encodeUtf8(secret), encodeUtf8(data))

  let out = ''
  for (let i = 0; i < signature.length; i += 1) {
    /* eslint-disable no-bitwise */
    out += HEX[signature[i] >>> 4] + HEX[signature[i] & 0x0f]
  }

  return out
}
