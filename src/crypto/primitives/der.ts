/**
 * Just enough ASN.1/DER to read and write the two key containers WebCrypto uses for
 * P-256: SubjectPublicKeyInfo (RFC 5280) and PKCS#8 PrivateKeyInfo (RFC 5208), whose
 * payload is an SEC1 ECPrivateKey (RFC 5915).
 *
 * Real parsing, not fixed offsets: these bytes come from other implementations, and the
 * public-key BIT STRING in a PKCS#8 is optional, so a hard-coded layout would be brittle.
 *
 * ECDH and ECDSA keys are byte-identical here -- both are id-ecPublicKey/prime256v1. The
 * algorithm a key is *for* lives on the key object, not in its encoding.
 */

import { U8 } from './intrinsics'
import { concat } from './sha'

/* eslint-disable no-bitwise */

const SEQUENCE = 0x30
const INTEGER = 0x02
const BIT_STRING = 0x03
const OCTET_STRING = 0x04
const OID = 0x06
const CONTEXT_1 = 0xa1

const OID_EC_PUBLIC_KEY = new U8([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]) // 1.2.840.10045.2.1
const OID_PRIME256V1 = new U8([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]) // 1.2.840.10045.3.1.7

const POINT_LENGTH = 65
const SCALAR_LENGTH = 32

export class DerError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'DerError'
  }
}

// --- Reading --------------------------------------------------------------------

interface Element {
  tag: number
  contents: Uint8Array
  /** Offset just past this element, for walking siblings. */
  end: number
}

const readElement = (bytes: Uint8Array, offset: number): Element => {
  if (offset + 2 > bytes.length) {
    throw new DerError('Truncated DER element')
  }

  const tag = bytes[offset]
  const first = bytes[offset + 1]

  let length: number
  let contentStart: number

  if (first < 0x80) {
    length = first
    contentStart = offset + 2
  } else {
    const lengthBytes = first & 0x7f
    if (lengthBytes === 0 || lengthBytes > 4) {
      throw new DerError('Unsupported DER length encoding')
    }
    if (offset + 2 + lengthBytes > bytes.length) {
      throw new DerError('Truncated DER length')
    }

    length = 0
    for (let i = 0; i < lengthBytes; i += 1) {
      length = length * 256 + bytes[offset + 2 + i]
    }
    contentStart = offset + 2 + lengthBytes
  }

  const contentEnd = contentStart + length
  if (contentEnd > bytes.length) {
    throw new DerError('DER element runs past the end of the buffer')
  }

  return { tag, contents: bytes.subarray(contentStart, contentEnd), end: contentEnd }
}

const expect = (bytes: Uint8Array, offset: number, tag: number): Element => {
  const element = readElement(bytes, offset)
  if (element.tag !== tag) {
    throw new DerError(`Expected DER tag 0x${tag.toString(16)}, got 0x${element.tag.toString(16)}`)
  }
  return element
}

const bytesEqual = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) {
    return false
  }
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) {
      return false
    }
  }
  return true
}

/** AlgorithmIdentifier ::= SEQUENCE { id-ecPublicKey, prime256v1 } */
const checkAlgorithmIdentifier = (element: Element): void => {
  const algorithmOid = expect(element.contents, 0, OID)
  if (!bytesEqual(algorithmOid.contents, OID_EC_PUBLIC_KEY)) {
    throw new DerError('Not an EC public key (unexpected algorithm OID)')
  }

  const curveOid = expect(element.contents, algorithmOid.end, OID)
  if (!bytesEqual(curveOid.contents, OID_PRIME256V1)) {
    throw new DerError('Not a P-256 key (unexpected curve OID)')
  }
}

/** Strips the BIT STRING's unused-bits octet, which is always 0 for a key. */
const bitStringContents = (element: Element): Uint8Array => {
  if (element.contents.length < 1 || element.contents[0] !== 0x00) {
    throw new DerError('Unexpected BIT STRING padding')
  }
  return element.contents.subarray(1)
}

const checkPoint = (point: Uint8Array): Uint8Array => {
  if (point.length !== POINT_LENGTH || point[0] !== 0x04) {
    throw new DerError('Expected an uncompressed P-256 point')
  }
  return point
}

/** SubjectPublicKeyInfo -> the uncompressed point (0x04 || X || Y). */
export const parseSpki = (bytes: Uint8Array): Uint8Array => {
  const root = expect(bytes, 0, SEQUENCE)

  const algorithm = expect(root.contents, 0, SEQUENCE)
  checkAlgorithmIdentifier(algorithm)

  const subjectPublicKey = expect(root.contents, algorithm.end, BIT_STRING)
  return checkPoint(bitStringContents(subjectPublicKey))
}

/** PKCS#8 PrivateKeyInfo -> the 32-byte private scalar. */
export const parsePkcs8 = (bytes: Uint8Array): Uint8Array => {
  const root = expect(bytes, 0, SEQUENCE)

  const version = expect(root.contents, 0, INTEGER)
  const algorithm = expect(root.contents, version.end, SEQUENCE)
  checkAlgorithmIdentifier(algorithm)

  const privateKeyOctets = expect(root.contents, algorithm.end, OCTET_STRING)

  // The OCTET STRING wraps an SEC1 ECPrivateKey.
  const ecPrivateKey = expect(privateKeyOctets.contents, 0, SEQUENCE)
  const ecVersion = expect(ecPrivateKey.contents, 0, INTEGER)
  const scalar = expect(ecPrivateKey.contents, ecVersion.end, OCTET_STRING)

  if (scalar.contents.length !== SCALAR_LENGTH) {
    throw new DerError('Expected a 32-byte P-256 private scalar')
  }

  return scalar.contents.slice()
}

// --- Writing --------------------------------------------------------------------

const encodeLength = (length: number): Uint8Array => {
  if (length < 0x80) {
    return new U8([length])
  }
  if (length < 0x100) {
    return new U8([0x81, length])
  }
  if (length < 0x10000) {
    return new U8([0x82, (length >>> 8) & 0xff, length & 0xff])
  }
  throw new DerError('DER length too large')
}

const encodeElement = (tag: number, contents: Uint8Array): Uint8Array =>
  concat(new U8([tag]), encodeLength(contents.length), contents)

const encodeAlgorithmIdentifier = (): Uint8Array =>
  encodeElement(SEQUENCE, concat(encodeElement(OID, OID_EC_PUBLIC_KEY), encodeElement(OID, OID_PRIME256V1)))

const encodeBitString = (contents: Uint8Array): Uint8Array =>
  encodeElement(BIT_STRING, concat(new U8([0x00]), contents))

export const encodeSpki = (publicKey: Uint8Array): Uint8Array => {
  checkPoint(publicKey)

  return encodeElement(SEQUENCE, concat(encodeAlgorithmIdentifier(), encodeBitString(publicKey)))
}

export const encodePkcs8 = (privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array => {
  if (privateKey.length !== SCALAR_LENGTH) {
    throw new DerError('Expected a 32-byte P-256 private scalar')
  }
  checkPoint(publicKey)

  // ECPrivateKey ::= SEQUENCE { version 1, privateKey OCTET STRING, [1] publicKey BIT STRING }
  const ecPrivateKey = encodeElement(
    SEQUENCE,
    concat(
      encodeElement(INTEGER, new U8([0x01])),
      encodeElement(OCTET_STRING, privateKey),
      encodeElement(CONTEXT_1, encodeBitString(publicKey))
    )
  )

  return encodeElement(
    SEQUENCE,
    concat(
      encodeElement(INTEGER, new U8([0x00])), // version 0
      encodeAlgorithmIdentifier(),
      encodeElement(OCTET_STRING, ecPrivateKey)
    )
  )
}
