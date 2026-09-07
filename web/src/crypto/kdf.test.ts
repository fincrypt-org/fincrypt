import { describe, expect, it } from 'vitest'
import { DEFAULT_KDF_PARAMS, deriveKek, validateKdfParams } from './kdf'
import { deriveKekOffThread } from './kdfWorkerClient'

const enc = new TextEncoder()

// Vectors verified against Go x/crypto/argon2 (IDKey) and the RustCrypto
// reference KAT suite this session: hash-wasm's argon2id reproduces
// byte-identical tags on every no-secret vector probed. All vectors below
// are h=32 (hashLength=32) because deriveKek fixes the output at 32 bytes
// (Argon2's H' is not truncatable — a different tag length is a different
// tag, so only same-length vectors are comparable).
const GO_CROSSCHECKED_VECTORS: Array<{
  password: string
  salt: string
  t: number
  m: number
  p: number
  hash: string
}> = [
  // RustCrypto reference-suite Argon2id v0x13 vectors (no secret, no AD, h=32)
  {
    password: 'password',
    salt: 'somesalt',
    t: 2,
    m: 65536,
    p: 1,
    hash: '09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7',
  },
  {
    password: 'password',
    salt: 'diffsalt',
    t: 2,
    m: 65536,
    p: 1,
    hash: 'bdf32b05ccc42eb15d58fd19b1f856b113da1e9a5874fdcc544308565aa8141c',
  },
]

describe('kdf', () => {
  for (const vec of GO_CROSSCHECKED_VECTORS) {
    it(`matches the cross-checked Argon2id vector (${vec.password} m=${vec.m} t=${vec.t} p=${vec.p})`, async () => {
      const kek = await deriveKek(
        enc.encode(vec.password),
        enc.encode(vec.salt),
        { m: vec.m, t: vec.t, p: vec.p, version: 1 },
        { allowShortSaltForVectorTests: true },
      )
      const hex =
        typeof kek === 'string'
          ? kek
          : [...kek].map((b) => b.toString(16).padStart(2, '0')).join('')
      // deriveKek always outputs 32 bytes (hashLength=32). Vectors recorded at
      // other hash lengths (e.g. the Go x/crypto h=24 vector) tag differently —
      // Argon2's H' is not truncatable — so only h=32 vectors are comparable.
      expect(hex.length).toBe(64)
      expect(hex).toBe(vec.hash)
    })
  }

  it('derives a 32-byte KEK with default params', async () => {
    const kek = await deriveKek(
      enc.encode('correct horse battery staple'),
      enc.encode('a'.repeat(16) + 'b'.repeat(16)),
    )
    expect(kek).toBeInstanceOf(Uint8Array)
    expect(kek.length).toBe(32)
  })

  it('is deterministic for identical inputs', async () => {
    const a = await deriveKek(enc.encode('pw'), enc.encode('0123456789abcdef'))
    const b = await deriveKek(enc.encode('pw'), enc.encode('0123456789abcdef'))
    expect([...a]).toEqual([...b])
  })

  it('differs for different salts (same password)', async () => {
    const a = await deriveKek(enc.encode('pw'), enc.encode('0123456789abcdef'))
    const b = await deriveKek(enc.encode('pw'), enc.encode('fedcba9876543210'))
    expect([...a]).not.toEqual([...b])
  })

  it('differs for different passwords (same salt)', async () => {
    const a = await deriveKek(enc.encode('pw1'), enc.encode('0123456789abcdef'))
    const b = await deriveKek(enc.encode('pw2'), enc.encode('0123456789abcdef'))
    expect([...a]).not.toEqual([...b])
  })

  it('rejects short salts', async () => {
    await expect(deriveKek(enc.encode('pw'), enc.encode('short'))).rejects.toThrow(/16 bytes/)
  })

  it('rejects invalid params', () => {
    expect(() => validateKdfParams({ m: 4, t: 3, p: 4 })).toThrow(/invalid KdfParams/)
    expect(() => validateKdfParams({ m: 65536, t: 0, p: 4 })).toThrow(/invalid KdfParams/)
    expect(() => validateKdfParams(null)).toThrow(/invalid KdfParams/)
    expect(validateKdfParams(DEFAULT_KDF_PARAMS)).toEqual(DEFAULT_KDF_PARAMS)
  })
})

describe('kdfWorkerClient', () => {
  it('derives the same KEK as direct derivation (worker or fallback)', async () => {
    const direct = await deriveKek(enc.encode('pw-123'), enc.encode('0123456789abcdef'))
    const { kek, offThread } = await deriveKekOffThread(
      enc.encode('pw-123'),
      enc.encode('0123456789abcdef'),
    )
    expect([...kek]).toEqual([...direct])
    // happy-dom may or may not provide a functional Worker; either path must agree.
    expect(typeof offThread).toBe('boolean')
  })

  it('propagates validation errors', async () => {
    await expect(deriveKekOffThread(enc.encode('pw'), enc.encode('short'))).rejects.toThrow(
      /16 bytes/,
    )
  })
})
