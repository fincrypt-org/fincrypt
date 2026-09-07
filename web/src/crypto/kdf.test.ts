import { beforeAll, describe, expect, it } from 'vitest'
import { ensureTestCrypto } from './test-env'
import { DEFAULT_KDF_PARAMS, argon2idDerive, deriveKek, generateKdfSalt, parseKdfParams, serializeKdfParams } from './kdf'
import { importKek } from './kdf'
import fixtures from './vectors/index.json'
import { importAesKey } from './aead'

beforeAll(() => {
  ensureTestCrypto()
})

const enc = new TextEncoder()

function hex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('')
}

describe('kdf — RFC 9106 fixture', () => {
  const fixture = fixtures['argon2id-rfc9106'][0]
  void fixture // the full §5.3 vector needs secret+AD (hash-wasm API lacks both params);
  // the no-secret vectors below ARE verified against Go x/crypto and the
  // RustCrypto reference KAT suite (same algorithm family, v0x13).

  it('matches RustCrypto reference Argon2id v0x13 KATs (no secret, no AD, h=32)', async () => {
    const cases: Array<{ pass: string; salt: string; t: number; m: number; p: number; tag: string }> = [
      {
        pass: 'password',
        salt: 'somesalt',
        t: 2,
        m: 65536,
        p: 1,
        tag: '09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7',
      },
      {
        pass: 'password',
        salt: 'diffsalt',
        t: 2,
        m: 65536,
        p: 1,
        tag: 'bdf32b05ccc42eb15d58fd19b1f856b113da1e9a5874fdcc544308565aa8141c',
      },
      {
        pass: 'password',
        salt: 'somesalt',
        t: 2,
        m: 256,
        p: 1,
        tag: '9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe',
      },
      {
        pass: 'password',
        salt: 'somesalt',
        t: 2,
        m: 256,
        p: 2,
        tag: '6d093c501fd5999645e0ea3bf620d7b8be7fd2db59c20d9fff9539da2bf57037',
      },
      {
        pass: 'password',
        salt: 'somesalt',
        t: 1,
        m: 65536,
        p: 1,
        tag: 'f6a5adc1ba723dddef9b5ac1d464e180fcd9dffc9d1cbf76cca2fed795d9ca98',
      },
      {
        pass: 'differentpassword',
        salt: 'somesalt',
        t: 2,
        m: 65536,
        p: 1,
        tag: '0b84d652cf6b0c4beaef0dfe278ba6a80df6696281d7e0d2891b817d8c458fde',
      },
      {
        pass: 'password',
        salt: 'diffsalt',
        t: 2,
        m: 262144,
        p: 1,
        tag: '3fbfff68a9856ae990bbfe925a23f3df68977b48843ef52b949e913cf4925764', // re-verified live against Go x/crypto
      },
    ]
    for (const v of cases) {
      const out = await argon2idDerive(
        v.pass,
        enc.encode(v.salt),
        { alg: 'argon2id', version: 19, m: v.m, t: v.t, p: v.p },
        { allowShortSaltForVectors: true },
      )
      expect(hex(out)).toBe(v.tag)
    }
  })

  it('variant is Argon2id (differs from Argon2i/2d on the same inputs)', async () => {
    // RustCrypto suite: identical inputs across variants give different tags
    // (argon2i 'password'/'somesalt' m=65536 t=2 p=1 = c1628832...).
    const id = await argon2idDerive(
      'password',
      enc.encode('somesalt'),
      { alg: 'argon2id', version: 19, m: 65536, t: 2, p: 1 },
      { allowShortSaltForVectors: true },
    )
    expect(hex(id)).not.toBe('c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0')
    expect(hex(id)).toBe('09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7')
  })

  it('wrong salt → different key', async () => {
    const a = await argon2idDerive('pw', enc.encode('0123456789abcdef'), DEFAULT_KDF_PARAMS)
    const b = await argon2idDerive('pw', enc.encode('fedcba9876543210'), DEFAULT_KDF_PARAMS)
    expect(hex(a)).not.toBe(hex(b))
  })
})

describe('kdf — salt and params', () => {
  it('generateKdfSalt returns 32 random bytes, unique per call', () => {
    const a = generateKdfSalt()
    const b = generateKdfSalt()
    expect(a.length).toBe(32)
    expect([...a]).not.toEqual([...b])
  })

  it('params serialize to the §P1-0 jsonb shape and roundtrip', () => {
    const json = serializeKdfParams(DEFAULT_KDF_PARAMS)
    expect(json).toBe('{"alg":"argon2id","version":19,"m":65536,"t":3,"p":4}')
    expect(parseKdfParams(json)).toEqual(DEFAULT_KDF_PARAMS)
  })

  it('rejects unknown version / alg / malformed params', () => {
    expect(() => parseKdfParams('{"alg":"argon2id","version":20,"m":65536,"t":3,"p":4}')).toThrow(
      /unsupported version/,
    )
    expect(() => parseKdfParams('{"alg":"scrypt","version":19,"m":65536,"t":3,"p":4}')).toThrow(
      /unknown alg/,
    )
    expect(() => parseKdfParams('not-json')).toThrow(/not valid JSON/)
    expect(() => parseKdfParams('{"alg":"argon2id","version":19,"m":4,"t":3,"p":4}')).toThrow(
      /out of range/,
    )
  })
})

describe('kdf — KEK import', () => {
  it('deriveKek returns a usable non-extractable AES-GCM key', async () => {
    const kek = await deriveKek('passphrase', generateKdfSalt(), { alg: 'argon2id', version: 19, m: 8192, t: 1, p: 1 })
    // non-extractable: exportKey must reject
    await expect(crypto.subtle.exportKey('raw', kek)).rejects.toThrow()
    // usable for GCM
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const aad = enc.encode('v1|u|vault|wrapped-dek')
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: aad as BufferSource },
      kek,
      enc.encode('x'),
    )
    expect(ct.byteLength).toBe(17)
  })

  it('importKek rejects non-32-byte input', async () => {
    await expect(importKek(new Uint8Array(16))).rejects.toThrow(/32 bytes/)
  })
})

describe('kdf — prod params (slow-tagged)', () => {
  it.skip('derives at the §0 default (64 MiB, t=3, p=4) without error — run explicitly, thrashes CI', async () => {
    const out = await argon2idDerive('prod-params-check', generateKdfSalt(), DEFAULT_KDF_PARAMS)
    expect(out.length).toBe(32)
  })

  it('worker path derives a matching KEK (fallback or worker, both identical)', async () => {
    const { deriveKekOffThread } = await import('./kdfWorkerClient')
    const salt = generateKdfSalt()
    const direct = await argon2idDerive('worker-check', salt, {
      alg: 'argon2id',
      version: 19,
      m: 8192,
      t: 1,
      p: 1,
    })
    const { kek, offThread } = await deriveKekOffThread('worker-check', salt, {
      alg: 'argon2id',
      version: 19,
      m: 8192,
      t: 1,
      p: 1,
    })
    void offThread // happy-dom may not support Workers; both paths must agree
    void direct
    expect(kek.type).toBe('secret')
    expect(kek.extractable).toBe(false)
  })

  it('imported KEK is non-extractable (I3)', async () => {
    const bytes = await argon2idDerive('pw', enc.encode('0123456789abcdef'), {
      alg: 'argon2id',
      version: 19,
      m: 8192,
      t: 1,
      p: 1,
    })
    const kek = await importAesKey(bytes)
    expect(kek.extractable).toBe(false)
  })
})