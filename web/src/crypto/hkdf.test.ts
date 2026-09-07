import { beforeAll, describe, expect, it } from 'vitest'
import { ensureTestCrypto } from './test-env'
import fixtures from './vectors/index.json'
import { hkdfBits, hkdfSaltBytes } from './keyHierarchy'

beforeAll(() => {
  ensureTestCrypto()
})

function hex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('')
}

describe('hkdfBits — RFC 5869 official fixtures (SHA-256)', () => {
  const cases = fixtures['hkdf-rfc5869']

  for (const c of cases) {
    it(c.name, () => {
      const okm = hkdfBits(
        Uint8Array.from(c.ikm.match(/.{2}/g)?.map((h) => parseInt(h, 16)) ?? []),
        Uint8Array.from(c.salt.match(/.{2}/g)?.map((h) => parseInt(h, 16)) ?? []),
        Uint8Array.from(c.info.match(/.{2}/g)?.map((h) => parseInt(h, 16)) ?? []),
        c.L * 8,
      )
      expect(hex(okm)).toBe(c.okm)
    })
  }

  it('rejects invalid bit lengths', () => {
    expect(() => hkdfBits(new Uint8Array(32), new Uint8Array(0), new Uint8Array(0), 0)).toThrow(
      /invalid bit length/,
    )
    expect(() => hkdfBits(new Uint8Array(32), new Uint8Array(0), new Uint8Array(0), 7)).toThrow(
      /invalid bit length/,
    )
  })

  it('the D1 salt label is "fincrypt/v1/hkdf"', () => {
    expect(new TextDecoder().decode(hkdfSaltBytes())).toBe('fincrypt/v1/hkdf')
  })
})
