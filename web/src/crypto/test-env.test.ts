/**
 * Test environment bridge verification (C1.0).
 * Runs FIRST (imported by every suite via the bridge) — asserts the
 * crypto implementation in use is the platform one (Node webcrypto in
 * tests, native in browsers), never a polyfill.
 */
import { beforeAll, describe, expect, it } from 'vitest'
import { ensureTestCrypto, getSubtle } from './test-env'

beforeAll(() => {
  ensureTestCrypto()
})

describe('test-env bridge', () => {
  it('has a working SubtleCrypto after the bridge', () => {
    const subtle = getSubtle()
    expect(subtle).toBeDefined()
  })

  it('getRandomValues produces distinct random bytes', () => {
    const a = crypto.getRandomValues(new Uint8Array(32))
    const b = crypto.getRandomValues(new Uint8Array(32))
    expect([...a]).not.toEqual([...b])
  })

  it('AES-GCM roundtrips through the bridged subtle', async () => {
    const subtle = getSubtle()
    const key = await subtle.importKey(
      'raw',
      crypto.getRandomValues(new Uint8Array(32)),
      { name: 'AES-GCM' },
      false,
      ['encrypt', 'decrypt'],
    )
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const ct = await subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode('v1|u|transactions|r') },
      key,
      new TextEncoder().encode('bridge'),
    )
    const pt = await subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode('v1|u|transactions|r') },
      key,
      ct,
    )
    expect(new TextDecoder().decode(pt)).toBe('bridge')
  })
})