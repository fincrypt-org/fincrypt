import { describe, expect, it } from 'vitest'
import { buildAad, decrypt, encrypt, importAesKey } from './aead'

const enc = new TextEncoder()
const dec = new TextDecoder()

// NIST AES-256-GCM test case 14 (key/IV/plaintext/AAD from
// GCM Spec test case 14, 256-bit key): plaintext empty, 16-byte tag.
// WebCrypto appends the tag to the ciphertext, so a zero-length
// plaintext yields exactly 16 bytes (tag) after the 12-byte nonce.
const NIST_KEY = new Uint8Array([
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
])
// Non-zero key vector (test case 16 from the GCM spec, 256-bit key):
// key = 00..e9? Use published: key feffe9928665731c6d6a8f94677244d8 (128-bit) is another case.
// For 256-bit, GCM spec case: key feffe9928665731c6e655875502942d7326a4d0a4f4e0a15...
// To stay verifiable, we use the well-known 128-bit key vector semantics
// only for structure checks and rely on WebCrypto for actual crypto.

describe('aead', () => {
  it('roundtrips plaintext with AAD', async () => {
    const key = await importAesKey(NIST_KEY)
    const aad = buildAad('u-123', 'transactions', 't-456')
    const packed = await encrypt(key, enc.encode('hello'), aad)
    expect(packed.length).toBe(12 + 5 + 16) // nonce + plaintext + 16-byte tag
    const pt = await decrypt(key, packed, aad)
    expect(dec.decode(pt)).toBe('hello')
  })

  it('rejects empty AAD on encrypt and decrypt', async () => {
    const key = await importAesKey(NIST_KEY)
    await expect(encrypt(key, enc.encode('x'), '')).rejects.toThrow(/mandatory/)
    await expect(decrypt(key, new Uint8Array(29), '')).rejects.toThrow(/mandatory/)
  })

  it('fails decryption with wrong AAD (different user)', async () => {
    const key = await importAesKey(NIST_KEY)
    const packed = await encrypt(
      key,
      enc.encode('secret'),
      buildAad('user-a', 'transactions', 'r1'),
    )
    await expect(decrypt(key, packed, buildAad('user-b', 'transactions', 'r1'))).rejects.toThrow()
  })

  it('fails decryption when ciphertexts are swapped between records (AAD-swap test)', async () => {
    const key = await importAesKey(NIST_KEY)
    // Record 1 and record 2, same key, same user — only record_id differs in AAD.
    const packed1 = await encrypt(
      key,
      enc.encode('record-one-data'),
      buildAad('user-a', 'transactions', 'r1'),
    )
    const packed2 = await encrypt(
      key,
      enc.encode('record-two-data'),
      buildAad('user-a', 'transactions', 'r2'),
    )

    // Server (or a tamperer) swaps the blobs — decryption must fail for both.
    await expect(decrypt(key, packed2, buildAad('user-a', 'transactions', 'r1'))).rejects.toThrow()
    await expect(decrypt(key, packed1, buildAad('user-a', 'transactions', 'r2'))).rejects.toThrow()

    // The originals still decrypt under their own AAD.
    expect(dec.decode(await decrypt(key, packed1, buildAad('user-a', 'transactions', 'r1')))).toBe(
      'record-one-data',
    )
  })

  it('fails decryption when record type differs', async () => {
    const key = await importAesKey(NIST_KEY)
    const packed = await encrypt(key, enc.encode('data'), buildAad('user-a', 'transactions', 'r1'))
    await expect(decrypt(key, packed, buildAad('user-a', 'chat', 'r1'))).rejects.toThrow()
  })

  it('fails decryption on tampered ciphertext', async () => {
    const key = await importAesKey(NIST_KEY)
    const packed = await encrypt(key, enc.encode('data'), buildAad('user-a', 'transactions', 'r1'))
    const last = packed.length - 1
    packed[last] = (packed[last] ?? 0) ^ 0x01
    await expect(decrypt(key, packed, buildAad('user-a', 'transactions', 'r1'))).rejects.toThrow()
  })

  it('wrong key fails decryption (wrong passphrase path)', async () => {
    const keyA = await importAesKey(NIST_KEY)
    const otherKeyBytes = new Uint8Array(32)
    otherKeyBytes.fill(0x42)
    const keyB = await importAesKey(otherKeyBytes)
    const packed = await encrypt(keyA, enc.encode('data'), buildAad('user-a', 'transactions', 'r1'))
    await expect(decrypt(keyB, packed, buildAad('user-a', 'transactions', 'r1'))).rejects.toThrow()
  })

  it('rejects truncated packed blobs', async () => {
    const key = await importAesKey(NIST_KEY)
    await expect(
      decrypt(key, new Uint8Array(12), buildAad('u', 'transactions', 'r')),
    ).rejects.toThrow(/too short/)
  })

  it('AAD builder rejects malformed components', () => {
    expect(() => buildAad('', 'transactions', 'r')).toThrow(/invalid AAD component/)
    expect(() => buildAad('u|weird', 'transactions', 'r')).toThrow(/invalid AAD component/)
    expect(() => buildAad('u', 'transactions', '')).toThrow(/invalid AAD component/)
    // @ts-expect-error — runtime guard for types not in RECORD_TYPES
    expect(() => buildAad('u', 'bogus-type', 'r')).toThrow(/unknown record type/)
    expect(buildAad('u', 'vault', 'settings')).toBe('v1|u|vault|settings')
  })

  it('nonce uniqueness: 1000 encryptions of the same plaintext never reuse a nonce', async () => {
    const key = await importAesKey(NIST_KEY)
    const aad = buildAad('user-a', 'transactions', 'r1')
    const nonces = new Set<string>()
    for (let i = 0; i < 1000; i++) {
      const packed = await encrypt(key, enc.encode('same plaintext'), aad)
      const nonceHex = [...packed.slice(0, 12)].map((b) => b.toString(16).padStart(2, '0')).join('')
      expect(nonces.has(nonceHex)).toBe(false) // fresh 12-byte nonce per write
      nonces.add(nonceHex)
      // ciphertexts must also differ (nonce-dependent)
    }
    expect(nonces.size).toBe(1000)
  })

  it('AES-GCM NIST vector (256-bit key, zero IV, 16-byte zero plaintext)', async () => {
    // GCM spec Appendix B, AES-256 Test Case 2: key=0^32, IV=0^12,
    // PT=0^16, no AAD → CT||tag = cea7403d4d606b6e074ec5d3baf39d18
    //                        d0d1c8a799996bf0265b98b5d48ab919.
    // Raw WebCrypto with empty AAD (the mandatory-AAD rule applies to the
    // envelope API, not to this direct vector check).
    const key = await importAesKey(NIST_KEY)
    const iv = new Uint8Array(12) // all zero
    const ct = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: new Uint8Array(0), tagLength: 128 },
        key,
        new Uint8Array(16),
      ),
    )
    const hex = [...ct].map((b) => b.toString(16).padStart(2, '0')).join('')
    expect(hex).toBe('cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919')
  })

  it('importAesKey rejects non-32-byte keys', async () => {
    await expect(importAesKey(new Uint8Array(16))).rejects.toThrow(/32 bytes/)
  })
})
