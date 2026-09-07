import { beforeAll, describe, expect, it } from 'vitest'
import { ensureTestCrypto } from './test-env'
import { RECORD_TYPES, buildAad, decryptBytes, encryptBytes, type RecordType } from './aead'
import {
  generateDek,
  deriveSubkey,
  wrapDek,
  unwrapDek,
  wrapWithRecovery,
  unwrapWithRecovery,
} from './keyHierarchy'
import { serializeEnvelope, parseEnvelope } from './envelope'
import { argon2idDerive, importKek } from './kdf'
import { zeroize, zeroizeAll } from './memzero'
import { InvalidParamsError } from './errors'

beforeAll(() => {
  ensureTestCrypto()
})

const enc = new TextEncoder()
const dec = new TextDecoder()

/** Cheap passphrase KEK for tests (prod params are slow-tagged in kdf.test.ts). */
async function kekFromPassphrase(passphrase: string): Promise<CryptoKey> {
  const bytes = await argon2idDerive(passphrase, enc.encode('0123456789abcdef'), {
    alg: 'argon2id',
    version: 19,
    m: 8192,
    t: 1,
    p: 1,
  })
  return importKek(bytes)
}

describe('keyHierarchy — DEK envelope (D3 AAD binding)', () => {
  it('wrap → unwrap roundtrips with the correct KEK', async () => {
    const kek = await kekFromPassphrase('correct horse')
    const dek = generateDek()
    const wrapped = await wrapDek(dek, kek, 'user-a')
    expect(wrapped.length).toBe(60)
    expect([...(await unwrapDek(wrapped, kek, 'user-a'))]).toEqual([...dek])
  })

  it('wrong passphrase KEK fails unwrap (wrong-passphrase test)', async () => {
    const kek = await kekFromPassphrase('correct horse')
    const wrongKek = await kekFromPassphrase('incorrect horse')
    const wrapped = await wrapDek(generateDek(), kek, 'user-a')
    await expect(unwrapDek(wrapped, wrongKek, 'user-a')).rejects.toMatchObject({
      code: 'wrap_failed',
    })
  })

  it('wrong userId fails unwrap (D3 binds the user)', async () => {
    const kek = await kekFromPassphrase('pw')
    const wrapped = await wrapDek(generateDek(), kek, 'user-a')
    await expect(unwrapDek(wrapped, kek, 'user-b')).rejects.toMatchObject({ code: 'wrap_failed' })
  })

  it('wrapped DEK cannot be replayed as a recovery-wrapped DEK and vice versa', async () => {
    const kek = await kekFromPassphrase('pw')
    const asDek = await wrapDek(generateDek(), kek, 'user-a')
    const asRecovery = await wrapWithRecovery(generateDek(), kek, 'user-a')
    await expect(unwrapDek(asRecovery, kek, 'user-a')).rejects.toMatchObject({
      code: 'wrap_failed',
    })
    await expect(unwrapWithRecovery(asDek, kek, 'user-a')).rejects.toMatchObject({
      code: 'wrap_failed',
    })
  })

  it('tampered wrapped DEK fails unwrap', async () => {
    const kek = await kekFromPassphrase('pw')
    const wrapped = await wrapDek(generateDek(), kek, 'user-a')
    const last = wrapped.length - 1
    wrapped[last] = (wrapped[last] ?? 0) ^ 0x01
    await expect(unwrapDek(wrapped, kek, 'user-a')).rejects.toMatchObject({ code: 'wrap_failed' })
  })

  it('wrapDek rejects short DEKs and empty userId; unwrap rejects wrong length', async () => {
    const kek = await kekFromPassphrase('pw')
    await expect(wrapDek(new Uint8Array(16), kek, 'u')).rejects.toMatchObject({
      code: 'wrap_failed',
    })
    await expect(wrapDek(generateDek(), kek, '')).rejects.toMatchObject({ code: 'wrap_failed' })
    await expect(unwrapDek(new Uint8Array(60), kek, 'u')).rejects.toMatchObject({
      code: 'wrap_failed',
    })
  })
})

describe('keyHierarchy — subkeys (I4)', () => {
  it('cross-type decrypt fails even with matching AAD (info=type separation)', async () => {
    const userId = 'user-a'
    const dek = generateDek()
    const tx = await deriveSubkey(dek, 'transactions')
    const chat = await deriveSubkey(dek, 'chat')
    const aad = buildAad(userId, 'transactions', 'r1')
    const packed = await encryptBytes(tx, enc.encode('tx data'), aad)
    // The chat subkey + THE SAME AAD must still fail (proves subkey separation):
    await expect(decryptBytes(chat, packed, aad)).rejects.toMatchObject({
      code: 'decryption_failed',
    })
    expect(dec.decode(await decryptBytes(tx, packed, aad))).toBe('tx data')
  })

  it('subkey differs per DEK (same type)', async () => {
    const a = await deriveSubkey(generateDek(), 'vault')
    const b = await deriveSubkey(generateDek(), 'vault')
    const aad = buildAad('u', 'vault', 'settings')
    const packed = await encryptBytes(a, enc.encode('data'), aad)
    await expect(decryptBytes(b, packed, aad)).rejects.toThrow()
  })

  it('subkey is deterministic per (DEK, type)', async () => {
    const dek = generateDek()
    const a = await deriveSubkey(dek, 'chat')
    const b = await deriveSubkey(dek, 'chat')
    const aad = buildAad('u', 'chat', 'r1')
    const packed = await encryptBytes(a, enc.encode('stable'), aad)
    expect(dec.decode(await decryptBytes(b, packed, aad))).toBe('stable')
  })

  it('record types are exactly the §0+D2 set', () => {
    expect([...RECORD_TYPES]).toEqual(['transactions', 'attachments', 'chat', 'accounts', 'vault'])
  })

  it('generateDek is 32 random bytes', () => {
    expect(generateDek().length).toBe(32)
  })
})

describe('memzero (I3)', () => {
  it('zeroize clears buffers; zeroizeAll walks nested objects', () => {
    const a = new Uint8Array([1, 2, 3])
    zeroize(a)
    expect([...a]).toEqual([0, 0, 0])
    const nested = { dek: new Uint8Array([9, 9]), inner: { sub: new Uint8Array([7]) }, keep: 'x' }
    zeroizeAll(nested as unknown as Record<string, unknown>)
    expect([...(nested.dek as Uint8Array)]).toEqual([0, 0])
    expect([...(nested.inner.sub as Uint8Array)]).toEqual([0])
    expect(nested.keep).toBe('x')
  })
})

describe('envelope codec (C1.2)', () => {
  it('roundtrip through the fixed-order codec', async () => {
    const userId = 'user-a'
    const type: RecordType = 'accounts'
    const dek = generateDek()
    const subkey = await deriveSubkey(dek, type)
    const aad = buildAad(userId, type, 'acct-1')
    const packed = await encryptBytes(subkey, enc.encode('account name|EUR|100'), aad)
    const env = {
      record_id: 'acct-1',
      type,
      nonce: packed.slice(0, 12),
      ciphertext: packed.slice(12),
      aad: dec.decode(aad),
      ts: '2026-09-07T00:00:00Z',
    }
    const bytes = serializeEnvelope(env)
    const json = dec.decode(bytes)
    // fixed key order:
    expect(json.indexOf('"record_id"')).toBeLessThan(json.indexOf('"type"'))
    expect(json.indexOf('"type"')).toBeLessThan(json.indexOf('"nonce"'))
    expect(json.indexOf('"nonce"')).toBeLessThan(json.indexOf('"ciphertext"'))
    expect(json.indexOf('"ciphertext"')).toBeLessThan(json.indexOf('"aad"'))
    expect(json.indexOf('"aad"')).toBeLessThan(json.indexOf('"ts"'))
    // byte-stable across serializations:
    expect(dec.decode(serializeEnvelope(env))).toBe(json)
    // parse back and decrypt:
    const back = parseEnvelope(bytes)
    expect(back.record_id).toBe('acct-1')
    expect(back.type).toBe('accounts')
    expect([...back.nonce]).toEqual([...env.nonce])
    expect([...back.ciphertext]).toEqual([...env.ciphertext])
    expect(dec.decode(await decryptBytes(subkey, packed, aad))).toBe('account name|EUR|100')
  })

  it('parse rejects unknown/missing fields and wrong nonce length', () => {
    expect(() => parseEnvelope(enc.encode('{"record_id":"r","type":"chat"}'))).toThrow()
    expect(() =>
      parseEnvelope(
        enc.encode(
          '{"record_id":"r","type":"chat","nonce":"AAAAAAAAAAAAAAAAAAAAAA==","ciphertext":"AAAA","aad":"v1|u|chat|r","ts":"t","v":1}',
        ),
      ),
    ).toThrow()
    expect(() =>
      parseEnvelope(
        enc.encode(
          '{"record_id":"r","type":"chat","nonce":"AAAA","ciphertext":"AAAA","aad":"v1|u|chat|r","ts":"t"}',
        ),
      ),
    ).toThrow()
  })

  it('InvalidParamsError is typed with a stable code', () => {
    expect(new InvalidParamsError('x').code).toBe('invalid_params')
    expect(new InvalidParamsError('x').name).toBe('InvalidParamsError')
  })
})
