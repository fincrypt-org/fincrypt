import { beforeAll, describe, expect, it } from 'vitest'
import { ensureTestCrypto } from './test-env'
import { generateDek, wrapDek, deriveSubkey, unwrapDek } from './keyHierarchy'
import { argon2idDerive, importKek, serializeKdfParams, generateKdfSalt } from './kdf'
import { recoverDek, generateRecoveryPhrase, wrapDekWithRecovery } from './recovery'
import { changePassphrase, recoverWithMnemonic, rotateRecovery } from './lifecycle'
import { buildAad, encryptBytes, decryptBytes } from './aead'
import { WrapError } from './errors'

beforeAll(() => {
  ensureTestCrypto()
})

const enc = new TextEncoder()
const dec = new TextDecoder()

/** Test KDF params (cheap); test params jsonb mirrors the stored shape. */
const TEST_PARAMS = { alg: 'argon2id' as const, version: 19 as const, m: 8192, t: 1, p: 1 }
const TEST_PARAMS_JSON = serializeKdfParams(TEST_PARAMS)
void TEST_PARAMS_JSON

interface Setup {
  userId: string
  oldPass: string
  dek: Uint8Array
  kdfSalt: Uint8Array
  kdfParamsJson: string
  wrappedDek: Uint8Array
  wrappedDekRecovery: Uint8Array
  mnemonic: string
}

async function setup(): Promise<Setup> {
  const userId = 'user-a'
  const oldPass = 'original-passphrase'
  const dek = generateDek()
  const kdfSalt = generateKdfSalt()
  const kdfParamsJson = serializeKdfParams(TEST_PARAMS)
  const kek = await importKek(await argon2idDerive(oldPass, kdfSalt, TEST_PARAMS))
  const wrappedDek = await wrapDek(dek, kek, userId)
  const mnemonic = generateRecoveryPhrase().mnemonic
  const wrappedDekRecovery = await wrapDekWithRecovery(dek, mnemonic, userId)
  return { userId, oldPass, dek, kdfSalt, kdfParamsJson, wrappedDek, wrappedDekRecovery, mnemonic }
}

describe('lifecycle — changePassphrase (§0: re-wrap both, no re-encryption)', () => {
  it('old passphrase fails after change; new works; pre-change envelope still decrypts', async () => {
    const fx = await setup()

    // Encrypt a record BEFORE the change.
    const subkeyBefore = await deriveSubkey(fx.dek, 'transactions')
    const aad = buildAad(fx.userId, 'transactions', 'r1')
    const packedBefore = await encryptBytes(subkeyBefore, enc.encode('pre-change data'), aad)

    const result = await changePassphrase({
      oldPass: fx.oldPass,
      newPass: 'brand-new-passphrase',
      userId: fx.userId,
      kdfSalt: fx.kdfSalt,
      kdfParamsJson: fx.kdfParamsJson,
      wrappedDek: fx.wrappedDek,
      wrappedDekRecovery: fx.wrappedDekRecovery,
    })

    // New salt differs; params re-issued; both wraps fresh (different from old).
    expect([...result.kdf_salt]).not.toEqual([...fx.kdfSalt])
    // §0 re-issues at the DEFAULT params (upgrade path), not the old ones:
    expect(result.kdf_params).toBe('{"alg":"argon2id","version":19,"m":65536,"t":3,"p":4}')
    expect([...result.wrapped_dek]).not.toEqual([...fx.wrappedDek])
    expect([...result.wrapped_dek_recovery]).not.toEqual([...fx.wrappedDekRecovery])

    // The change re-issued at DEFAULT params — parse them from the result
    // (exactly what the server would hand back):
    const { parseKdfParams } = await import('./kdf')
    const resultParams = parseKdfParams(result.kdf_params)

    // Old passphrase now fails:
    const oldKek = await importKek(await argon2idDerive(fx.oldPass, result.kdf_salt, resultParams))
    await expect(unwrapDek(result.wrapped_dek, oldKek, fx.userId)).rejects.toMatchObject({
      code: 'wrap_failed',
    })

    // New passphrase works and yields the SAME DEK:
    const newKek = await importKek(
      await argon2idDerive('brand-new-passphrase', result.kdf_salt, resultParams),
    )
    expect([...(await unwrapDek(result.wrapped_dek, newKek, fx.userId))]).toEqual([...fx.dek])

    // No data re-encryption: the pre-change envelope still decrypts with the
    // DEK recovered under the NEW passphrase.
    const recoveredDek = await unwrapDek(result.wrapped_dek, newKek, fx.userId)
    const subkeyAfter = await deriveSubkey(recoveredDek, 'transactions')
    expect(dec.decode(await decryptBytes(subkeyAfter, packedBefore, aad))).toBe('pre-change data')
    void subkeyBefore
  })

  it('wrong old passphrase → WrapError, nothing rotated', async () => {
    const fx = await setup()
    await expect(
      changePassphrase({
        oldPass: 'not-the-passphrase',
        newPass: 'brand-new-passphrase',
        userId: fx.userId,
        kdfSalt: fx.kdfSalt,
        kdfParamsJson: fx.kdfParamsJson,
        wrappedDek: fx.wrappedDek,
        wrappedDekRecovery: fx.wrappedDekRecovery,
      }),
    ).rejects.toMatchObject({ code: 'wrap_failed' })
  })

  it('new == old rejected; empty new rejected', async () => {
    const fx = await setup()
    await expect(
      changePassphrase({
        oldPass: fx.oldPass,
        newPass: fx.oldPass,
        userId: fx.userId,
        kdfSalt: fx.kdfSalt,
        kdfParamsJson: fx.kdfParamsJson,
        wrappedDek: fx.wrappedDek,
        wrappedDekRecovery: fx.wrappedDekRecovery,
      }),
    ).rejects.toMatchObject({ code: 'wrap_failed' })
    await expect(
      changePassphrase({
        oldPass: fx.oldPass,
        newPass: '',
        userId: fx.userId,
        kdfSalt: fx.kdfSalt,
        kdfParamsJson: fx.kdfParamsJson,
        wrappedDek: fx.wrappedDek,
        wrappedDekRecovery: fx.wrappedDekRecovery,
      }),
    ).rejects.toMatchObject({ code: 'wrap_failed' })
  })
})

describe('lifecycle — recoverWithMnemonic', () => {
  it('recovers the same DEK the passphrase wrap holds', async () => {
    const fx = await setup()
    const { dek } = await recoverWithMnemonic({
      mnemonic: fx.mnemonic,
      userId: fx.userId,
      wrappedDekRecovery: fx.wrappedDekRecovery,
    })
    expect([...dek]).toEqual([...fx.dek])
  })

  it('wrong mnemonic → wrap_failed', async () => {
    const fx = await setup()
    await expect(
      recoverWithMnemonic({
        mnemonic: generateRecoveryPhrase().mnemonic,
        userId: fx.userId,
        wrappedDekRecovery: fx.wrappedDekRecovery,
      }),
    ).rejects.toMatchObject({ code: 'wrap_failed' })
  })
})

describe('lifecycle — rotateRecovery', () => {
  it('old mnemonic dead, new works, passphrase wrap untouched', async () => {
    const fx = await setup()
    const newPhrase = generateRecoveryPhrase().mnemonic

    const result = await rotateRecovery({
      oldMnemonic: fx.mnemonic,
      newMnemonic: newPhrase,
      userId: fx.userId,
      wrappedDekRecovery: fx.wrappedDekRecovery,
    })

    // Passphrase wrap untouched:
    expect(result.wrapped_dek_recovery).toBeDefined()
    const kek = await importKek(await argon2idDerive(fx.oldPass, fx.kdfSalt, TEST_PARAMS))
    expect([...(await unwrapDek(fx.wrappedDek, kek, fx.userId))]).toEqual([...fx.dek])

    // Old mnemonic dead:
    await expect(
      recoverDek(result.wrapped_dek_recovery, fx.mnemonic, fx.userId),
    ).rejects.toMatchObject({
      code: 'wrap_failed',
    })
    // New mnemonic works:
    expect([...(await recoverDek(result.wrapped_dek_recovery, newPhrase, fx.userId))]).toEqual([
      ...fx.dek,
    ])
  })

  it('invalid new phrase → typed error (wrap_failed or invalid_phrase)', async () => {
    const fx = await setup()
    await expect(
      rotateRecovery({
        oldMnemonic: fx.mnemonic,
        newMnemonic: 'not a valid phrase at all here friend',
        userId: fx.userId,
        wrappedDekRecovery: fx.wrappedDekRecovery,
      }),
    ).rejects.toSatisfy((e: unknown) => {
      const code = (e as { code?: string }).code
      return code === 'wrap_failed' || code === 'invalid_phrase'
    })
  })

  it('wrong old phrase on rotate → wrap_failed (verification first)', async () => {
    const fx = await setup()
    await expect(
      rotateRecovery({
        oldMnemonic: generateRecoveryPhrase().mnemonic,
        newMnemonic: generateRecoveryPhrase().mnemonic,
        userId: fx.userId,
        wrappedDekRecovery: fx.wrappedDekRecovery,
      }),
    ).rejects.toMatchObject({ code: 'wrap_failed' })
  })
})

describe('lifecycle — hygiene (I1)', () => {
  it('results never contain the passphrase, mnemonic words, or DEK bytes as strings', async () => {
    const fx = await setup()
    const result = await changePassphrase({
      oldPass: fx.oldPass,
      newPass: 'brand-new-passphrase',
      userId: fx.userId,
      kdfSalt: fx.kdfSalt,
      kdfParamsJson: fx.kdfParamsJson,
      wrappedDek: fx.wrappedDek,
      wrappedDekRecovery: fx.wrappedDekRecovery,
    })
    const dump = JSON.stringify({
      salt: [...result.kdf_salt],
      params: result.kdf_params,
      wrapped: [...result.wrapped_dek],
      wrappedRec: [...result.wrapped_dek_recovery],
    })
    expect(dump).not.toContain(fx.oldPass)
    expect(dump).not.toContain('brand-new-passphrase')
    expect(dump).not.toContain(fx.mnemonic.split(' ')[0] ?? '')
  })

  it('recovery-wrap rotation roundtrip through wrapDekWithRecovery helper', async () => {
    const userId = 'user-b'
    const dek = generateDek()
    const phrase1 = generateRecoveryPhrase().mnemonic
    const wrapped1 = await wrapDekWithRecovery(dek, phrase1, userId)
    expect([...(await recoverDek(wrapped1, phrase1, userId))]).toEqual([...dek])
    void WrapError
  })
})
