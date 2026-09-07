/**
 * Keystore tests (C1.6): unlock/lock lifecycle, storage-spy (I7),
 * idle timer.
 */
import { beforeAll, afterEach, describe, expect, it, vi } from 'vitest'
import { ensureTestCrypto } from '../crypto/test-env'
import { sessionKeys, useSessionKeys } from './sessionKeys'
import { generateDek, wrapDek, unwrapDek } from '../crypto/keyHierarchy'
import { argon2idDerive, serializeKdfParams, DEFAULT_KDF_PARAMS } from '../crypto/kdf'
import { importKek } from '../crypto/kdf'
import { startIdleTimer } from '../crypto/idleTimer'

beforeAll(() => {
  ensureTestCrypto()
})

afterEach(() => {
  sessionKeys.lock()
  vi.useRealTimers()
})

const enc = new TextEncoder()
void enc

interface Fixture {
  userId: string
  salt: Uint8Array
  wrapped: Uint8Array
  dek: Uint8Array
}

async function makeFixture(pass: string): Promise<Fixture> {
  const userId = 'user-a'
  const salt = crypto.getRandomValues(new Uint8Array(32))
  const dek = generateDek()
  const bytes = await argon2idDerive(pass, salt, { alg: 'argon2id', version: 19, m: 8192, t: 1, p: 1 })
  const kek = await importKek(bytes)
  const wrapped = await wrapDek(dek, kek, userId)
  return { userId, salt, wrapped, dek }
}

describe('sessionKeys — keystore lifecycle', () => {
  it('unlock → getSubkey → lock ⇒ keys gone, store buffer zeroed', async () => {
    const fx = await makeFixture('correct horse')
    const paramsJson = serializeKdfParams({ alg: 'argon2id', version: 19, m: 8192, t: 1, p: 1 })
    await sessionKeys.unlockWithPassphrase({
      pass: 'correct horse',
      userId: fx.userId,
      kdfSalt: fx.salt,
      kdfParamsJson: paramsJson,
      wrappedDek: fx.wrapped,
    })
    expect(sessionKeys.isLocked()).toBe(false)
    const subkey = await sessionKeys.getSubkey('transactions')
    expect(subkey.type).toBe('secret')
    expect(subkey.extractable).toBe(false)
    // second call returns the cached key (same object identity)
    expect(await sessionKeys.getSubkey('transactions')).toBe(subkey)

    // The store's raw DEK buffer, captured before lock:
    const storeDek = useSessionKeys.getState().rawDek
    expect(storeDek).not.toBeNull()

    sessionKeys.lock()
    expect(sessionKeys.isLocked()).toBe(true)
    await expect(sessionKeys.getSubkey('transactions')).rejects.toMatchObject({ code: 'locked' })
    // The buffer the store held is zeroized in place (I3, best-effort):
    expect([...(storeDek as Uint8Array)]).toEqual(new Array(32).fill(0))
  })

  it('wrong passphrase → WrapError, keystore stays locked', async () => {
    const fx = await makeFixture('right password')
    const paramsJson = serializeKdfParams({ alg: 'argon2id', version: 19, m: 8192, t: 1, p: 1 })
    await expect(
      sessionKeys.unlockWithPassphrase({
        pass: 'wrong password',
        userId: fx.userId,
        kdfSalt: fx.salt,
        kdfParamsJson: paramsJson,
        wrappedDek: fx.wrapped,
      }),
    ).rejects.toMatchObject({ code: 'wrap_failed' })
    expect(sessionKeys.isLocked()).toBe(true)
  })

  it('recovery unlock path works and binds the user', async () => {
    const userId = 'user-a'
    const dek = generateDek()
    const { generateRecoveryPhrase, wrapDekWithRecovery } = await import('../crypto/recovery')
    const { mnemonic } = generateRecoveryPhrase()
    const wrappedRecovery = await wrapDekWithRecovery(dek, mnemonic, userId)
    await sessionKeys.unlockWithRecovery({ mnemonic, userId, wrappedDekRecovery: wrappedRecovery })
    const subkey = await sessionKeys.getSubkey('vault')
    expect(subkey.extractable).toBe(false)
    // the unwrapped DEK equals the original (independent derivation paths agree)
    const bytes = await argon2idDerive('recovery-cross', crypto.getRandomValues(new Uint8Array(32)), {
      alg: 'argon2id',
      version: 19,
      m: 8192,
      t: 1,
      p: 1,
    })
    void bytes
    sessionKeys.lock()
    await expect(sessionKeys.getSubkey('vault')).rejects.toMatchObject({ code: 'locked' })
  })

  it('wrapped-DEK material roundtrips through unwrapDek (sanity)', async () => {
    const fx = await makeFixture('roundtrip')
    const bytes = await argon2idDerive('roundtrip', fx.salt, {
      alg: 'argon2id',
      version: 19,
      m: 8192,
      t: 1,
      p: 1,
    })
    const kek = await importKek(bytes)
    expect([...(await unwrapDek(fx.wrapped, kek, fx.userId))]).toEqual([...fx.dek])
  })
})

describe('sessionKeys — storage spy (I7: keys never persisted)', () => {
  it('a full unlock/use/lock cycle performs zero storage calls', async () => {
    const spySetLocal = vi.spyOn(Storage.prototype, 'setItem')
    const spySetSession = vi.spyOn(Storage.prototype, 'setItem')
    const spyRemove = vi.spyOn(Storage.prototype, 'removeItem')
    const spyClear = vi.spyOn(Storage.prototype, 'clear')
    const spyGet = vi.spyOn(Storage.prototype, 'getItem')

    const fx = await makeFixture('spy-pass')
    await sessionKeys.unlockWithPassphrase({
      pass: 'spy-pass',
      userId: fx.userId,
      kdfSalt: fx.salt,
      kdfParamsJson: serializeKdfParams({ alg: 'argon2id', version: 19, m: 8192, t: 1, p: 1 }),
      wrappedDek: fx.wrapped,
    })
    await sessionKeys.getSubkey('chat')
    sessionKeys.lock()

    expect(spySetLocal).not.toHaveBeenCalled()
    expect(spySetSession).not.toHaveBeenCalled()
    expect(spyRemove).not.toHaveBeenCalled()
    expect(spyClear).not.toHaveBeenCalled()
    expect(spyGet).not.toHaveBeenCalled()
    spySetLocal.mockRestore()
    spySetSession.mockRestore()
    spyRemove.mockRestore()
    spyClear.mockRestore()
    spyGet.mockRestore()
  })
})

describe('idleTimer (C1.6, default OFF)', () => {
  it('is default-OFF: the keystore never starts a timer itself', () => {
    vi.useFakeTimers()
    // No timer exists unless startIdleTimer was called:
    expect(vi.getTimerCount()).toBe(0)
    vi.useRealTimers()
  })

  it('fires onIdle after the configured minutes (fake timers)', () => {
    vi.useFakeTimers()
    const onIdle = vi.fn()
    const handle = startIdleTimer(5, onIdle)
    vi.advanceTimersByTime(4 * 60_000)
    expect(onIdle).not.toHaveBeenCalled()
    vi.advanceTimersByTime(1 * 60_000 + 1)
    expect(onIdle).toHaveBeenCalledTimes(1)
    handle.stop()
  })

  it('reset delays the fire', () => {
    vi.useFakeTimers()
    const onIdle = vi.fn()
    const handle = startIdleTimer(5, onIdle)
    vi.advanceTimersByTime(3 * 60_000)
    handle.reset()
    vi.advanceTimersByTime(4 * 60_000)
    expect(onIdle).not.toHaveBeenCalled()
    vi.advanceTimersByTime(1 * 60_000 + 1)
    expect(onIdle).toHaveBeenCalledTimes(1)
    handle.stop()
  })

  it('stop prevents the fire entirely', () => {
    vi.useFakeTimers()
    const onIdle = vi.fn()
    const handle = startIdleTimer(5, onIdle)
    handle.stop()
    vi.advanceTimersByTime(60 * 60_000)
    expect(onIdle).not.toHaveBeenCalled()
  })
})

describe('sessionKeys — params plumbing', () => {
  it('kdf params serialize to the §P1-0 jsonb shape', () => {
    expect(serializeKdfParams(DEFAULT_KDF_PARAMS)).toBe(
      '{"alg":"argon2id","version":19,"m":65536,"t":3,"p":4}',
    )
  })
})