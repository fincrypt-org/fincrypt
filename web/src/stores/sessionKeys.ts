/**
 * Session keystore (C1.6, I7): memory-only.
 *
 * Holds the raw DEK (zeroizable), derived subkeys (cached), and the
 * userId binding. Key material is NEVER written to any persistence
 * API (browser storage, cookies) — enforced three ways: eslint no-restricted-globals over
 * src/{crypto,stores}, a CI grep (lint-web job), and a runtime
 * storage-spy test (sessionKeys.test.ts).
 */
import { create } from 'zustand'
import { argon2idDerive, parseKdfParams, serializeKdfParams, type KdfParams } from '../crypto/kdf'
import { deriveKekOffThread } from '../crypto/kdfWorkerClient'
import { generateDek, deriveSubkey, unwrapDek, type RawKey } from '../crypto/keyHierarchy'
import { deriveRecoveryKek, recoverDek } from '../crypto/recovery'
import { importAesKey } from '../crypto/aead'
import { zeroize } from '../crypto/memzero'
import { CryptoError } from '../crypto/errors'

export interface UnlockMaterial {
  userId: string
  kdfSalt: Uint8Array
  kdfParamsJson: string
  wrappedDek: Uint8Array
}

export interface RecoveryUnlockMaterial {
  userId: string
  wrappedDekRecovery: Uint8Array
}

interface SessionKeysState {
  locked: boolean
  userId: string | null
  /** server-assigned UUID for record-data AADs (differs from the wrap id) */
  recordUserId: string | null
  rawDek: RawKey | null
  subkeys: Map<RecordTypeLike, CryptoKey>
  /** kdf params as stored (echoed on lock for re-derive flows) */
  kdfParamsJson: string | null
  kdfSalt: Uint8Array | null
  wrappedDek: Uint8Array | null
  wrappedDekRecovery: Uint8Array | null
}

type RecordTypeLike = 'transactions' | 'attachments' | 'chat' | 'accounts' | 'vault'

interface SessionKeysActions {
  unlockWithPassphrase(args: {
    pass: string
    /** OPAQUE/wrap identity (canonical email) — binds the wrap AAD */
    userId: string
    /** server-assigned user UUID — binds the RECORD data AAD */
    recordUserId?: string
    kdfSalt: Uint8Array
    kdfParamsJson: string
    wrappedDek: Uint8Array
  }): Promise<void>
  unlockWithRecovery(args: {
    mnemonic: string
    userId: string
    wrappedDekRecovery: Uint8Array
  }): Promise<void>
  getSubkey(type: RecordTypeLike): Promise<CryptoKey>
  lock(): void
}

type SessionKeysStore = SessionKeysState & SessionKeysActions

export const useSessionKeys = create<SessionKeysStore>((set, get) => ({
  locked: true,
  userId: null,
  recordUserId: null,
  rawDek: null,
  subkeys: new Map(),
  kdfParamsJson: null,
  kdfSalt: null,
  wrappedDek: null,
  wrappedDekRecovery: null,

  async unlockWithPassphrase(args: Parameters<SessionKeysActions['unlockWithPassphrase']>[0]) {
    const { pass, userId, kdfSalt, kdfParamsJson, wrappedDek } = args
    const params = parseKdfParams(kdfParamsJson)
    // KSF off the main thread when a Worker is available — a 64 MiB
    // Argon2id on the main thread freezes all rendering during unlock.
    let kek: CryptoKey
    try {
      kek = (await deriveKekOffThread(pass, kdfSalt, params)).kek
    } catch {
      kek = await importAesKey(await argon2idDerive(pass, kdfSalt, params))
    }
    const dek = await unwrapDek(wrappedDek, kek, userId)
    set({
      locked: false,
      userId,
      recordUserId: args.recordUserId ?? userId,
      rawDek: dek,
      subkeys: new Map(),
      kdfParamsJson,
      kdfSalt,
      wrappedDek,
      wrappedDekRecovery: null,
    })
    if (typeof indexedDB !== 'undefined') {
      void import('../domain/store').then((m) => m.beginSync?.())
    }
  },

  async unlockWithRecovery({ mnemonic, userId, wrappedDekRecovery }) {
    const dek = await recoverDek(wrappedDekRecovery, mnemonic, userId)
    set({
      locked: false,
      userId,
      rawDek: dek,
      subkeys: new Map(),
      kdfParamsJson: null,
      kdfSalt: null,
      wrappedDek: null,
      wrappedDekRecovery,
    })
    if (typeof indexedDB !== 'undefined') {
      void import('../domain/store').then((m) => m.beginSync?.())
    }
  },

  async getSubkey(type) {
    const state = get()
    if (state.locked || state.rawDek == null) {
      throw new CryptoError('locked', 'keystore is locked')
    }
    const cached = state.subkeys.get(type)
    if (cached) return cached
    const key = await deriveSubkey(state.rawDek as RawKey, type)
    const next = new Map(state.subkeys)
    next.set(type, key)
    set({ subkeys: next })
    return key
  },

  lock() {
    const state = get()
    if (state.rawDek) zeroize(state.rawDek)
    set({
      locked: true,
      userId: null,
      rawDek: null,
      subkeys: new Map(),
      kdfParamsJson: null,
      kdfSalt: null,
      wrappedDek: null,
      wrappedDekRecovery: null,
    })
    if (typeof indexedDB !== 'undefined') {
      void import('../domain/store').then((m) => m.endSync?.())
    }
  },
}))

/** Non-hook accessor for non-React callers (lifecycle.ts, dev page). */
export const sessionKeys = {
  unlockWithPassphrase: (args: Parameters<SessionKeysActions['unlockWithPassphrase']>[0]) =>
    useSessionKeys.getState().unlockWithPassphrase(args),
  unlockWithRecovery: (args: Parameters<SessionKeysActions['unlockWithRecovery']>[0]) =>
    useSessionKeys.getState().unlockWithRecovery(args),
  getSubkey: (type: RecordTypeLike) => useSessionKeys.getState().getSubkey(type),
  lock: () => useSessionKeys.getState().lock(),
  isLocked: () => useSessionKeys.getState().locked,
  currentUserId: () => useSessionKeys.getState().userId,
  material: () => {
    const s = useSessionKeys.getState()
    return {
      kdfSalt: s.kdfSalt,
      kdfParamsJson: s.kdfParamsJson,
      wrappedDek: s.wrappedDek,
      wrappedDekRecovery: s.wrappedDekRecovery,
    }
  },
  /** Re-encrypt a record through the keystore (I4: subkey only). */
  async encryptRecord(
    userId: string,
    type: RecordTypeLike,
    plaintext: Uint8Array,
    aad: string,
  ): Promise<{ nonce: Uint8Array; ciphertext: Uint8Array }> {
    const s = useSessionKeys.getState()
    if (s.locked || s.userId !== userId)
      throw new CryptoError('locked', 'keystore locked or user mismatch')
    const key = await s.getSubkey(type)
    const { encryptBytes } = await import('../crypto/aead')
    const packed = await encryptBytes(key, plaintext, new TextEncoder().encode(aad))
    return { nonce: packed.slice(0, 12), ciphertext: packed.slice(12) }
  },
  generateDek,
  serializeKdfParams,
}

/** Exposed for lifecycle flows that need to derive a KEK directly. */
export async function deriveKekBytes(
  pass: string,
  kdfSalt: Uint8Array,
  kdfParamsJson: string,
): Promise<Uint8Array> {
  const params: KdfParams = parseKdfParams(kdfParamsJson)
  return argon2idDerive(pass, kdfSalt, params)
}

export { deriveRecoveryKek }
