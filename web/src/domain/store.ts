/**
 * Data layer (C2.8): the ONLY path from UI intent to encrypted storage.
 * encrypt → outbox → (flush) → server; decrypt on pull → working set.
 * Everything here uses the frozen crypto API (P1) — no local shims.
 */
import { cache, clearWorking } from '../cache/db'
import { enqueue, flush, startSync, type FlushResult } from '../sync/engine'
import { useSessionKeys } from '../stores/sessionKeys'
import { deriveSubkey, buildAadString } from '../crypto/index'
import { fromB64 } from '../crypto/b64'
import type { DataByType, SyncableType } from './types'
import { isSyncableType } from './types'

// ─── write path ──────────────────────────────────────────────────────

/**
 * saveRecord encrypts the payload with the type's subkey, queues the
 * envelope, and triggers a flush (immediate when online).
 */
export async function saveRecord<T extends SyncableType>(args: {
  type: T
  recordId: string
  data: DataByType[T]
  /** existing envelope ts for updates; omit for create */
  ts?: string
}): Promise<void> {
  const store = useSessionKeys.getState()
  if (store.locked || store.rawDek == null || store.recordUserId == null) {
    throw new Error('vault is locked')
  }
  const userId = store.recordUserId
  const subkey = await deriveSubkey(store.rawDek, args.type)
  const recordId = args.recordId
  const aad = buildAadString(userId, args.type, recordId)
  const nonce = new Uint8Array(12)
  crypto.getRandomValues(nonce)
  const plaintext = new TextEncoder().encode(JSON.stringify(args.data))
  const packed = await encryptWithSubkey(subkey, nonce, plaintext, aad)
  const envelope = {
    record_id: recordId,
    type: args.type,
    nonce: toB64(nonce),
    ciphertext: toB64(packed),
    aad,
    ts: args.ts ?? new Date().toISOString(),
  }
  // write-through cache (decrypted working set + ciphertext row)
  await cache.working.put({
    key: args.type + ':' + recordId,
    recordId,
    type: args.type,
    data: args.data,
    ts: envelope.ts,
  })
  await enqueue({ recordId, type: args.type, envelope })
  // optimistic UI: flush in the background
  void flush(userId)
}

/** deleteRecord tombstones locally and queues the server delete. */
export async function deleteRecord(type: SyncableType, recordId: string): Promise<void> {
  const store = useSessionKeys.getState()
  if (store.userId == null) throw new Error('vault locked')
  await cache.envelopes.delete(type + ':' + recordId)
  await cache.working.delete(type + ':' + recordId)
  await cache.meta.put({
    key: 'delete:' + type + ':' + recordId,
    value: new Date().toISOString(),
  })
  void flush(store.userId)
}

// ─── read path ───────────────────────────────────────────────────────

/**
 * loadWorking decrypts every cached envelope of a type into the working
 * set (called on unlock; the working set is never persisted).
 */
export async function loadWorking(
  type: SyncableType,
): Promise<Array<{ recordId: string; data: unknown; ts: string }>> {
  const store = useSessionKeys.getState()
  if (store.locked || store.rawDek == null || store.userId == null) {
    throw new Error('vault is locked')
  }
  const subkey = await deriveSubkey(store.rawDek, type)
  // pull the latest server delta first so the read is cache-coherent;
  // failures (offline) just fall through to the local cache
  try {
    await flush(store.userId)
  } catch {
    // offline / server unreachable — keep the cached view
  }
  const rows = await cache.envelopes.where('type').equals(type).toArray()
  const out: Array<{ recordId: string; data: unknown; ts: string }> = []
  const covered = new Set<string>()
  for (const row of rows) {
    if (row.deleted === 1) continue
    const packed = fromB64(row.blob)
    // server returns the packed blob: 12-byte nonce || ciphertext
    const nonce = packed.slice(0, 12)
    const ciphertext = packed.slice(12)
    const plaintext = await decryptWithSubkey(subkey, nonce, ciphertext, row.aad)
    const data = JSON.parse(new TextDecoder().decode(plaintext)) as unknown
    await cache.working.put({ key: row.key, recordId: row.recordId, type, data, ts: row.ts })
    covered.add(row.key)
    out.push({ recordId: row.recordId, data, ts: row.ts })
  }
  // freshly-saved rows live in the working set before the server
  // round-trip lands them in envelopes — surface them too
  const pending = await cache.working.where('type').equals(type).toArray()
  for (const w of pending) {
    if (covered.has(w.key)) continue
    out.push({ recordId: w.recordId, data: w.data, ts: w.ts })
  }
  return out
}

// ─── crypto glue (byte-level, subkey-based) ──────────────────────────

async function encryptWithSubkey(
  subkey: CryptoKey,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: string,
): Promise<Uint8Array> {
  const ptCopy = new Uint8Array(plaintext.length)
  ptCopy.set(plaintext)
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: new Uint8Array(nonce.slice()),
        additionalData: new TextEncoder().encode(aad),
      },
      subkey,
      ptCopy,
    ),
  )
  // packed = nonce || ct (server stores verbatim)
  const packed = new Uint8Array(nonce.length + ct.length)
  packed.set(nonce, 0)
  packed.set(ct, nonce.length)
  return packed
}

async function decryptWithSubkey(
  subkey: CryptoKey,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad: string,
): Promise<Uint8Array> {
  const ctCopy = new Uint8Array(ciphertext.length)
  ctCopy.set(ciphertext)
  return new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: new Uint8Array(nonce.slice()),
        additionalData: new TextEncoder().encode(aad),
      },
      subkey,
      ctCopy,
    ),
  )
}

function toB64(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s)
}

/** syncNow forces a flush (used by the UI refresh button). */
export async function syncNow(): Promise<FlushResult> {
  const store = useSessionKeys.getState()
  if (store.userId == null) throw new Error('not signed in')
  return flush(store.userId)
}

/** beginSync flushes immediately, then starts the background loop (on unlock). */
export function beginSync(): void {
  const store = useSessionKeys.getState()
  if (store.userId != null) {
    void flush(store.userId)
    startSync(store.userId)
  }
}

/** endSync stops the loop and clears the decrypted working set (on lock). */
export async function endSync(): Promise<void> {
  await clearWorking()
}

// re-exports so pages don't import the engine directly
export { flush, isSyncableType }
