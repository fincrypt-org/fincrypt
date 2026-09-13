/**
 * Dexie cache (C2.7, D10): ciphertext envelopes persist across reloads;
 * the decrypted working set + MiniSearch index do NOT — they are rebuilt
 * on unlock and cleared on lock/logout (I14: zero key material ever).
 * The version field is here from day 1 (pitfall 8).
 */
import Dexie, { type EntityTable } from 'dexie'

export interface CachedEnvelope {
  /** `${type}:${recordId}` — primary key */
  key: string
  recordId: string
  type: string
  /** packed nonce||ciphertext, base64 (I5) */
  blob: string
  aad: string
  ts: string
  deleted: 0 | 1
}

export interface WorkingRow {
  key: string
  recordId: string
  type: string
  /** decrypted JSON payload (client-only; never leaves the device) */
  data: unknown
  ts: string
}

export interface OutboxRow {
  /** monotonically increasing sequence */
  seq: number
  recordId: string
  type: string
  envelope: string // JSON of the full envelope
  ts: string
}

export interface MetaRow {
  key: string
  value: string
}

export class FincryptCache extends Dexie {
  envelopes!: EntityTable<CachedEnvelope, 'key'>
  working!: EntityTable<WorkingRow, 'key'>
  outbox!: EntityTable<OutboxRow, 'seq'>
  meta!: EntityTable<MetaRow, 'key'>

  constructor() {
    super('fincrypt-cache')
    this.version(1).stores({
      envelopes: 'key, type, ts, deleted',
      working: 'key, type',
      outbox: '++seq, type',
      meta: 'key',
    })
  }
}

export const cache = new FincryptCache()

/** clearWorking empties the decrypted set + search index (lock/logout). */
export async function clearWorking(): Promise<void> {
  await cache.working.clear()
}

/** clearAll wipes everything (account reset / e2e isolation). */
export async function clearAll(): Promise<void> {
  await Promise.all([
    cache.envelopes.clear(),
    cache.working.clear(),
    cache.outbox.clear(),
    cache.meta.clear(),
  ])
}
