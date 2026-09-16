/**
 * Merge (C2.6): client-side LWW, same D6 rules as the server — winner =
 * strictly greater ts, equal keeps the stored copy, tombstones delete
 * cache rows + working entries (never mutate envelopes into a
 * tombstone-shaped row).
 */
import { cache, type CachedEnvelope } from '../cache/db'
import { typeKey } from './outbox'

interface ChangeJSON {
  envelope?: {
    record_id: string
    type: string
    nonce: string
    ciphertext: string
    aad: string
    ts: string
  }
  tombstone?: {
    recordId: string
    type: string
    deletedAt: string
  }
}

/** mergeChange applies one server change to the local cache. */
export async function mergeChange(change: ChangeJSON): Promise<void> {
  if (change.tombstone != null) {
    const { recordId, type } = change.tombstone
    await cache.envelopes.delete(typeKey(type, recordId))
    await cache.working.delete(typeKey(type, recordId))
    return
  }
  const e = change.envelope
  if (e == null) return
  const key = typeKey(e.type, e.record_id)
  const existing = await cache.envelopes.get(key)
  // client-side LWW: strictly greater ts wins; equal ts keeps stored
  if (existing != null && existing.ts >= e.ts) return
  const row: CachedEnvelope = {
    key,
    recordId: e.record_id,
    type: e.type,
    blob: e.ciphertext, // packed nonce||ct from the server
    aad: e.aad,
    ts: e.ts,
    deleted: 0,
  }
  await cache.envelopes.put(row)
}

export type { ChangeJSON }
