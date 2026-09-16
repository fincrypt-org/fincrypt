/**
 * Outbox (C2.6): durable mutation queue. Every mutation lands here
 * before any network attempt, so a reload or offline window can never
 * lose a write; flush drains ≤500 entries per batch.
 */
import { cache, type OutboxRow } from '../cache/db'

export interface OutboxEnvelope {
  record_id: string
  type: string
  nonce: string
  ciphertext: string
  aad: string
  ts: string
}

/** enqueue adds one mutation to the outbox. */
export async function enqueue(args: {
  recordId: string
  type: string
  envelope: OutboxEnvelope
}): Promise<void> {
  await cache.outbox.add({
    recordId: args.recordId,
    type: args.type,
    envelope: JSON.stringify(args.envelope),
    ts: args.envelope.ts,
  })
}

/** enqueueDelete queues a tombstone push (DELETE endpoint call). */
export async function enqueueDelete(args: {
  recordId: string
  type: string
  ts: string
}): Promise<void> {
  await cache.meta.put({ key: 'delete:' + args.type + ':' + args.recordId, value: args.ts })
  await cache.envelopes.update(typeKey(args.type, args.recordId), { deleted: 1 })
  // the delete itself is flushed as a DELETE request in flush()
}

/** typeKey builds the cache primary key for one record. */
export function typeKey(type: string, recordId: string): string {
  return type + ':' + recordId
}

/** drainBatch returns the next ≤limit outbox rows in FIFO order. */
export async function drain(limit = 500): Promise<OutboxRow[]> {
  return cache.outbox.orderBy('seq').limit(limit).toArray()
}

/** removeFlushed deletes the given rows after a successful push. */
export async function removeFlushed(seqs: number[]): Promise<void> {
  await cache.outbox.bulkDelete(seqs)
}

/** pendingDeletes lists queued tombstone pushes. */
export async function pendingDeletes(): Promise<
  Array<{ type: string; recordId: string; ts: string }>
> {
  const metas = await cache.meta.toArray()
  const out: Array<{ type: string; recordId: string; ts: string }> = []
  for (const m of metas) {
    if (!m.key.startsWith('delete:')) continue
    const [, type, recordId] = m.key.split(':')
    out.push({ type: type ?? '', recordId: recordId ?? '', ts: m.value })
  }
  return out
}

/** clearDelete removes one queued tombstone after its DELETE succeeds. */
export async function clearDelete(type: string, recordId: string): Promise<void> {
  await cache.meta.delete('delete:' + type + ':' + recordId)
}
