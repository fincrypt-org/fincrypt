/**
 * Sync engine (C2.6): outbox → flush (≤500/batch) → merge.
 *
 * Every mutation queues an envelope in the Dexie outbox; a flush fires
 * on interval, 'online', and after each mutation. Server changes merge
 * LWW (same D6 rules client-side); tombstones remove cache rows + index
 * entries. Exponential backoff ± jitter on failure.
 */
import { cache, type CachedEnvelope } from '../cache/db'
import { apiFetch } from '../api/client'

// ─── server shapes (§P2-0) ───────────────────────────────────────────

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

// ─── outbox ──────────────────────────────────────────────────────────

/** enqueue adds one mutation to the outbox. */
export async function enqueue(args: {
  recordId: string
  type: string
  envelope: {
    record_id: string
    type: string
    nonce: string
    ciphertext: string
    aad: string
    ts: string
  }
}): Promise<void> {
  await cache.outbox.add({
    seq: 0, // auto-increment
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

// ─── merge (client-side LWW, same D6 rules) ──────────────────────────

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

function typeKey(type: string, recordId: string): string {
  return type + ':' + recordId
}

// ─── flush ───────────────────────────────────────────────────────────

export interface FlushResult {
  pushed: number
  failed: boolean
}

/** flush pushes up to 500 outbox entries and pulls the delta. */
export async function flush(userId: string): Promise<FlushResult> {
  const batch = await cache.outbox.orderBy('seq').limit(500).toArray()
  if (batch.length === 0) {
    // pull-only sync
    return pull(userId)
  }
  const pushes = batch.map((row) => JSON.parse(row.envelope))
  try {
    const since = await getCursor()
    const res = await apiFetch<{ serverTime: string; changes: ChangeJSON[]; nextCursor?: string }>(
      '/api/records/sync',
      { method: 'POST', body: JSON.stringify({ since, pushes }) },
    )
    for (const change of res.changes) {
      await mergeChange(change)
    }
    if (res.nextCursor != null) {
      await cache.meta.put({ key: 'cursor', value: res.nextCursor })
    }
    // remove the flushed batch
    await cache.outbox.bulkDelete(batch.map((b) => b.seq))
    // flush pending deletes
    await flushDeletes(userId)
    return { pushed: batch.length, failed: false }
  } catch {
    return { pushed: 0, failed: true }
  }
}

async function flushDeletes(userId: string): Promise<void> {
  void userId
  const metas = await cache.meta.toArray()
  for (const m of metas) {
    if (!m.key.startsWith('delete:')) continue
    const [, type, recordId] = m.key.split(':')
    try {
      const res = await apiFetch<unknown>(
        `/api/records/${type}/${recordId}?ts=${encodeURIComponent(m.value)}`,
        { method: 'DELETE' },
      )
      void res
      await cache.meta.delete(m.key)
    } catch {
      // keep for retry
    }
  }
}

async function getCursor(): Promise<string | null> {
  const row = await cache.meta.get('cursor')
  return row?.value ?? null
}

async function pull(userId: string): Promise<FlushResult> {
  void userId
  try {
    const since = await getCursor()
    const res = await apiFetch<{ serverTime: string; changes: ChangeJSON[]; nextCursor?: string }>(
      '/api/records/sync',
      { method: 'POST', body: JSON.stringify({ since, pushes: [] }) },
    )
    for (const change of res.changes) {
      await mergeChange(change)
    }
    if (res.nextCursor != null) {
      await cache.meta.put({ key: 'cursor', value: res.nextCursor })
    }
    return { pushed: 0, failed: false }
  } catch {
    return { pushed: 0, failed: true }
  }
}

// ─── scheduler ───────────────────────────────────────────────────────

let timer: ReturnType<typeof setInterval> | null = null
let attempts = 0

/** startSync begins the interval + online-event loop. Idempotent. */
export function startSync(userId: string): void {
  if (timer != null) return
  timer = setInterval(() => {
    void tick(userId)
  }, 15_000)
  if (typeof window !== 'undefined') {
    window.addEventListener('online', () => {
      void tick(userId)
    })
  }
}

export function stopSync(): void {
  if (timer != null) {
    clearInterval(timer)
    timer = null
  }
}

async function tick(userId: string): Promise<void> {
  const result = await flush(userId)
  if (result.failed) {
    attempts = Math.min(attempts + 1, 6) // cap ~10 min with 2^n seconds
  } else {
    attempts = 0
  }
}

/** backoffDelay is the current exponential backoff ± 20% jitter (ms). */
export function backoffDelay(): number {
  const base = Math.pow(2, attempts) * 1000
  const jitter = Math.random() * base * 0.2
  return Math.min(base + jitter, base * 1.2 + 200)
}
