/**
 * Sync engine (C2.6): orchestrator. Outbox → flush (≤500/batch) →
 * merge. Queueing lives in outbox.ts, LWW/tombstone application in
 * merge.ts; this module owns the transport loop — flush on interval,
 * 'online', and after each mutation — with exponential backoff ± jitter.
 */
import { cache } from '../cache/db'
import { apiFetch } from '../api/client'
import { enqueue, enqueueDelete, drain, removeFlushed, pendingDeletes, clearDelete } from './outbox'
import { mergeChange, type ChangeJSON } from './merge'

// re-export so existing importers (domain/store) keep one surface
export { enqueue, enqueueDelete }
export { mergeChange }
export type { ChangeJSON }

// ─── flush ───────────────────────────────────────────────────────────

export interface FlushResult {
  pushed: number
  failed: boolean
}

/** flush pushes up to 500 outbox entries and pulls the delta. */
export async function flush(userId: string): Promise<FlushResult> {
  const batch = await drain(500)
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
    // remove the flushed batch only after merge — a crash mid-flush
    // leaves the rows queued (retry semantics)
    await removeFlushed(batch.map((b) => b.seq))
    // flush pending deletes
    await flushDeletes()
    return { pushed: batch.length, failed: false }
  } catch {
    return { pushed: 0, failed: true }
  }
}

async function flushDeletes(): Promise<void> {
  const pending = await pendingDeletes()
  for (const d of pending) {
    try {
      await apiFetch<unknown>(
        `/api/records/${d.type}/${d.recordId}?ts=${encodeURIComponent(d.ts)}`,
        { method: 'DELETE' },
      )
      await clearDelete(d.type, d.recordId)
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
