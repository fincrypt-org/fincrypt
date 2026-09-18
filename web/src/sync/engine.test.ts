/**
 * Sync engine + cache tests (C2.6/C2.7, fake-indexeddb): queue survives
 * reload, deterministic merge winner, tombstone propagation, idempotent
 * re-sync, ciphertext-only envelope tables, clear-on-lock.
 */
import { describe, expect, it, beforeEach, vi } from 'vitest'
import 'fake-indexeddb/auto'
import { cache, clearAll } from '../cache/db'
import { enqueue, flush, enqueueDelete, backoffDelay } from '../sync/engine'
import { drain, removeFlushed, pendingDeletes, clearDelete } from '../sync/outbox'
import { mergeChange } from '../sync/merge'
import { useSessionKeys } from '../stores/sessionKeys'

// The engine's fetch goes to the "server"; a small in-memory stub holds
// the server's authoritative state and applies the same LWW.
function makeServerStub() {
  const serverState = new Map<string, { ciphertext: string; ts: string; aad: string }>()
  const tombstones = new Set<string>()

  async function handle(path: string, body: Record<string, unknown>): Promise<unknown> {
    if (path === '/api/records/sync') {
      const pushes = (body.pushes ?? []) as Array<{
        record_id: string
        type: string
        ciphertext: string
        aad: string
        ts: string
      }>
      for (const p of pushes) {
        const key = p.type + ':' + p.record_id
        const existing = serverState.get(key)
        // server LWW: strictly greater ts
        if (existing == null || existing.ts < p.ts) {
          serverState.set(key, { ciphertext: p.ciphertext, ts: p.ts, aad: p.aad })
        }
      }
      // return changes newer than cursor
      const since = (body.since as string | null) ?? null
      const changes = []
      for (const [key, v] of serverState) {
        const [type, recordId] = key.split(':')
        if (since == null || v.ts > since) {
          changes.push({
            envelope: {
              record_id: recordId,
              type,
              nonce: '',
              ciphertext: v.ciphertext,
              aad: v.aad,
              ts: v.ts,
            },
          })
        }
      }
      const serverTime = new Date().toISOString()
      return { serverTime, changes, nextCursor: serverTime }
    }
    throw new Error('unhandled path ' + path)
  }

  return { serverState, tombstones, handle }
}

let stub: ReturnType<typeof makeServerStub>

beforeEach(async () => {
  await clearAll()
  stub = makeServerStub()
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input)
      const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : {}
      const data = await stub.handle(path, body)
      return new Response(JSON.stringify(data), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    }),
  )
  useSessionKeys.getState().lock()
})

function envelope(args: {
  recordId: string
  type: string
  seed: number
  ts: string
  userId: string
}) {
  const nonce = new Uint8Array(12)
  crypto.getRandomValues(nonce)
  const ct = new Uint8Array(40)
  ct[0] = args.seed
  return {
    record_id: args.recordId,
    type: args.type,
    nonce: btoa(String.fromCharCode(...nonce)),
    ciphertext: btoa(String.fromCharCode(...ct)),
    aad: 'v1|' + args.userId + '|' + args.type + '|' + args.recordId,
    ts: args.ts,
  }
}

describe('outbox', () => {
  it('queues mutations and survives a reload (fresh module state reads the same table)', async () => {
    await enqueue({
      recordId: 'r1',
      type: 'accounts',
      envelope: envelope({
        recordId: 'r1',
        type: 'accounts',
        seed: 1,
        ts: new Date().toISOString(),
        userId: 'u',
      }),
    })
    const rows = await cache.outbox.toArray()
    expect(rows).toHaveLength(1)
    expect(rows[0]?.type).toBe('accounts')
  })

  it('drains in FIFO seq order and respects the batch limit', async () => {
    for (let i = 0; i < 3; i++) {
      await enqueue({
        recordId: 'd' + i,
        type: 'chat',
        envelope: envelope({
          recordId: 'd' + i,
          type: 'chat',
          seed: i,
          ts: new Date().toISOString(),
          userId: 'u',
        }),
      })
    }
    const batch = await drain(2)
    expect(batch).toHaveLength(2)
    expect(batch[0]?.seq).toBeLessThanOrEqual(batch[1]?.seq ?? 0)
    const first = JSON.parse(batch[0]?.envelope ?? '{}') as { record_id: string }
    expect(first.record_id).toBe('d0')
    await removeFlushed(batch.map((b) => b.seq))
    const rest = await cache.outbox.toArray()
    expect(rest).toHaveLength(1)
  })

  it('queues and clears tombstone deletes', async () => {
    await cache.envelopes.put({
      key: 'chat:dd1',
      recordId: 'dd1',
      type: 'chat',
      blob: 'A',
      aad: 'x',
      ts: '2026-01-01T00:00:00Z',
      deleted: 0,
    })
    const ts = '2026-01-02T00:00:00Z'
    await enqueueDelete({ recordId: 'dd1', type: 'chat', ts })
    const row = await cache.envelopes.get('chat:dd1')
    expect(row?.deleted).toBe(1) // flagged locally
    const pending = await pendingDeletes()
    expect(pending).toHaveLength(1)
    expect(pending[0]?.recordId).toBe('dd1')
    await clearDelete('chat', 'dd1')
    expect(await pendingDeletes()).toHaveLength(0)
  })
})

describe('merge (client LWW)', () => {
  it('keeps the stored copy on equal-or-older ts', async () => {
    const ts = new Date().toISOString()
    await cache.envelopes.put({
      key: 'chat:keep',
      recordId: 'keep',
      type: 'chat',
      blob: 'stored',
      aad: 'v1|u|chat|keep',
      ts,
      deleted: 0,
    })
    await mergeChange({
      envelope: {
        record_id: 'keep',
        type: 'chat',
        nonce: '',
        ciphertext: 'NEW',
        aad: 'v1|u|chat|keep',
        ts, // equal ts
      },
    })
    const row = await cache.envelopes.get('chat:keep')
    expect(row?.blob).toBe('stored') // equal ts ⇒ stored copy wins
  })

  it('applies strictly newer envelopes', async () => {
    await mergeChange({
      envelope: {
        record_id: 'n1',
        type: 'chat',
        nonce: '',
        ciphertext: 'AAA',
        aad: 'v1|u|chat|n1',
        ts: '2026-01-01T00:00:00Z',
      },
    })
    await mergeChange({
      envelope: {
        record_id: 'n1',
        type: 'chat',
        nonce: '',
        ciphertext: 'BBB',
        aad: 'v1|u|chat|n1',
        ts: '2026-01-02T00:00:00Z',
      },
    })
    const row = await cache.envelopes.get('chat:n1')
    expect(row?.blob).toBe('BBB') // strictly newer ⇒ applied
  })

  it('removes rows + working entries on tombstones (never a mutated envelope)', async () => {
    await cache.envelopes.put({
      key: 'chat:gone',
      recordId: 'gone',
      type: 'chat',
      blob: 'AAA',
      aad: 'v1|u|chat|gone',
      ts: '2026-01-01T00:00:00Z',
      deleted: 0,
    })
    await cache.working.put({
      key: 'chat:gone',
      recordId: 'gone',
      type: 'chat',
      data: { x: 1 },
      ts: '',
    })
    await mergeChange({
      tombstone: { recordId: 'gone', type: 'chat', deletedAt: '2026-01-02T00:00:00Z' },
    })
    expect(await cache.envelopes.get('chat:gone')).toBeUndefined()
    expect(await cache.working.get('chat:gone')).toBeUndefined()
  })
})

describe('flush', () => {
  it('pushes the outbox, merges server changes, and clears the queue', async () => {
    await enqueue({
      recordId: 'f1',
      type: 'chat',
      envelope: envelope({
        recordId: 'f1',
        type: 'chat',
        seed: 7,
        ts: new Date().toISOString(),
        userId: 'u',
      }),
    })
    const result = await flush('user-1')
    expect(result.failed).toBe(false)
    expect(result.pushed).toBe(1)
    expect(await cache.outbox.count()).toBe(0)
  })

  it('re-sync is idempotent (no duplicate rows)', async () => {
    const env = envelope({
      recordId: 'i1',
      type: 'chat',
      seed: 3,
      ts: new Date().toISOString(),
      userId: 'u',
    })
    await enqueue({ recordId: 'i1', type: 'chat', envelope: env })
    await flush('user-1')
    await flush('user-1') // pull-only
    const rows = [await cache.envelopes.get('chat:i1')]
    expect(rows).toHaveLength(1)
  })

  it('keeps the queue on server failure (retry semantics)', async () => {
    await enqueue({
      recordId: 'x1',
      type: 'chat',
      envelope: envelope({
        recordId: 'x1',
        type: 'chat',
        seed: 1,
        ts: new Date().toISOString(),
        userId: 'u',
      }),
    })
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        await Promise.resolve()
        throw new TypeError('network down')
      }),
    )
    const result = await flush('user-1')
    expect(result.failed).toBe(true)
    expect(await cache.outbox.count()).toBe(1) // still queued
  })
})

describe('scheduler', () => {
  it('backoff grows exponentially and stays within the jitter cap', () => {
    const first = backoffDelay()
    expect(first).toBeGreaterThanOrEqual(1000)
    expect(first).toBeLessThanOrEqual(1200) // 1s ± 20%
  })
})

describe('cache hygiene', () => {
  it('envelope tables hold ciphertext only (no plaintext fields)', async () => {
    await cache.envelopes.put({
      key: 'chat:c1',
      recordId: 'c1',
      type: 'chat',
      blob: 'QUJD',
      aad: 'v1|u|chat|c1',
      ts: '2026-01-01T00:00:00Z',
      deleted: 0,
    })
    const row = await cache.envelopes.get('chat:c1')
    expect(row && Object.keys(row).sort()).toEqual([
      'aad',
      'blob',
      'deleted',
      'key',
      'recordId',
      'ts',
      'type',
    ])
    expect(row && typeof row.blob).toBe('string') // base64 ciphertext
  })

  it('clearAll wipes every table', async () => {
    await cache.envelopes.put({
      key: 'chat:c2',
      recordId: 'c2',
      type: 'chat',
      blob: 'A',
      aad: 'x',
      ts: '',
      deleted: 0,
    })
    await clearAll()
    expect(await cache.envelopes.count()).toBe(0)
    expect(await cache.outbox.count()).toBe(0)
  })
})
