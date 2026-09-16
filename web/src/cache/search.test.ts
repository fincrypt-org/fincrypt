/**
 * Cache tests (C2.7): MiniSearch index over the working set — rebuild on
 * unlock, cleared on lock (D10/I14: ciphertext tables may persist, the
 * decrypted index may not).
 */
import { describe, expect, it, beforeEach } from 'vitest'
import 'fake-indexeddb/auto'
import { cache, clearAll } from './db'
import { buildSearchIndex, searchIndex } from './search'

async function put(type: string, id: string, data: unknown): Promise<void> {
  await cache.working.put({
    key: type + ':' + id,
    recordId: id,
    type,
    data,
    ts: '2026-01-01T00:00:00Z',
  })
}

beforeEach(async () => {
  await clearAll()
})

describe('MiniSearch over the working set', () => {
  it('finds accounts by name and transactions by description/category', async () => {
    await put('accounts', 'a1', { name: 'Checking Main', currency: 'USD' })
    await put('transactions', 't1', {
      description: 'Grocery run',
      category: 'Food',
      amount: 42.5,
    })
    const index = await buildSearchIndex()
    const names = searchIndex(index, 'checking')
    expect(names).toHaveLength(1)
    expect(names[0]?.recordId).toBe('a1')
    expect(names[0]?.type).toBe('accounts')

    const cats = searchIndex(index, 'food')
    expect(cats).toHaveLength(1)
    expect(cats[0]?.recordId).toBe('t1')
  })

  it('rebuild reflects working-table changes (unlock → fresh index)', async () => {
    await put('accounts', 'a1', { name: 'Old Name' })
    const first = searchIndex(await buildSearchIndex(), 'old')
    expect(first).toHaveLength(1)
    // mutate the working set (simulate another save), rebuild on unlock
    await cache.working.delete('accounts:a1')
    await put('accounts', 'a2', { name: 'Savings' })
    const second = searchIndex(await buildSearchIndex(), 'old')
    expect(second).toHaveLength(0)
    expect(searchIndex(await buildSearchIndex(), 'savings')).toHaveLength(1)
  })

  it('empty query returns nothing; results are ranked by score', async () => {
    await put('accounts', 'a1', { name: 'Cash' })
    await put('accounts', 'a2', { name: 'Cash Reserve' })
    const index = await buildSearchIndex()
    expect(searchIndex(index, '   ')).toHaveLength(0)
    const hits = searchIndex(index, 'cash')
    expect(hits.length).toBeGreaterThanOrEqual(1)
    for (let i = 1; i < hits.length; i++) {
      expect(hits[i - 1]?.score).toBeGreaterThanOrEqual(hits[i]?.score ?? 0)
    }
  })
})
