/**
 * Search (C2.7): MiniSearch over the decrypted working set. The index
 * lives in memory only, rebuilt on unlock, and is destroyed on
 * lock/logout (D10/I14: zero key material at rest beyond the ciphertext
 * envelope tables).
 */
import MiniSearch from 'minisearch'
import { cache } from './db'

/** searchable text for one working row (type-aware field extraction) */
function searchableText(type: string, data: unknown): string {
  if (data == null || typeof data !== 'object') return ''
  const d = data as Record<string, unknown>
  if (type === 'accounts') {
    return String(d.name ?? '')
  }
  if (type === 'transactions') {
    return [d.description, d.category, d.amount].filter(Boolean).join(' ')
  }
  return JSON.stringify(d)
}

export interface SearchRow {
  key: string
  recordId: string
  type: string
  data: unknown
  ts: string
}

export interface SearchHit {
  key: string
  recordId: string
  type: string
  /** score from MiniSearch (higher = more relevant) */
  score: number
}

/** buildSearchIndex loads the whole working table into a fresh index. */
export async function buildSearchIndex(): Promise<MiniSearch<SearchRow>> {
  const index = new MiniSearch<SearchRow>({
    fields: ['text'],
    storeFields: ['key', 'recordId', 'type'],
    idField: 'key',
    extractField: (row, field) =>
      field === 'text'
        ? searchableText(row.type, row.data)
        : ((row as unknown as Record<string, string>)[field] ?? ''),
  })
  const rows = await cache.working.toArray()
  index.addAll(
    rows.map((w) => ({
      key: w.key,
      recordId: w.recordId,
      type: w.type,
      data: w.data,
      ts: w.ts,
    })),
  )
  return index
}

/** searchIndex queries the in-memory index; empty query ⇒ no hits. */
export function searchIndex(
  index: MiniSearch<SearchRow> | null,
  query: string,
  limit = 50,
): SearchHit[] {
  if (index == null || query.trim() === '') return []
  return index
    .search(query)
    .slice(0, limit)
    .map((h) => ({
      key: String(h.key),
      recordId: String(h.recordId),
      type: String(h.type),
      score: h.score,
    }))
}
