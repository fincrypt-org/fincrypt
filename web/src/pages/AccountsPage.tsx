/**
 * Accounts page (C2.8): first-class accounts — name/currency/opening
 * balance live inside the ciphertext; balances are derived client-side.
 * Content left-aligns in the 1200 shell (layout convention).
 */
import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { saveRecord, loadWorking } from '../domain/store'
import type { AccountData } from '../domain/types'

interface AccountRow {
  recordId: string
  data: AccountData
  ts: string
}

export default function AccountsPage() {
  const [rows, setRows] = useState<AccountRow[]>([])
  const [name, setName] = useState('')
  const [currency, setCurrency] = useState('USD')
  const [opening, setOpening] = useState('0.00')
  const [busy, setBusy] = useState(false)
  const [localError, setLocalError] = useState<string | null>(null)

  async function reload() {
    const loaded = await loadWorking('accounts')
    setRows(
      loaded
        .map((r) => ({ recordId: r.recordId, data: r.data as AccountData, ts: r.ts }))
        .sort((a, b) => a.data.name.localeCompare(b.data.name)),
    )
  }

  useEffect(() => {
    void reload()
  }, [])

  async function onCreate(e: React.FormEvent) {
    e.preventDefault()
    if (name.trim() === '') return
    setBusy(true)
    try {
      const data: AccountData = {
        name: name.trim(),
        currency,
        openingBalance: Number(opening),
        institutionNote: '',
        archived: false,
      }
      await saveRecord({ type: 'accounts', recordId: crypto.randomUUID(), data })
      setName('')
      setOpening('0.00')
      await reload()
    } catch (e) {
      setLocalError(String(e))
    } finally {
      setBusy(false)
    }
  }

  async function onArchive(row: AccountRow) {
    setBusy(true)
    try {
      await saveRecord({
        type: 'accounts',
        recordId: row.recordId,
        data: { ...row.data, archived: true },
        ts: new Date(Date.now() + 1).toISOString(), // strictly newer than stored
      })
      await reload()
    } finally {
      setBusy(false)
    }
  }

  const active = useMemo(() => rows.filter((r) => !r.data.archived), [rows])
  const archived = useMemo(() => rows.filter((r) => r.data.archived), [rows])

  return (
    <main style={{ padding: '2rem', maxWidth: 1200 }}>
      <h1>Accounts</h1>
      {localError != null && <p role="alert" style={{ color: "#c0392b" }}>{localError}</p>}
      <form
        onSubmit={onCreate}
        style={{ display: 'flex', gap: '0.5rem', maxWidth: 640, margin: '1rem 0 2rem' }}
      >
        <input
          placeholder="Account name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
          style={{ flex: 2, padding: '0.5rem' }}
        />
        <select
          value={currency}
          onChange={(e) => setCurrency(e.target.value)}
          style={{ width: 90, padding: '0.5rem' }}
        >
          {['USD', 'EUR', 'GBP', 'CHF'].map((c) => (
            <option key={c}>{c}</option>
          ))}
        </select>
        <input
          placeholder="Opening balance"
          value={opening}
          onChange={(e) => setOpening(e.target.value)}
          style={{ width: 130, padding: '0.5rem' }}
        />
        <button type="submit" disabled={busy} style={{ padding: '0.5rem 1rem' }}>
          Add
        </button>
      </form>

      <h2>Active</h2>
      {active.length === 0 && (
        <p style={{ color: 'var(--muted-foreground, #777)' }}>No accounts yet.</p>
      )}
      <ul style={{ listStyle: 'none', padding: 0, maxWidth: 760 }}>
        {active.map((row) => (
          <li
            key={row.recordId}
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              padding: '0.6rem 0.8rem',
              borderBottom: '1px solid var(--border, #e5e5e5)',
            }}
          >
            <span>
              <strong>{row.data.name}</strong>{' '}
              <span style={{ color: 'var(--muted-foreground, #888)' }}>{row.data.currency}</span>
            </span>
            <span style={{ display: 'flex', gap: '0.75rem' }}>
              <Link to={`/transactions?account=${row.recordId}`}>Transactions</Link>
              <button
                onClick={() => void onArchive(row)}
                disabled={busy}
                style={{ cursor: 'pointer' }}
              >
                Archive
              </button>
            </span>
          </li>
        ))}
      </ul>

      {archived.length > 0 && (
        <>
          <h2>Archived</h2>
          <ul style={{ listStyle: 'none', padding: 0, color: 'var(--muted-foreground, #777)' }}>
            {archived.map((row) => (
              <li key={row.recordId} style={{ padding: '0.4rem 0.8rem' }}>
                {row.data.name}
              </li>
            ))}
          </ul>
        </>
      )}
    </main>
  )
}
