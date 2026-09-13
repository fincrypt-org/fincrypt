/**
 * Budgets page (C2.9): budget caps live inside the vault envelope (D5);
 * monthly status is client-computed from decrypted transactions.
 */
import { useEffect, useState } from 'react'
import { loadWorking } from '../domain/store'
import { budgetStatus, type BudgetLine } from '../domain/summaries'
import type { TransactionData } from '../domain/types'

export default function BudgetsPage() {
  const [rows, setRows] = useState<TransactionData[]>([])
  const [budgets, setBudgets] = useState<BudgetLine[]>([])
  const [month, setMonth] = useState(new Date().toISOString().slice(0, 7))
  const [newCategory, setNewCategory] = useState('')
  const [newCap, setNewCap] = useState('')

  useEffect(() => {
    void (async () => {
      const txns = await loadWorking('transactions')
      setRows(txns.map((r) => r.data as TransactionData))
      // Budget caps live in the vault envelope (D5). The vault's client
      // read path lands with the vault editor (P3); in P2 the caps are
      // session-local state — the pure budgetStatus math is the tested unit.
    })()
  }, [])

  async function addBudget(e: React.FormEvent) {
    e.preventDefault()
    const cap = Number(newCap)
    if (newCategory.trim() === '' || Number.isNaN(cap)) return
    const next = [
      ...budgets.filter((b) => b.category !== newCategory.trim()),
      { category: newCategory.trim(), cap },
    ]
    setBudgets(next)
    setNewCategory('')
    setNewCap('')
  }

  const status = budgetStatus(rows, month, budgets)

  return (
    <main style={{ padding: '2rem', maxWidth: 1200 }}>
      <h1>Budgets</h1>
      <label style={{ display: 'block', margin: '1rem 0' }}>
        Month <input type="month" value={month} onChange={(e) => setMonth(e.target.value)} />
      </label>
      <table style={{ borderCollapse: 'collapse', minWidth: 560 }}>
        <thead>
          <tr>
            <th
              style={{
                textAlign: 'left',
                padding: '0.4rem 1rem',
                borderBottom: '2px solid var(--border, #ccc)',
              }}
            >
              Category
            </th>
            <th
              style={{
                textAlign: 'right',
                padding: '0.4rem 1rem',
                borderBottom: '2px solid var(--border, #ccc)',
              }}
            >
              Cap
            </th>
            <th
              style={{
                textAlign: 'right',
                padding: '0.4rem 1rem',
                borderBottom: '2px solid var(--border, #ccc)',
              }}
            >
              Actual
            </th>
            <th
              style={{
                textAlign: 'right',
                padding: '0.4rem 1rem',
                borderBottom: '2px solid var(--border, #ccc)',
              }}
            >
              Status
            </th>
          </tr>
        </thead>
        <tbody>
          {status.map((s) => (
            <tr key={s.category}>
              <td style={{ padding: '0.4rem 1rem', borderBottom: '1px solid var(--border, #eee)' }}>
                {s.category}
              </td>
              <td
                style={{
                  padding: '0.4rem 1rem',
                  textAlign: 'right',
                  borderBottom: '1px solid var(--border, #eee)',
                }}
              >
                {s.cap.toFixed(2)}
              </td>
              <td
                style={{
                  padding: '0.4rem 1rem',
                  textAlign: 'right',
                  borderBottom: '1px solid var(--border, #eee)',
                }}
              >
                {s.actual.toFixed(2)}
              </td>
              <td
                style={{
                  padding: '0.4rem 1rem',
                  borderBottom: '1px solid var(--border, #eee)',
                  color: s.over ? '#c0392b' : '#1a7f37',
                }}
              >
                {s.over ? 'over budget' : Math.round(s.ratio * 100) + '%'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <form
        onSubmit={(e) => void addBudget(e)}
        style={{ display: 'flex', gap: '0.5rem', marginTop: '1.5rem', maxWidth: 480 }}
      >
        <input
          placeholder="Category"
          value={newCategory}
          onChange={(e) => setNewCategory(e.target.value)}
          style={{ flex: 1, padding: '0.4rem' }}
        />
        <input
          placeholder="Monthly cap"
          value={newCap}
          onChange={(e) => setNewCap(e.target.value)}
          style={{ width: 130, padding: '0.4rem' }}
        />
        <button type="submit" style={{ padding: '0.4rem 1rem', cursor: 'pointer' }}>
          Set
        </button>
      </form>
    </main>
  )
}
