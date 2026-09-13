/**
 * Transactions page (C2.8): virtualized list (@tanstack/react-virtual)
 * over the decrypted working set; manual entry (decision #14 — offline
 * floor); transfers create two linked rows sharing a transfer_group.
 */
import { useEffect, useMemo, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useVirtualizer } from '@tanstack/react-virtual'
import { saveRecord, deleteRecord, loadWorking } from '../domain/store'
import { newTransferGroup, type TransactionData, type AccountData } from '../domain/types'

interface TxnRow {
  recordId: string
  data: TransactionData
  ts: string
}

export default function TransactionsPage() {
  const [params] = useSearchParams()
  const accountFilter = params.get('account')
  const [rows, setRows] = useState<TxnRow[]>([])
  const [accounts, setAccounts] = useState<Array<{ recordId: string; data: AccountData }>>([])
  const [editing, setEditing] = useState<TxnRow | null>(null)
  const [creating, setCreating] = useState(false)
  const listRef = useRef<HTMLDivElement>(null)

  async function reload() {
    const txns = await loadWorking('transactions')
    const accts = await loadWorking('accounts')
    setRows(
      (txns as Array<{ recordId: string; data: TransactionData; ts: string }>).sort((a, b) =>
        b.data.date.localeCompare(a.data.date),
      ),
    )
    setAccounts(accts as Array<{ recordId: string; data: AccountData }>)
  }

  useEffect(() => {
    void reload()
  }, [])

  const visible = useMemo(
    () => rows.filter((r) => accountFilter == null || r.data.accountId === accountFilter),
    [rows, accountFilter],
  )

  const virtualizer = useVirtualizer({
    count: visible.length,
    getScrollElement: () => listRef.current,
    estimateSize: () => 44,
    overscan: 10,
  })

  const accountName = (id: string) =>
    accounts.find((a) => a.recordId === id)?.data.name ?? '(unknown account)'

  async function onSave(data: TransactionData, recordId?: string) {
    await saveRecord({
      type: 'transactions',
      recordId: recordId ?? crypto.randomUUID(),
      data,
      ts: recordId != null ? new Date(Date.now() + 1).toISOString() : undefined,
    })
    setEditing(null)
    setCreating(false)
    await reload()
  }

  async function onDelete(row: TxnRow) {
    await deleteRecord('transactions', row.recordId)
    // if this row is one leg of a transfer, flag-delete the partner too:
    // both legs share transfer_group; deleting one flags the pair (spec)
    if (row.data.transferGroup != null) {
      const partner = rows.find(
        (r) => r.recordId !== row.recordId && r.data.transferGroup === row.data.transferGroup,
      )
      if (partner != null) {
        await deleteRecord('transactions', partner.recordId)
      }
    }
    await reload()
  }

  return (
    <main style={{ padding: '2rem', maxWidth: 1200 }}>
      <h1>Transactions</h1>
      <div style={{ margin: '1rem 0', display: 'flex', gap: '0.75rem' }}>
        <button
          onClick={() => setCreating(true)}
          style={{ padding: '0.5rem 1rem', cursor: 'pointer' }}
        >
          Add transaction
        </button>
        <a href="/accounts" style={{ alignSelf: 'center' }}>
          ← Accounts
        </a>
      </div>

      {(creating || editing != null) && (
        <TransactionForm
          accounts={accounts}
          initial={editing?.data}
          onSubmit={(data) => {
            void onSave(data, editing?.recordId).then(() => undefined)
          }}
          onCancel={() => {
            setCreating(false)
            setEditing(null)
          }}
        />
      )}

      {rows.length === 0 ? (
        <p style={{ color: 'var(--muted-foreground, #777)' }}>No transactions yet.</p>
      ) : (
        <div
          ref={listRef}
          style={{
            maxHeight: 520,
            overflow: 'auto',
            maxWidth: 960,
            border: '1px solid var(--border, #e5e5e5)',
          }}
        >
          <div style={{ height: visible.length * 44, position: 'relative' }}>
            {virtualizer.getVirtualItems().map((vi) => {
              const row = visible[vi.index]
              if (row == null) return null
              return (
                <div
                  key={row.recordId}
                  style={{
                    position: 'absolute',
                    top: 0,
                    left: 0,
                    width: '100%',
                    height: vi.size,
                    transform: `translateY(${vi.start}px)`,
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    padding: '0 0.8rem',
                    borderBottom: '1px solid var(--border, #eee)',
                    boxSizing: 'border-box',
                  }}
                >
                  <span style={{ minWidth: 110 }}>{row.data.date}</span>
                  <span style={{ flex: 1, padding: '0 1rem' }}>
                    {row.data.description}
                    {row.data.transferGroup != null && (
                      <span style={{ color: 'var(--muted-foreground, #999)', marginLeft: 8 }}>
                        (transfer)
                      </span>
                    )}
                    <span style={{ color: 'var(--muted-foreground, #888)', marginLeft: 8 }}>
                      {accountFilter == null ? accountName(row.data.accountId) : ''}
                    </span>
                  </span>
                  <span
                    style={{
                      color: row.data.amount >= 0 ? '#1a7f37' : '#c0392b',
                      fontVariantNumeric: 'tabular-nums',
                      minWidth: 110,
                      textAlign: 'right',
                    }}
                  >
                    {row.data.amount >= 0 ? '+' : ''}
                    {row.data.amount.toFixed(2)} {row.data.currency}
                  </span>
                  <span style={{ display: 'flex', gap: '0.5rem', marginLeft: '0.75rem' }}>
                    <button onClick={() => setEditing(row)} style={{ cursor: 'pointer' }}>
                      Edit
                    </button>
                    <button onClick={() => void onDelete(row)} style={{ cursor: 'pointer' }}>
                      Delete
                    </button>
                  </span>
                </div>
              )
            })}
          </div>
        </div>
      )}
    </main>
  )
}

// ─── form ────────────────────────────────────────────────────────────

function TransactionForm(props: {
  accounts: Array<{ recordId: string; data: AccountData }>
  initial?: TransactionData
  onSubmit: (data: TransactionData) => void
  onCancel: () => void
}) {
  const [description, setDescription] = useState(props.initial?.description ?? '')
  const [amount, setAmount] = useState(props.initial?.amount?.toString() ?? '')
  const [date, setDate] = useState(props.initial?.date ?? new Date().toISOString().slice(0, 10))
  const [accountId, setAccountId] = useState(
    props.initial?.accountId ?? props.accounts[0]?.recordId ?? '',
  )
  const [category, setCategory] = useState(props.initial?.category ?? '')
  const [asTransfer, setAsTransfer] = useState(false)
  const [targetAccount, setTargetAccount] = useState('')

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    const amountNum = Number(amount)
    if (Number.isNaN(amountNum)) return
    const now = new Date().toISOString()
    if (asTransfer) {
      const group = newTransferGroup()
      // two linked rows: outflow from source, inflow to target
      await saveRecord({
        type: 'transactions',
        recordId: crypto.randomUUID(),
        data: {
          accountId,
          description: description || 'Transfer out',
          amount: -Math.abs(amountNum),
          currency: props.accounts.find((a) => a.recordId === accountId)?.data.currency ?? 'USD',
          date,
          category,
          transferGroup: group,
          source: 'manual',
        },
      })
      await saveRecord({
        type: 'transactions',
        recordId: crypto.randomUUID(),
        data: {
          accountId: targetAccount,
          description: description || 'Transfer in',
          amount: Math.abs(amountNum),
          currency:
            props.accounts.find((a) => a.recordId === targetAccount)?.data.currency ?? 'USD',
          date,
          category,
          transferGroup: group,
          source: 'manual',
        },
        ts: now,
      })
    } else {
      await saveRecord({
        type: 'transactions',
        recordId: crypto.randomUUID(),
        data: {
          accountId,
          description,
          amount: amountNum,
          currency: props.accounts.find((a) => a.recordId === accountId)?.data.currency ?? 'USD',
          date,
          category,
          transferGroup: null,
          source: 'manual',
        },
      })
    }
    props.onSubmit({
      accountId,
      description,
      amount: amountNum,
      currency: 'USD',
      date,
      category,
      transferGroup: null,
      source: 'manual',
    })
  }

  return (
    <form
      onSubmit={(e) => void submit(e)}
      style={{
        display: 'grid',
        gap: '0.6rem',
        maxWidth: 480,
        padding: '1rem',
        border: '1px solid var(--border, #ddd)',
        marginBottom: '1.5rem',
      }}
    >
      <label>
        Description
        <input
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          required
          style={{ display: 'block', width: '100%', padding: '0.4rem' }}
        />
      </label>
      <label>
        Amount (negative = outflow)
        <input
          value={amount}
          onChange={(e) => setAmount(e.target.value)}
          required
          style={{ display: 'block', width: '100%', padding: '0.4rem' }}
        />
      </label>
      <label>
        Date
        <input
          type="date"
          value={date}
          onChange={(e) => setDate(e.target.value)}
          required
          style={{ display: 'block', width: '100%', padding: '0.4rem' }}
        />
      </label>
      <label>
        Account
        <select
          value={accountId}
          onChange={(e) => setAccountId(e.target.value)}
          style={{ display: 'block', width: '100%', padding: '0.4rem' }}
        >
          {props.accounts.map((a) => (
            <option key={a.recordId} value={a.recordId}>
              {a.data.name}
            </option>
          ))}
        </select>
      </label>
      <label>
        Category
        <input
          value={category}
          onChange={(e) => setCategory(e.target.value)}
          style={{ display: 'block', width: '100%', padding: '0.4rem' }}
        />
      </label>
      <label style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
        <input
          type="checkbox"
          checked={asTransfer}
          onChange={(e) => setAsTransfer(e.target.checked)}
        />
        Transfer (creates the paired row)
      </label>
      {asTransfer && (
        <label>
          To account
          <select
            value={targetAccount}
            onChange={(e) => setTargetAccount(e.target.value)}
            style={{ display: 'block', width: '100%', padding: '0.4rem' }}
          >
            {props.accounts
              .filter((a) => a.recordId !== accountId)
              .map((a) => (
                <option key={a.recordId} value={a.recordId}>
                  {a.data.name}
                </option>
              ))}
          </select>
        </label>
      )}
      <div style={{ display: 'flex', gap: '0.5rem' }}>
        <button type="submit" style={{ padding: '0.5rem 1rem', cursor: 'pointer' }}>
          Save
        </button>
        <button
          type="button"
          onClick={props.onCancel}
          style={{ padding: '0.5rem 1rem', cursor: 'pointer' }}
        >
          Cancel
        </button>
      </div>
    </form>
  )
}
