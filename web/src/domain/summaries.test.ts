/**
 * Summaries golden tests (C2.9): fixed fixture rows → exact totals.
 * The totals are committed here as golden values (claims → tests).
 */
import { describe, expect, it } from 'vitest'
import { byCategoryMonth, monthlyTotals, budgetStatus, type BudgetLine } from './summaries'
import type { TransactionData } from './types'

const rows: TransactionData[] = [
  {
    accountId: 'a',
    description: 'salary',
    amount: 3000,
    currency: 'USD',
    date: '2026-08-01',
    category: 'income',
    transferGroup: null,
    source: 'manual',
  },
  {
    accountId: 'a',
    description: 'rent',
    amount: -1200,
    currency: 'USD',
    date: '2026-08-02',
    category: 'housing',
    transferGroup: null,
    source: 'manual',
  },
  {
    accountId: 'a',
    description: 'groceries 1',
    amount: -150.25,
    currency: 'USD',
    date: '2026-08-10',
    category: 'food',
    transferGroup: null,
    source: 'manual',
  },
  {
    accountId: 'a',
    description: 'groceries 2',
    amount: -89.75,
    currency: 'USD',
    date: '2026-08-20',
    category: 'food',
    transferGroup: null,
    source: 'manual',
  },
  {
    accountId: 'a',
    description: 'salary',
    amount: 3000,
    currency: 'USD',
    date: '2026-09-01',
    category: 'income',
    transferGroup: null,
    source: 'manual',
  },
  {
    accountId: 'a',
    description: 'rent',
    amount: -1200,
    currency: 'USD',
    date: '2026-09-02',
    category: 'housing',
    transferGroup: null,
    source: 'manual',
  },
  {
    accountId: 'a',
    description: 'transfer out',
    amount: -200,
    currency: 'USD',
    date: '2026-09-03',
    category: 'transfers',
    transferGroup: 'g1',
    source: 'manual',
  },
  {
    accountId: 'b',
    description: 'transfer in',
    amount: 200,
    currency: 'USD',
    date: '2026-09-03',
    category: 'transfers',
    transferGroup: 'g1',
    source: 'manual',
  },
]

describe('byCategoryMonth', () => {
  it('produces golden per-category totals', () => {
    const result = byCategoryMonth(rows)
    expect(result).toEqual([
      { month: '2026-08', category: 'food', expense: 240, income: 0 },
      { month: '2026-08', category: 'housing', expense: 1200, income: 0 },
      { month: '2026-08', category: 'income', expense: 0, income: 3000 },
      { month: '2026-09', category: 'housing', expense: 1200, income: 0 },
      { month: '2026-09', category: 'income', expense: 0, income: 3000 },
      { month: '2026-09', category: 'transfers', expense: 200, income: 200 },
    ])
  })
})

describe('monthlyTotals', () => {
  it('nets income − expense per month', () => {
    const result = monthlyTotals(rows)
    expect(result).toEqual([
      { month: '2026-08', income: 3000, expense: 1440, net: 1560 },
      { month: '2026-09', income: 3200, expense: 1400, net: 1800 },
    ])
  })
})

describe('budgetStatus', () => {
  const budgets: BudgetLine[] = [
    { category: 'food', cap: 300 },
    { category: 'housing', cap: 1100 },
    { category: 'dining', cap: 100 },
  ]

  it('flags over-budget categories for the month', () => {
    const status = budgetStatus(rows, '2026-08', budgets)
    expect(status).toEqual([
      { category: 'housing', cap: 1100, actual: 1200, ratio: 1.0909090909090908, over: true },
      { category: 'food', cap: 300, actual: 240, ratio: 0.8, over: false },
      { category: 'dining', cap: 100, actual: 0, ratio: 0, over: false },
    ])
  })

  it('reports 0 actual for months with no spend in a budgeted category', () => {
    const status = budgetStatus(rows, '2026-07', budgets)
    expect(status.every((s) => s.actual === 0 && !s.over)).toBe(true)
  })
})
