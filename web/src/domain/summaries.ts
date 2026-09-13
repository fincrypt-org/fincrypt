/**
 * Summaries (C2.9): pure functions over decrypted transactions —
 * monthly by category, income vs expense, cash flow. Client-computed
 * only; the server never sees any of this. Golden totals come from
 * committed fixtures (claims → tests).
 */
import type { TransactionData } from './types'

export interface CategoryMonth {
  month: string // yyyy-mm
  category: string
  /** sum of NEGATIVE amounts (outflows), reported positive */
  expense: number
  /** sum of POSITIVE amounts for the category */
  income: number
}

/** byCategoryMonth groups expense/income per (month, category). */
export function byCategoryMonth(rows: TransactionData[]): CategoryMonth[] {
  const map = new Map<string, CategoryMonth>()
  for (const r of rows) {
    const month = r.date.slice(0, 7)
    const key = month + '|' + r.category
    let entry = map.get(key)
    if (entry == null) {
      entry = { month, category: r.category, expense: 0, income: 0 }
      map.set(key, entry)
    }
    if (r.amount < 0) entry.expense += -r.amount
    else entry.income += r.amount
  }
  return [...map.values()].sort((a, b) =>
    a.month === b.month ? a.category.localeCompare(b.category) : a.month.localeCompare(b.month),
  )
}

export interface MonthTotals {
  month: string
  income: number
  expense: number
  /** income − expense */
  net: number
}

/** monthlyTotals collapses all categories per month. */
export function monthlyTotals(rows: TransactionData[]): MonthTotals[] {
  const map = new Map<string, MonthTotals>()
  for (const r of rows) {
    const month = r.date.slice(0, 7)
    let entry = map.get(month)
    if (entry == null) {
      entry = { month, income: 0, expense: 0, net: 0 }
      map.set(month, entry)
    }
    if (r.amount < 0) entry.expense += -r.amount
    else entry.income += r.amount
    entry.net = entry.income - entry.expense
  }
  return [...map.values()].sort((a, b) => a.month.localeCompare(b.month))
}

/** budgetStatus compares actual spend against a monthly budget cap. */
export interface BudgetLine {
  category: string
  /** monthly cap, major units */
  cap: number
}

export interface BudgetStatus {
  category: string
  cap: number
  actual: number
  /** actual / cap, capped at 999% for display safety */
  ratio: number
  over: boolean
}

export function budgetStatus(
  rows: TransactionData[],
  month: string,
  budgets: BudgetLine[],
): BudgetStatus[] {
  const spent = new Map<string, number>()
  for (const r of rows) {
    if (r.date.slice(0, 7) !== month || r.amount >= 0) continue
    const cat = r.category === '' ? '(uncategorized)' : r.category
    spent.set(cat, (spent.get(cat) ?? 0) + -r.amount)
  }
  return budgets
    .map((b) => {
      const actual = spent.get(b.category) ?? 0
      return {
        category: b.category,
        cap: b.cap,
        actual,
        ratio: b.cap > 0 ? Math.min(actual / b.cap, 9.99) : actual > 0 ? 9.99 : 0,
        over: actual > b.cap,
      }
    })
    .sort((a, b) => b.actual - a.actual)
}
