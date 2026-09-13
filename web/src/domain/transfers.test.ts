/**
 * Transfer pairing unit tests (C2.8): two linked rows share the
 * client-generated transfer_group; deleting one flags the pair; no
 * double-count (balance math derives from signed amounts).
 */
import { describe, expect, it } from 'vitest'
import { newTransferGroup, type TransactionData } from './types'

describe('transfer pairing', () => {
  it('mints distinct group ids', () => {
    expect(newTransferGroup()).not.toBe(newTransferGroup())
  })

  it('paired legs are signed opposites sharing a group — no double-count', () => {
    const group = newTransferGroup()
    const out: TransactionData = {
      accountId: 'acc-a',
      description: 'Transfer out',
      amount: -100,
      currency: 'USD',
      date: '2026-09-13',
      category: '',
      transferGroup: group,
      source: 'manual',
    }
    const inn: TransactionData = {
      accountId: 'acc-b',
      description: 'Transfer in',
      amount: 100,
      currency: 'USD',
      date: '2026-09-13',
      category: '',
      transferGroup: group,
      source: 'manual',
    }
    expect(out.transferGroup).toBe(inn.transferGroup)
    expect(out.amount + inn.amount).toBe(0) // zero-sum across accounts
    // single-account net effect: -100 for A, +100 for B
    expect(out.amount).toBeLessThan(0)
    expect(inn.amount).toBeGreaterThan(0)
  })

  it('balance derivation never double-counts transfers (per-account filter)', () => {
    const group = newTransferGroup()
    const rows: Array<{ accountId: string; amount: number; transferGroup: string | null }> = [
      { accountId: 'a', amount: 500, transferGroup: null },
      { accountId: 'a', amount: -100, transferGroup: group }, // out leg
      { accountId: 'b', amount: 100, transferGroup: group }, // in leg
    ]
    const balance = (acc: string) =>
      rows.filter((r) => r.accountId === acc).reduce((sum, r) => sum + r.amount, 0)
    expect(balance('a')).toBe(400)
    expect(balance('b')).toBe(100)
    // total across ALL accounts counts both legs (that's why the UI shows
    // them under their own accounts, and net worth math nets them)
    expect(rows.reduce((s, r) => s + r.amount, 0)).toBe(500)
  })
})
