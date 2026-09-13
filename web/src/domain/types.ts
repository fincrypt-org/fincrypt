/**
 * Domain types (C2.8): the plaintext shapes that live INSIDE envelope
 * ciphertext. The server never sees any of these fields.
 */

export interface AccountData {
  name: string
  currency: string // ISO 4217
  openingBalance: number // minor units? No — major units, 2dp-decimal string to avoid float drift
  institutionNote: string
  archived: boolean
}

export interface TransactionData {
  accountId: string // the parent account's record id
  description: string
  amount: number // signed: positive = inflow, negative = outflow
  currency: string
  date: string // ISO yyyy-mm-dd (deterministic column twin)
  category: string
  /** set on BOTH legs when this row is part of a transfer pair */
  transferGroup: string | null
  source: 'manual' | 'scan' | 'csv' | 'plaid'
}

export interface ChatMessageData {
  role: 'user' | 'assistant'
  content: string
}

/** record type → payload type mapping (compile-time routing). */
export interface DataByType {
  accounts: AccountData
  transactions: TransactionData
  chat: ChatMessageData
}

export type SyncableType = keyof DataByType

export function isSyncableType(t: string): t is SyncableType {
  return t === 'accounts' || t === 'transactions' || t === 'chat'
}

/** newTransferGroup mints the client-generated transfer pairing id. */
export function newTransferGroup(): string {
  return crypto.randomUUID()
}
