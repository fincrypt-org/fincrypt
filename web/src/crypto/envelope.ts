/**
 * Envelope codec (C1.2) — PLAN §0 verbatim:
 *   { record_id, type, nonce, ciphertext, aad, ts }  — NO `v` field.
 *
 * `nonce` and `ciphertext` are b64 (RFC 4648 padded); `ciphertext` is
 * the WebCrypto GCM output ct‖tag, never split. Serialized with a
 * FIXED key order so the JSON is byte-stable across runs — the golden
 * vector target (C1.8) and P5's enclave work depend on it.
 */
import { InvalidEnvelopeError } from './errors'
import { fromB64, toB64 } from './b64'
import type { RecordType } from './aead'

export interface Envelope {
  record_id: string
  type: RecordType
  /** raw 12-byte nonce (unpacked) */
  nonce: Uint8Array
  /** raw ct‖tag (unpacked) */
  ciphertext: Uint8Array
  /** the AAD string used for this record (mandatory, non-empty) */
  aad: string
  /** advisory RFC 3339 timestamp; server stamps its own in P2 */
  ts: string
}

/** Fixed key order for byte-stable serialization. */
const ENVELOPE_KEYS = ['record_id', 'type', 'nonce', 'ciphertext', 'aad', 'ts'] as const

export function serializeEnvelope(env: Envelope): Uint8Array {
  // Hand-rolled fixed-order JSON to guarantee byte stability across
  // JS engines (JSON.stringify follows insertion order; we control it).
  const parts: string[] = []
  for (const key of ENVELOPE_KEYS) {
    let value: string
    switch (key) {
      case 'record_id':
        value = env.record_id
        break
      case 'type':
        value = env.type
        break
      case 'nonce':
        value = toB64(env.nonce)
        break
      case 'ciphertext':
        value = toB64(env.ciphertext)
        break
      case 'aad':
        value = env.aad
        break
      case 'ts':
        value = env.ts
        break
      default: {
        const _exhaustive: never = key
        void _exhaustive
        throw new Error('unreachable')
      }
    }
    parts.push(`${JSON.stringify(key)}:${JSON.stringify(value)}`)
  }
  const json = `{${parts.join(',')}}`
  return new TextEncoder().encode(json)
}

/** Known record types — must match aead.ts RECORD_TYPES (single grammar). */
const KNOWN_TYPES = new Set(['transactions', 'attachments', 'chat', 'accounts', 'vault'])

/** Shape-strict parse: rejects unknown fields, missing fields, wrong types. */
export function parseEnvelope(bytes: Uint8Array): Envelope {
  let parsed: Record<string, unknown>
  try {
    parsed = JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>
  } catch {
    throw new InvalidEnvelopeError('envelope is not valid JSON')
  }
  const keys = Object.keys(parsed)
  if (keys.length !== ENVELOPE_KEYS.length || !ENVELOPE_KEYS.every((k) => k in parsed)) {
    throw new InvalidEnvelopeError('envelope fields do not match the v1 shape')
  }
  for (const k of keys) {
    if (!ENVELOPE_KEYS.includes(k as (typeof ENVELOPE_KEYS)[number])) {
      throw new InvalidEnvelopeError('envelope has unknown fields')
    }
  }
  const { record_id, type, nonce, ciphertext, aad, ts } = parsed
  if (typeof record_id !== 'string' || record_id.length === 0) {
    throw new InvalidEnvelopeError('envelope record_id missing')
  }
  if (typeof type !== 'string' || !KNOWN_TYPES.has(type)) {
    throw new InvalidEnvelopeError('envelope type unknown')
  }
  if (typeof aad !== 'string' || aad.length === 0) {
    throw new InvalidEnvelopeError('envelope aad missing')
  }
  if (typeof ts !== 'string') {
    throw new InvalidEnvelopeError('envelope ts missing')
  }
  if (typeof nonce !== 'string') throw new InvalidEnvelopeError('envelope nonce missing')
  if (typeof ciphertext !== 'string') throw new InvalidEnvelopeError('envelope ciphertext missing')
  const nonceBytes = fromB64(nonce)
  if (nonceBytes.length !== 12) throw new InvalidEnvelopeError('envelope nonce must be 12 bytes')
  const ctBytes = fromB64(ciphertext)
  if (ctBytes.length < 16) throw new InvalidEnvelopeError('envelope ciphertext too short')
  return {
    record_id,
    type: type as RecordType,
    nonce: nonceBytes,
    ciphertext: ctBytes,
    aad,
    ts,
  }
}