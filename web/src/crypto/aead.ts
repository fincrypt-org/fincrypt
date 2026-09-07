/**
 * AEAD layer: AES-256-GCM with MANDATORY associated data.
 *
 * Every ciphertext is bound to `v1|user_id|record_type|record_id` —
 * swapping ciphertexts between records must fail decryption. The AAD
 * builder here is the only way to produce one, so the format can't
 * drift call-site by call-site.
 *
 * Envelope JSON per row (plan §0):
 *   { record_id, type, nonce, ciphertext, aad, ts } — codec in envelope.ts
 *
 * Error-oracle rule (I6): every decrypt failure throws ONE generic
 * DecryptError — never distinguish tamper vs AAD mismatch vs wrong key.
 */
import { DecryptError, asDecryptError } from './errors'

const NONCE_BYTES = 12
const TAG_BITS = 128

/** Record types that may appear in AAD — kept in one place so the AAD grammar is total. */
export const RECORD_TYPES = ['transactions', 'attachments', 'chat', 'accounts', 'vault'] as const
export type RecordType = (typeof RECORD_TYPES)[number]

/**
 * buildAad constructs the mandatory AAD bytes for a record.
 * Format: `v1|<user_id>|<record_type>|<record_id>`
 */
export function buildAad(userId: string, recordType: RecordType, recordId: string): Uint8Array {
  for (const part of [userId, recordId]) {
    if (part.length === 0 || part.includes('|')) {
      throw new Error(`aead: invalid AAD component (empty or contains '|')`)
    }
  }
  if (!RECORD_TYPES.includes(recordType)) {
    throw new Error(`aead: unknown record type`)
  }
  return new TextEncoder().encode(`v1|${userId}|${recordType}|${recordId}`)
}

/** The AAD string (for the envelope's `aad` field) — same grammar, string form. */
export function buildAadString(userId: string, recordType: RecordType, recordId: string): string {
  return new TextDecoder().decode(buildAad(userId, recordType, recordId))
}

/**
 * encryptBytes AES-256-GCM with a fresh random 12-byte nonce.
 * Returns nonce || ciphertext‖tag. aad is mandatory bytes.
 */
export async function encryptBytes(
  key: CryptoKey,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  if (aad.length === 0) throw new Error('aead: AAD is mandatory')
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES))
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: aad as BufferSource, tagLength: 128 },
      key,
      plaintext as BufferSource,
    ),
  )
  const packed = new Uint8Array(NONCE_BYTES + ct.length)
  packed.set(nonce, 0)
  packed.set(ct, NONCE_BYTES)
  return packed
}

/**
 * decryptBytes opens a packed nonce||ciphertext blob against the exact
 * AAD bytes. Any failure → DecryptError (no oracle).
 */
export async function decryptBytes(
  key: CryptoKey,
  packed: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  if (aad.length === 0) throw new Error('aead: AAD is mandatory')
  if (packed.length <= NONCE_BYTES) throw asDecryptError(new Error('short'))
  const nonce = packed.slice(0, NONCE_BYTES)
  const ct = packed.slice(NONCE_BYTES)
  try {
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: aad as BufferSource, tagLength: 128 },
      key,
      ct as BufferSource,
    )
    return new Uint8Array(pt)
  } catch {
    throw new DecryptError()
  }
}

/** Import raw 32 key bytes as a non-extractable AES-256-GCM CryptoKey (I3). */
export async function importAesKey(raw: Uint8Array): Promise<CryptoKey> {
  if (raw.length !== 32) throw new Error(`aead: key must be 32 bytes (got ${raw.length})`)
  return crypto.subtle.importKey('raw', raw as BufferSource, { name: 'AES-GCM' }, false, [
    'encrypt',
    'decrypt',
  ])
}