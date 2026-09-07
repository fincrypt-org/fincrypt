/**
 * AEAD layer: AES-256-GCM with MANDATORY associated data.
 *
 * Every ciphertext is bound to `v1|user_id|record_type|record_id` —
 * swapping ciphertexts between records must fail decryption. The AAD
 * builder here is the only way to produce one, so the format can't
 * drift call-site by call-site.
 *
 * Envelope JSON per row (plan §0):
 *   { record_id, type, nonce, ciphertext, aad, ts }
 * This module handles the nonce‖ciphertext byte-packing; the envelope
 * object shape is defined in types.ts.
 */

const NONCE_BYTES = 12
const TAG_BITS = 128

/** Record types that may appear in AAD — kept in one place so the AAD grammar is total. */
export const RECORD_TYPES = ['transactions', 'attachments', 'chat', 'accounts', 'vault'] as const
export type RecordType = (typeof RECORD_TYPES)[number]

/**
 * buildAad constructs the mandatory AAD string for a record.
 * Format: `v1|<user_id>|<record_type>|<record_id>`
 */
export function buildAad(userId: string, recordType: RecordType, recordId: string): string {
  for (const part of [userId, recordId]) {
    if (part.length === 0 || part.includes('|')) {
      throw new Error(`aead: invalid AAD component ${JSON.stringify(part)} (empty or contains '|')`)
    }
  }
  if (!RECORD_TYPES.includes(recordType)) {
    throw new Error(`aead: unknown record type ${recordType}`)
  }
  return `v1|${userId}|${recordType}|${recordId}`
}

/**
 * encrypt AES-256-GCM with a fresh random 12-byte nonce.
 * Returns nonce || ciphertext (tag appended, WebCrypto convention).
 * aad must be a non-empty AAD string from buildAad — this parameter is
 * deliberately not optional.
 */
export async function encrypt(
  key: CryptoKey,
  plaintext: Uint8Array,
  aad: string,
): Promise<Uint8Array> {
  if (aad.length === 0) throw new Error('aead: AAD is mandatory')
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES))
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: nonce,
        additionalData: new TextEncoder().encode(aad),
        tagLength: TAG_BITS,
      },
      key,
      plaintext as BufferSource,
    ),
  )
  // pack: nonce(12) || ciphertext
  const packed = new Uint8Array(NONCE_BYTES + ct.length)
  packed.set(nonce, 0)
  packed.set(ct, NONCE_BYTES)
  return packed
}

/**
 * decrypt verifies and opens a packed nonce||ciphertext blob against
 * the exact AAD string. Any AAD mismatch (or tampering) throws.
 */
export async function decrypt(
  key: CryptoKey,
  packed: Uint8Array,
  aad: string,
): Promise<Uint8Array> {
  if (aad.length === 0) throw new Error('aead: AAD is mandatory')
  if (packed.length <= NONCE_BYTES) throw new Error('aead: ciphertext too short')
  const nonce = packed.slice(0, NONCE_BYTES)
  const ct = packed.slice(NONCE_BYTES)
  const pt = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
      additionalData: new TextEncoder().encode(aad),
      tagLength: TAG_BITS,
    },
    key,
    ct as BufferSource,
  )
  return new Uint8Array(pt)
}

/** Import raw 32 key bytes as an AES-256-GCM CryptoKey. */
export async function importAesKey(raw: Uint8Array): Promise<CryptoKey> {
  if (raw.length !== 32) throw new Error(`aead: key must be 32 bytes (got ${raw.length})`)
  return crypto.subtle.importKey('raw', raw as BufferSource, { name: 'AES-GCM' }, false, [
    'encrypt',
    'decrypt',
  ])
}
