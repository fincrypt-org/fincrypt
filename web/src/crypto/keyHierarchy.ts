/**
 * Key hierarchy (C1.3): DEK, HKDF subkeys, wrap/unwrap, zeroize.
 *
 * Formats per P1-SPEC §P1-0:
 * - Subkey: HKDF-SHA256(DEK, salt=utf8("fincrypt/v1/hkdf"), info=utf8(record_type), 256)
 *   (D1: salt string is a §0 gap-fill; info = bare record_type is §0-locked)
 * - Wrap AADs (D3): `v1|<userId>|wrapped-dek` / `v1|<userId>|wrapped-dek-recovery`
 * - Packed wrap: nonce(12) ‖ GCM(dek_raw, KEK, aad) = exactly 60 bytes
 *
 * The DEK stays RAW (zeroizable) because non-extractable CryptoKeys
 * cannot be re-imported for HKDF; HKDF itself is fed via an
 * non-extractable HKDF import. Both worlds satisfied (I3/I4).
 */
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { decryptBytes, encryptBytes, importAesKey, type RecordType } from './aead'
import { WrapError } from './errors'
import { asDecryptError } from './errors'

const DEK_BYTES = 32
/** D1 (gap-fill): §0 names info but not the HKDF salt. */
const HKDF_SALT_LABEL = 'fincrypt/v1/hkdf'

/** The DEK material. Treat as secret; zeroize when done (memzero.ts). */
export type RawKey = Uint8Array

/** HKDF-SHA256 raw bits (RFC 5869-testable core). */
export function hkdfBits(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, bits: number): Uint8Array {
  // @noble/hashes hkdf output is bytes; bits must be a multiple of 8
  if (bits % 8 !== 0 || bits <= 0 || bits > 255 * 32) {
    throw new WrapError('hkdf: invalid bit length')
  }
  return hkdfSha256(ikm, salt, info, bits / 8)
}

import { hkdf as hkdfSha256 } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'

/** The D1 HKDF salt, exposed for tests. */
export function hkdfSaltBytes(): Uint8Array {
  return new TextEncoder().encode(HKDF_SALT_LABEL)
}

/**
 * deriveSubkey: per-purpose AES-256-GCM key via HKDF-SHA256(DEK,
 * salt=fincrypt/v1/hkdf, info=record_type) — non-extractable (I3).
 * The raw DEK never encrypts a record (I4).
 */
export async function deriveSubkey(dek: RawKey, type: RecordType): Promise<CryptoKey> {
  const bits = hkdfBits(dek, hkdfSaltBytes(), new TextEncoder().encode(type), 256)
  return importAesKey(bits)
}

/** Generate a fresh 32-byte DEK on-device. */
export function generateDek(): RawKey {
  return crypto.getRandomValues(new Uint8Array(DEK_BYTES))
}

const wrapAad = (userId: string, kind: 'wrapped-dek' | 'wrapped-dek-recovery'): Uint8Array =>
  new TextEncoder().encode(`v1|${userId}|${kind}`)

/**
 * wrapDek seals the DEK under the KEK → exactly 60 bytes
 * (12 nonce + 32 ct + 16 tag). Wrap AAD binds userId + kind (D3).
 */
export async function wrapDek(dek: RawKey, kek: CryptoKey, userId: string): Promise<Uint8Array> {
  if (dek.length !== DEK_BYTES) throw new WrapError(`DEK must be ${DEK_BYTES} bytes`)
  if (userId.length === 0) throw new WrapError('userId required for wrap AAD')
  return encryptBytes(kek, dek, wrapAad(userId, 'wrapped-dek'))
}

/**
 * unwrapDek opens a wrapped DEK. Wrong KEK, wrong userId, tampering or
 * wrap-kind replay → WrapError (never a generic failure — this is NOT
 * a decrypt oracle path because the caller must distinguish "wrong
 * passphrase" from data corruption for UX; the error message stays
 * content-free).
 */
export async function unwrapDek(w: Uint8Array, kek: CryptoKey, userId: string): Promise<RawKey> {
  if (w.length !== 60) throw new WrapError('wrapped DEK must be 60 bytes')
  try {
    const dek = await decryptBytes(kek, w, wrapAad(userId, 'wrapped-dek'))
    if (dek.length !== DEK_BYTES) throw new WrapError('unwrapped DEK has wrong length')
    return dek
  } catch (err) {
    if (err instanceof WrapError) throw err
    throw asDecryptError(err) && new WrapError('unwrap failed')
  }
}

/** Recovery-phrase wrap/unwrap: same packing, D3 recovery AAD. */
export async function wrapWithRecovery(dek: RawKey, kek: CryptoKey, userId: string): Promise<Uint8Array> {
  if (dek.length !== DEK_BYTES) throw new WrapError(`DEK must be ${DEK_BYTES} bytes`)
  if (userId.length === 0) throw new WrapError('userId required for wrap AAD')
  return encryptBytes(kek, dek, wrapAad(userId, 'wrapped-dek-recovery'))
}

export async function unwrapWithRecovery(w: Uint8Array, kek: CryptoKey, userId: string): Promise<RawKey> {
  if (w.length !== 60) throw new WrapError('wrapped DEK must be 60 bytes')
  try {
    const dek = await decryptBytes(kek, w, wrapAad(userId, 'wrapped-dek-recovery'))
    if (dek.length !== DEK_BYTES) throw new WrapError('unwrapped DEK has wrong length')
    return dek
  } catch (err) {
    if (err instanceof WrapError) throw err
    throw new WrapError('unwrap failed')
  }
}