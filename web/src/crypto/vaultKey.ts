/**
 * Vault key envelope: DEK generation and double wrap/unwrap.
 *
 * - DEK: 32 random bytes, generated on-device.
 * - Wrapped under the passphrase KEK  -> users.wrapped_dek
 * - Wrapped under the recovery KEK    -> users.wrapped_dek_recovery
 * - Packing format for both: nonce(12) || AES-GCM ciphertext+tag, with
 *   fixed AAD labels (`fincrypt-wrap-v1:dek` / `fincrypt-wrap-v1:dek-recovery`)
 *   so a wrapped DEK can never be replayed as the other kind.
 *
 * Per-purpose subkeys: HKDF-SHA256 off the DEK with info = record_type,
 * so a leaked domain key cannot decrypt anything else. The raw DEK is
 * never used for AEAD directly.
 */
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { decrypt, encrypt, importAesKey, type RecordType } from './aead'

const DEK_BYTES = 32
const WRAP_AAD_DEK = 'fincrypt-wrap-v1:dek'
const WRAP_AAD_RECOVERY = 'fincrypt-wrap-v1:dek-recovery'

/** The DEK material. Treat as secret; never log, never persist unwrapped. */
export type RawDek = Uint8Array

/** Generate a fresh 32-byte DEK on-device. */
export function generateDek(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(DEK_BYTES))
}

/**
 * wrapDek seals the DEK under an AES-256-GCM wrapping key (the KEK),
 * returning nonce||ciphertext ready for bytea storage.
 */
export async function wrapDek(kek: CryptoKey, dek: Uint8Array): Promise<Uint8Array> {
  if (dek.length !== DEK_BYTES) throw new Error(`vaultKey: DEK must be ${DEK_BYTES} bytes`)
  return encrypt(kek, dek, WRAP_AAD_DEK)
}

/**
 * unwrapDek opens a wrapped DEK. Wrong KEK or tampering throws —
 * the caller maps that to "wrong passphrase" / "invalid recovery phrase".
 */
export async function unwrapDek(kek: CryptoKey, wrapped: Uint8Array): Promise<Uint8Array> {
  const dek = await decrypt(kek, wrapped, WRAP_AAD_DEK)
  if (dek.length !== DEK_BYTES) throw new Error('vaultKey: unwrapped DEK has wrong length')
  return dek
}

/** Recovery-phrase wrap/unwrap use the same packing with a distinct AAD label. */
export async function wrapDekWithRecovery(
  recoveryKek: CryptoKey,
  dek: Uint8Array,
): Promise<Uint8Array> {
  if (dek.length !== DEK_BYTES) throw new Error(`vaultKey: DEK must be ${DEK_BYTES} bytes`)
  return encrypt(recoveryKek, dek, WRAP_AAD_RECOVERY)
}

export async function unwrapDekWithRecovery(
  recoveryKek: CryptoKey,
  wrapped: Uint8Array,
): Promise<Uint8Array> {
  const dek = await decrypt(recoveryKek, wrapped, WRAP_AAD_RECOVERY)
  if (dek.length !== DEK_BYTES) throw new Error('vaultKey: unwrapped DEK has wrong length')
  return dek
}

/**
 * deriveDomainKey extracts the per-purpose AES-256-GCM key for a record
 * type via HKDF-SHA256(DEK, salt=empty, info=recordType).
 * The raw DEK never encrypts application data.
 */
export async function deriveDomainKey(dek: Uint8Array, recordType: RecordType): Promise<CryptoKey> {
  const subkey = hkdf(sha256, dek, new Uint8Array(0), new TextEncoder().encode(recordType), 32)
  return importAesKey(subkey)
}

/** Import a KEK (raw 32 bytes from the KDF) for wrap/unwrap operations. */
export async function importKek(kekBytes: Uint8Array): Promise<CryptoKey> {
  return importAesKey(kekBytes)
}
