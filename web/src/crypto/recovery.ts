/**
 * Recovery: 12-word BIP39 phrase (mandatory at signup, shown once).
 *
 * The phrase maps to a 64-byte BIP39 seed; the recovery KEK is
 * Argon2id(seed-as-password, fixed app salt) — same KDF policy as the
 * passphrase KEK. The passphrase salt is server-stored per-user; the
 * recovery salt is a fixed domain label because the phrase itself
 * already carries ~128 bits of entropy (no salt uniqueness needed).
 */
import { mnemonicToSeedSync, validateMnemonic, generateMnemonic } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english.js'
import { importAesKey } from './aead'
import { DEFAULT_KDF_PARAMS, deriveKek } from './kdf'

const RECOVERY_SALT_LABEL = 'fincrypt-recovery-kek-v1'

/** generateRecoveryPhrase returns a fresh 12-word phrase (128-bit entropy). */
export function generateRecoveryPhrase(): string {
  return generateMnemonic(wordlist, 128)
}

/** normalizePhrase lowercases and collapses whitespace so restore is forgiving about formatting. */
export function normalizePhrase(phrase: string): string {
  return phrase.trim().toLowerCase().split(/\s+/).filter(Boolean).join(' ')
}

/** validateRecoveryPhrase checks the words against the English wordlist + checksum. */
export function validateRecoveryPhrase(phrase: string): boolean {
  try {
    return validateMnemonic(normalizePhrase(phrase), wordlist)
  } catch {
    return false
  }
}

/**
 * deriveRecoveryKek turns the phrase into an AES-256-GCM KEK.
 * Throws when the phrase fails BIP39 validation (bad word or checksum).
 */
export async function deriveRecoveryKek(phrase: string): Promise<CryptoKey> {
  const normalized = normalizePhrase(phrase)
  if (!validateRecoveryPhrase(normalized)) {
    throw new Error('recovery: invalid recovery phrase (unknown word or bad checksum)')
  }
  const seed = mnemonicToSeedSync(normalized)
  const salt = new TextEncoder().encode(RECOVERY_SALT_LABEL)
  const kekBytes = await deriveKek(seed.slice(0, 32), salt, DEFAULT_KDF_PARAMS)
  return importAesKey(kekBytes)
}
