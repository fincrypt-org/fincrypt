/**
 * Recovery (C1.4): 12-word BIP39 phrase, mandatory at signup, shown once.
 *
 * D4 (gap-fill): the recovery KEK derivation — §0 names the recovery
 * KEK without its derivation path. Pinned for v1:
 *   mnemonic --BIP39 seed(passphrase pinned "")--> 64-byte seed
 *   → HKDF-SHA256(seed, salt="fincrypt/v1/hkdf", info="recovery", 256)
 *   → AES-256-GCM KEK.
 * (The P1 first cut used Argon2id(seed, fixed label); the HKDF path is
 * the specced D4 and cheaper — the phrase itself carries the entropy.)
 */
import { mnemonicToSeedSync, validateMnemonic, generateMnemonic } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english.js'
import { hkdfBits, hkdfSaltBytes, wrapWithRecovery, unwrapWithRecovery, type RawKey } from './keyHierarchy'
import { importAesKey } from './aead'
import { CryptoError } from './errors'

const RECOVERY_INFO = 'recovery'

/** generateRecoveryPhrase returns 12 words + the normalized mnemonic string. */
export function generateRecoveryPhrase(): { words: string[]; mnemonic: string } {
  const mnemonic = generateMnemonic(wordlist, 128)
  return { words: mnemonic.split(' '), mnemonic }
}

/**
 * normalizePhrase: NFKD-normalize, lowercase, collapse whitespace —
 * restore is forgiving about formatting but nothing else.
 */
export function normalizePhrase(input: string): string {
  return input
    .normalize('NFKD')
    .trim()
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean)
    .join(' ')
}

/** validateRecoveryPhrase checks words against the English wordlist + checksum. */
export function validateRecoveryPhrase(phrase: string): boolean {
  try {
    return validateMnemonic(normalizePhrase(phrase), wordlist)
  } catch {
    return false
  }
}

/**
 * deriveRecoveryKek: BIP39 seed → HKDF → AES-256-GCM KEK (D4).
 * Throws CryptoError('invalid_phrase') on a malformed phrase.
 */
export async function deriveRecoveryKek(mnemonic: string): Promise<CryptoKey> {
  const normalized = normalizePhrase(mnemonic)
  if (!validateRecoveryPhrase(normalized)) {
    throw new CryptoError('invalid_phrase', 'invalid recovery phrase')
  }
  const seed = mnemonicToSeedSync(normalized) // 25th word (BIP39 passphrase) pinned "" in v1
  const bits = hkdfBits(seed, hkdfSaltBytes(), new TextEncoder().encode(RECOVERY_INFO), 256)
  return importAesKey(bits)
}

/** wrapDekWithRecovery: DEK under the recovery KEK (60 bytes). */
export async function wrapDekWithRecovery(
  dek: RawKey,
  mnemonic: string,
  userId: string,
): Promise<Uint8Array> {
  const kek = await deriveRecoveryKek(mnemonic)
  return wrapWithRecovery(dek, kek, userId)
}

/** recoverDek: open the recovery wrap with a fresh phrase → the original DEK. */
export async function recoverDek(
  wrappedRecovery: Uint8Array,
  mnemonic: string,
  userId: string,
): Promise<RawKey> {
  const kek = await deriveRecoveryKek(mnemonic)
  return unwrapWithRecovery(wrappedRecovery, kek, userId)
}

/**
 * pickConfirmIndices: 3 distinct indices of 0..11 for the
 * retype-confirmation flow at signup. Injectable rng for tests.
 */
export function pickConfirmIndices(rng: () => number = Math.random): [number, number, number] {
  const draw = (): number => Math.floor(rng() * 12)
  const set = new Set<number>()
  while (set.size < 3) set.add(draw())
  const [a, b, c] = [...set] as [number, number, number]
  return [a, b, c]
}