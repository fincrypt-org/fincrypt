import { beforeAll, describe, expect, it } from 'vitest'
import { ensureTestCrypto } from './test-env'
import fixtures from './vectors/index.json'
import { mnemonicToSeedSync, validateMnemonic } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english.js'
import {
  deriveRecoveryKek,
  generateRecoveryPhrase,
  normalizePhrase,
  pickConfirmIndices,
  recoverDek,
  validateRecoveryPhrase,
  wrapDekWithRecovery,
} from './recovery'
import { generateDek, deriveSubkey } from './keyHierarchy'
import { buildAad, decryptBytes, encryptBytes } from './aead'

beforeAll(() => {
  ensureTestCrypto()
})

const enc = new TextEncoder()
const dec = new TextDecoder()

describe('recovery — BIP39 official fixtures (empty passphrase, D4 pin)', () => {
  const cases = fixtures['bip39-official']

  it('seed matches the official BIP39 mnemonics with empty passphrase', () => {
    for (const c of cases) {
      expect(validateMnemonic(c.mnemonic, wordlist)).toBe(true)
      const seed = mnemonicToSeedSync(c.mnemonic) // 25th word pinned "" (D4)
      expect([...new Uint8Array(seed)].map((b) => b.toString(16).padStart(2, '0')).join('')).toBe(
        c.seed_hex,
      )
    }
  })

  it('validateRecoveryPhrase accepts official mnemonics, rejects bad checksum and unknown words', () => {
    for (const c of cases) {
      expect(validateRecoveryPhrase(c.mnemonic)).toBe(true)
    }
    expect(
      validateRecoveryPhrase(
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon',
      ),
    ).toBe(false) // bad checksum
    expect(
      validateRecoveryPhrase(
        'notaword notaword notaword notaword notaword notaword notaword notaword notaword notaword notaword notaword',
      ),
    ).toBe(false)
  })

  it('normalizePhrase handles case/multi-space; NFKD folds compat chars', () => {
    const phrase = 'legal winner thank year wave sausage worth useful legal winner thank yellow'
    const messy = `  ${phrase.toUpperCase().split(' ').join('   ')}`
    expect(normalizePhrase(messy)).toBe(phrase)
    expect(validateRecoveryPhrase(messy)).toBe(true)
    expect(normalizePhrase('\uFB01x')).toBe('fix')
  })
})

describe('recovery — KEK derivation (D4) and flows', () => {
  it('malformed phrase rejected with typed error', async () => {
    await expect(
      deriveRecoveryKek('definitely not a valid phrase at all here now'),
    ).rejects.toMatchObject({
      code: 'invalid_phrase',
    })
  })

  it('wrap → recover roundtrip returns the same DEK', async () => {
    const userId = 'user-a'
    const dek = generateDek()
    const { mnemonic } = generateRecoveryPhrase()
    const wrapped = await wrapDekWithRecovery(dek, mnemonic, userId)
    expect(wrapped.length).toBe(60) // 12 nonce + 32 dek + 16 tag
    const recovered = await recoverDek(wrapped, mnemonic, userId)
    expect([...recovered]).toEqual([...dek])
    // Formatting differences in the typed phrase still recover:
    const recoveredMessy = await recoverDek(wrapped, `  ${mnemonic.toUpperCase()}  `, userId)
    expect([...recoveredMessy]).toEqual([...dek])
  })

  it('wrong phrase fails recovery', async () => {
    const userId = 'user-a'
    const dek = generateDek()
    const wrapped = await wrapDekWithRecovery(dek, generateRecoveryPhrase().mnemonic, userId)
    await expect(
      recoverDek(wrapped, generateRecoveryPhrase().mnemonic, userId),
    ).rejects.toMatchObject({
      code: 'wrap_failed',
    })
  })

  it('pickConfirmIndices returns 3 distinct indices in 0..11', () => {
    for (let i = 0; i < 50; i++) {
      const [a, b, c] = pickConfirmIndices()
      expect(new Set([a, b, c]).size).toBe(3)
      for (const idx of [a, b, c]) expect(idx).toBeGreaterThanOrEqual(0)
    }
    // degenerate rngs still terminate and yield 3 distinct indices:
    expect(new Set(pickConfirmIndices(() => 0)).size).toBe(3)
    expect(new Set(pickConfirmIndices(() => 0.999)).size).toBe(3)
    for (const idx of pickConfirmIndices(() => 0.999)) expect(idx).toBeLessThanOrEqual(11)
  })

  it('encrypted data survives the full recovery flow on a fresh device', async () => {
    const userId = 'user-a'
    const { mnemonic } = generateRecoveryPhrase()
    const dek = generateDek()
    const wrappedRecovery = await wrapDekWithRecovery(dek, mnemonic, userId)

    const txKey = await deriveSubkey(dek, 'transactions')
    const aad = buildAad(userId, 'transactions', 'r1')
    const packed = await encryptBytes(txKey, enc.encode('transaction payload'), aad)

    const restored = await recoverDek(wrappedRecovery, mnemonic, userId)
    const restoredKey = await deriveSubkey(restored, 'transactions')
    expect(dec.decode(await decryptBytes(restoredKey, packed, aad))).toBe('transaction payload')
  })
})
