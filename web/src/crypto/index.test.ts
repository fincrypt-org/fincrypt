/**
 * API freeze test (I8): the export set of `./index.ts` is EXACTLY this
 * list. Adding, removing, or renaming a public export is a breaking
 * change — it must come with a THREAT_MODEL.md delta in the same PR
 * (CONTRIBUTING rule 2) and an intentional edit of this list.
 */
import { describe, expect, it } from 'vitest'
import * as crypto from './index'

const FROZEN_EXPORTS = [
  // errors
  'CryptoError',
  'DecryptError',
  'InvalidInputError',
  'InvalidParamsError',
  'InvalidKeyError',
  'WrapError',
  'InvalidEnvelopeError',
  'asDecryptError',
  // b64
  'toB64',
  'fromB64',
  // aead
  'RECORD_TYPES',
  'buildAad',
  'buildAadString',
  'encryptBytes',
  'decryptBytes',
  'importAesKey',
  // envelope
  'serializeEnvelope',
  'parseEnvelope',
  // kdf
  'DEFAULT_KDF_PARAMS',
  'generateKdfSalt',
  'argon2idDerive',
  'deriveKek',
  'serializeKdfParams',
  'parseKdfParams',
  'importKek',
  'deriveKekOffThread',
  // key hierarchy
  'hkdfBits',
  'hkdfSaltBytes',
  'deriveSubkey',
  'generateDek',
  'wrapDek',
  'unwrapDek',
  'wrapWithRecovery',
  'unwrapWithRecovery',
  'zeroize',
  'zeroizeAll',
  // recovery
  'generateRecoveryPhrase',
  'normalizePhrase',
  'validateRecoveryPhrase',
  'deriveRecoveryKek',
  'wrapDekWithRecovery',
  'recoverDek',
  'pickConfirmIndices',
  // opaque
  'opaqueRegister',
  'opaqueLogin',
  'canonicalUserIdentifier',
  // lifecycle
  'changePassphrase',
  'recoverWithMnemonic',
  'rotateRecovery',
  // keystore
  'useSessionKeys',
  'sessionKeys',
  'startIdleTimer',
  // types (type-only — checked for presence as undefined runtime exports too)
  'Envelope',
  'RecordType',
  'KdfParams',
  'RawKey',
  'Transport',
  'RegistrationResult',
  'LoginResult',
  'PassphraseChangeResult',
  'RecoverWithMnemonicResult',
  'RotateRecoveryResult',
  'CryptoErrorCode',
  'IdleTimerHandle',
] as const

const TYPE_ONLY_EXPORTS = new Set([
  'Envelope',
  'RecordType',
  'KdfParams',
  'RawKey',
  'Transport',
  'RegistrationResult',
  'LoginResult',
  'PassphraseChangeResult',
  'RecoverWithMnemonicResult',
  'RotateRecoveryResult',
  'CryptoErrorCode',
  'IdleTimerHandle',
])

describe('API freeze (I8)', () => {
  it('the export key set is exactly the frozen list', () => {
    const actual = new Set(Object.keys(crypto) as string[])
    const expected = new Set<string>(FROZEN_EXPORTS.filter((name) => !TYPE_ONLY_EXPORTS.has(name)))

    const extra = [...actual].filter((k) => !expected.has(k))
    const missing = [...expected].filter((k) => !actual.has(k))

    expect(extra).toEqual([])
    expect(missing).toEqual([])
    expect(actual.size).toBe(expected.size)
  })

  it('every runtime export is defined (no undefined re-exports)', () => {
    for (const name of FROZEN_EXPORTS) {
      if (TYPE_ONLY_EXPORTS.has(name)) continue
      expect((crypto as unknown as Record<string, unknown>)[name], `export ${name}`).toBeDefined()
    }
  })
})
