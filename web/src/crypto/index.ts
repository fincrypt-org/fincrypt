/**
 * Fincrypt crypto core — PUBLIC API (frozen, I8).
 *
 * This file is the ONLY supported import surface (`web/src/crypto`).
 * The export set is asserted by index.test.ts; adding/removing/renaming
 * an export is a breaking change requiring a THREAT_MODEL.md delta in
 * the same PR (CONTRIBUTING rule 2).
 *
 * Downstream phases (P2+) consume this module and never reimplement or
 * bypass it. See API.md for signatures and the byte-format table.
 */

// errors ------------------------------------------------------------
export {
  CryptoError,
  DecryptError,
  InvalidInputError,
  InvalidParamsError,
  InvalidKeyError,
  WrapError,
  InvalidEnvelopeError,
  asDecryptError,
  type CryptoErrorCode,
} from './errors'

// b64 (I5 — the one codec) -------------------------------------------
export { toB64, fromB64 } from './b64'

// aead ---------------------------------------------------------------
export {
  RECORD_TYPES,
  buildAad,
  buildAadString,
  encryptBytes,
  decryptBytes,
  importAesKey,
  type RecordType,
} from './aead'

// envelope codec ------------------------------------------------------
export { serializeEnvelope, parseEnvelope, type Envelope } from './envelope'

// kdf -----------------------------------------------------------------
export {
  DEFAULT_KDF_PARAMS,
  generateKdfSalt,
  argon2idDerive,
  deriveKek,
  serializeKdfParams,
  parseKdfParams,
  importKek,
  type KdfParams,
} from './kdf'
export { deriveKekOffThread } from './kdfWorkerClient'

// key hierarchy ---------------------------------------------------------
export {
  hkdfBits,
  hkdfSaltBytes,
  deriveSubkey,
  generateDek,
  wrapDek,
  unwrapDek,
  wrapWithRecovery,
  unwrapWithRecovery,
  type RawKey,
} from './keyHierarchy'
export { zeroize, zeroizeAll } from './memzero'

// recovery --------------------------------------------------------------
export {
  generateRecoveryPhrase,
  normalizePhrase,
  validateRecoveryPhrase,
  deriveRecoveryKek,
  wrapDekWithRecovery,
  recoverDek,
  pickConfirmIndices,
} from './recovery'

// opaque ----------------------------------------------------------------
export {
  register as opaqueRegister,
  login as opaqueLogin,
  canonicalUserIdentifier,
  type Transport,
  type RegistrationResult,
  type LoginResult,
} from './opaque'

// lifecycle ---------------------------------------------------------------
export {
  changePassphrase,
  recoverWithMnemonic,
  rotateRecovery,
  type PassphraseChangeResult,
  type RecoverWithMnemonicResult,
  type RotateRecoveryResult,
} from './lifecycle'

// session keystore (zustand) ---------------------------------------------
export { useSessionKeys, sessionKeys } from '../stores/sessionKeys'
export { startIdleTimer, type IdleTimerHandle } from './idleTimer'
