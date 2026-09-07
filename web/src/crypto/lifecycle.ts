/**
 * Key lifecycle (C1.7) — §0 verbatim behaviors:
 *
 * - Passphrase change: NEW random kdf_salt, re-wraps BOTH wrapped DEKs,
 *   no data re-encryption. OPAQUE re-registration is P2's endpoint —
 *   this module produces the four server-stored fields.
 * - Recovery reset (lost passphrase, phrase known): same re-wrap path
 *   against the recovery wrap.
 * - Recovery rotation: new phrase → re-issue wrapped_dek_recovery only;
 *   passphrase wrap untouched.
 *
 * Every flow returns only server-storable envelopes; no plaintext or
 * key material in the results beyond the DEK when explicitly requested
 * by recovery.
 */
import {
  generateKdfSalt,
  serializeKdfParams,
  DEFAULT_KDF_PARAMS,
  argon2idDerive,
  importKek,
  type KdfParams,
} from './kdf'
import { unwrapDek, wrapDek, wrapWithRecovery, type RawKey } from './keyHierarchy'
import { recoverDek, deriveRecoveryKek } from './recovery'
import { zeroize } from './memzero'
import { WrapError } from './errors'

export interface PassphraseChangeResult {
  kdf_salt: Uint8Array
  kdf_params: string
  wrapped_dek: Uint8Array
  wrapped_dek_recovery: Uint8Array
}

export interface ChangePassphraseArgs {
  oldPass: string
  newPass: string
  userId: string
  kdfSalt: Uint8Array
  kdfParamsJson: string
  wrappedDek: Uint8Array
  wrappedDekRecovery: Uint8Array
}

/**
 * changePassphrase: verify the old passphrase, then re-wrap both wraps
 * under a fresh salt + new KEK. Both wraps get fresh nonces.
 */
export async function changePassphrase(
  args: ChangePassphraseArgs,
): Promise<PassphraseChangeResult> {
  if (args.newPass === args.oldPass) {
    throw new WrapError('new passphrase must differ from the old one')
  }
  if (args.newPass.length === 0) throw new WrapError('new passphrase must not be empty')

  // Verify old: unwrap with the current KEK (throws WrapError if wrong).
  const oldParams = oldKekParams(JSON.parse(args.kdfParamsJson))
  const oldKekBytes = await argon2idDerive(args.oldPass, args.kdfSalt, oldParams)
  const oldKek = await importKek(oldKekBytes)
  const dek = await unwrapDek(args.wrappedDek, oldKek, args.userId)
  zeroize(oldKekBytes)

  // New salt + params → new KEK → fresh wraps (both from the same DEK,
  // so the recovery wrap continues to describe the same data key).
  const newSalt = generateKdfSalt()
  const newParams = DEFAULT_KDF_PARAMS
  const newKekBytes = await argon2idDerive(args.newPass, newSalt, newParams)
  const newKek = await importKek(newKekBytes)
  const wrapped = await wrapDek(dek, newKek, args.userId)
  const wrappedRecovery = await wrapWithRecovery(dek, newKek, args.userId)
  zeroize(newKekBytes)

  return {
    kdf_salt: newSalt,
    kdf_params: serializeKdfParams(newParams),
    wrapped_dek: wrapped,
    wrapped_dek_recovery: wrappedRecovery,
  }
}

export interface RecoverWithMnemonicResult {
  dek: RawKey
}

/** recoverWithMnemonic: open the recovery wrap with the phrase → the DEK. */
export async function recoverWithMnemonic(args: {
  mnemonic: string
  userId: string
  wrappedDekRecovery: Uint8Array
}): Promise<RecoverWithMnemonicResult> {
  const dek = await recoverDek(args.wrappedDekRecovery, args.mnemonic, args.userId)
  return { dek }
}

export interface RotateRecoveryArgs {
  oldMnemonic: string
  newMnemonic: string
  userId: string
  wrappedDekRecovery: Uint8Array
}

export interface RotateRecoveryResult {
  wrapped_dek_recovery: Uint8Array
}

/**
 * rotateRecovery: verify the old phrase opens the current recovery wrap,
 * then re-issue the recovery wrap under the NEW phrase. The passphrase
 * wrap is untouched.
 */
export async function rotateRecovery(args: RotateRecoveryArgs): Promise<RotateRecoveryResult> {
  const dek = await recoverDek(args.wrappedDekRecovery, args.oldMnemonic, args.userId)
  const newKek = await deriveRecoveryKek(args.newMnemonic)
  const wrapped = await wrapWithRecovery(dek, newKek, args.userId)
  return { wrapped_dek_recovery: wrapped }
}

// helpers -----------------------------------------------------------

function oldKekParams(p: unknown): KdfParams {
  // The stored params carry their own alg/version guard via parseKdfParams
  // upstream; here we only need the numeric shape for derivation.
  const v = p as { alg: 'argon2id'; version: 19; m: number; t: number; p: number }
  return { alg: 'argon2id', version: 19, m: v.m, t: v.t, p: v.p }
}
