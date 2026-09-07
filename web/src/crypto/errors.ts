/**
 * Typed crypto errors (I6): stable codes, messages that never contain
 * key material, plaintext, or user content.
 *
 * The decrypt oracle rule: ALL decryption failures — wrong key, AAD
 * mismatch, tampering, truncation — surface as ONE generic
 * DecryptError('decryption failed'). Callers and logs can never learn
 * why decryption failed.
 */

export type CryptoErrorCode =
  | 'decryption_failed'
  | 'invalid_input'
  | 'invalid_params'
  | 'invalid_phrase'
  | 'invalid_key'
  | 'wrap_failed'
  | 'invalid_envelope'
  | 'locked'
  | 'not_supported'

export class CryptoError extends Error {
  readonly code: CryptoErrorCode

  constructor(code: CryptoErrorCode, message: string) {
    super(message)
    this.name = 'CryptoError'
    this.code = code
  }
}

/** The one generic decryption failure — no oracle. */
export class DecryptError extends CryptoError {
  constructor() {
    super('decryption_failed', 'decryption failed')
    this.name = 'DecryptError'
  }
}

export class InvalidInputError extends CryptoError {
  constructor(message: string) {
    super('invalid_input', message)
    this.name = 'InvalidInputError'
  }
}

export class InvalidParamsError extends CryptoError {
  constructor(message: string) {
    super('invalid_params', message)
    this.name = 'InvalidParamsError'
  }
}

export class InvalidKeyError extends CryptoError {
  constructor(message: string) {
    super('invalid_key', message)
    this.name = 'InvalidKeyError'
  }
}

export class WrapError extends CryptoError {
  constructor(message = 'key wrapping failed') {
    super('wrap_failed', message)
    this.name = 'WrapError'
  }
}

export class InvalidEnvelopeError extends CryptoError {
  constructor(message: string) {
    super('invalid_envelope', message)
    this.name = 'InvalidEnvelopeError'
  }
}

/** Normalize any thrown error from a decrypt path into DecryptError. */
export function asDecryptError(_err: unknown): DecryptError {
  void _err
  return new DecryptError()
}