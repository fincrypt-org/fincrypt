/**
 * KDF parameters and Argon2id invocation.
 *
 * The 64 MiB / t=3 / p=4 derivation takes ~1s and must never run on the
 * main thread — the caller (kdfWorker.ts / kdfWorkerClient.ts) routes it
 * to a Web Worker. This module is the pure parameter + crypto layer so
 * tests can exercise the actual derivation synchronously in happy-dom.
 */
import { argon2id } from 'hash-wasm'

/** Argon2id parameters, per THREAT_MODEL §0 (plan: m=64MiB, t=3, p=4). */
export interface KdfParams {
  /** memory in KiB */
  m: number
  /** passes */
  t: number
  /** parallelism (lanes) */
  p: number
  /** algorithm version for the upgrade path */
  version: 1
}

/** Defaults locked by PLAN §0: 64 MiB, 3 passes, 4 lanes. */
export const DEFAULT_KDF_PARAMS: KdfParams = {
  m: 65536,
  t: 3,
  p: 4,
  version: 1,
}

/** Validate a params blob (e.g. read back from users.kdf_params). */
export function validateKdfParams(value: unknown): KdfParams {
  const v = value as Partial<KdfParams> | null
  if (
    v == null ||
    typeof v !== 'object' ||
    typeof v.m !== 'number' ||
    typeof v.t !== 'number' ||
    typeof v.p !== 'number' ||
    !Number.isInteger(v.m) ||
    !Number.isInteger(v.t) ||
    !Number.isInteger(v.p) ||
    v.m < 8 * v.p ||
    v.t < 1 ||
    v.p < 1 ||
    v.p > 2 ** 24 - 1
  ) {
    throw new Error('kdf: invalid KdfParams (m must be >= 8*p KiB, t >= 1, p in [1, 2^24))')
  }
  return { m: v.m, t: v.t, p: v.p, version: 1 }
}

/**
 * deriveKek runs Argon2id over the passphrase.
 * Password and salt are the raw bytes; output is a 32-byte KEK.
 *
 * NOTE: hash-wasm accepts `string | Uint8Array` for both; we require
 * Uint8Array so callers can't accidentally pass a JS string (whose
 * UTF-16 representation differs from what the server/other devices
 * would derive). Callers must encode with a single canonical encoding.
 */
export async function deriveKek(
  password: Uint8Array,
  salt: Uint8Array,
  params: KdfParams = DEFAULT_KDF_PARAMS,
  opts: { allowShortSaltForVectorTests?: boolean } = {},
): Promise<Uint8Array> {
  if (salt.length < 16 && !opts.allowShortSaltForVectorTests) {
    throw new Error('kdf: salt must be at least 16 bytes (RFC 9106 recommendation)')
  }
  return (await argon2id({
    password,
    salt,
    iterations: params.t,
    parallelism: params.p,
    memorySize: params.m,
    hashLength: 32,
    outputType: 'binary',
  })) as Uint8Array
}
