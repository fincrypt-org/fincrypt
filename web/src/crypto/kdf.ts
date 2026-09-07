/**
 * KDF (C1.1): Argon2id via hash-wasm, run in the Web Worker
 * (kdfWorker/kdfWorkerClient) — never the main thread.
 *
 * Formats (§0 + §P1-0):
 * - kdf_salt: 32 crypto-random bytes, never email-derived
 * - kdf_params jsonb: {"alg":"argon2id","version":19,"m":65536,"t":3,"p":4}
 *   (`version` here is the params-upgrade version field from §1's schema
 *   comment; Argon2's internal version is pinned 0x13=19)
 * - KEK: Argon2id(utf8(pass), kdf_salt, params) → 32 B → non-extractable
 *   AES-256-GCM CryptoKey
 */
import { argon2id } from 'hash-wasm'
import { InvalidParamsError } from './errors'

export interface KdfParams {
  alg: 'argon2id'
  /** Argon2 algorithm version (0x13 = 19) */
  version: 19
  /** memory in KiB */
  m: number
  /** passes */
  t: number
  /** parallelism (lanes) */
  p: number
}

/** Defaults locked by PLAN §0: 64 MiB, 3 passes, 4 lanes, argon2id v19. */
export const DEFAULT_KDF_PARAMS: KdfParams = {
  alg: 'argon2id',
  version: 19,
  m: 65536,
  t: 3,
  p: 4,
}

/** generateKdfSalt: 32 crypto-random bytes — never email-derived (§0). */
export function generateKdfSalt(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32))
}

/** serializeKdfParams → the exact jsonb string stored in users.kdf_params. */
export function serializeKdfParams(p: KdfParams): string {
  return JSON.stringify({ alg: p.alg, version: p.version, m: p.m, t: p.t, p: p.p })
}

/** parseKdfParams: shape-strict; unknown version/alg → InvalidParamsError (upgrade path guard). */
export function parseKdfParams(json: string): KdfParams {
  let v: Record<string, unknown>
  try {
    v = JSON.parse(json) as Record<string, unknown>
  } catch {
    throw new InvalidParamsError('kdf params are not valid JSON')
  }
  if (v.alg !== 'argon2id') throw new InvalidParamsError('kdf params: unknown alg')
  if (v.version !== 19) {
    // Future param upgrades parse differently; v1 only knows version 19.
    throw new InvalidParamsError('kdf params: unsupported version')
  }
  const m = v.m
  const t = v.t
  const p = v.p
  if (
    typeof m !== 'number' ||
    typeof t !== 'number' ||
    typeof p !== 'number' ||
    !Number.isInteger(m) ||
    !Number.isInteger(t) ||
    !Number.isInteger(p) ||
    m < 8 * p ||
    t < 1 ||
    p < 1 ||
    p > 2 ** 24 - 1
  ) {
    throw new InvalidParamsError('kdf params: out of range (m >= 8*p KiB, t >= 1, p in [1, 2^24))')
  }
  return { alg: 'argon2id', version: 19, m, t, p }
}

/**
 * argon2idDerive: the raw 32-byte derivation (hash-wasm).
 * Worker-only in production — callers must go through kdfWorkerClient;
 * this function is exported pure for vector tests.
 */
export async function argon2idDerive(
  pass: string,
  salt: Uint8Array,
  p: KdfParams,
  opts: { allowShortSaltForVectors?: boolean } = {},
): Promise<Uint8Array> {
  if (salt.length < 16 && !opts.allowShortSaltForVectors) {
    // RFC 9106 recommends 16-byte salts; committed reference vectors use less.
    throw new InvalidParamsError('kdf: salt must be at least 16 bytes')
  }
  return (await argon2id({
    password: new TextEncoder().encode(pass),
    salt,
    iterations: p.t,
    parallelism: p.p,
    memorySize: p.m,
    hashLength: 32,
    outputType: 'binary',
  })) as Uint8Array
}

/**
 * deriveKek: passphrase → KEK CryptoKey (non-extractable, I3).
 * NOTE: this direct call blocks the main thread at prod params — the
 * app uses deriveKekOffThread from kdfWorkerClient.
 */
export async function deriveKek(
  pass: string,
  salt: Uint8Array,
  params: KdfParams = DEFAULT_KDF_PARAMS,
): Promise<CryptoKey> {
  const bytes = await argon2idDerive(pass, salt, params)
  return importAesKek(bytes)
}

import { importAesKey } from './aead'

/** Import raw KEK bytes as non-extractable AES-GCM key. */
export async function importKek(kekBytes: Uint8Array): Promise<CryptoKey> {
  return importAesKey(kekBytes)
}

function importAesKek(bytes: Uint8Array): Promise<CryptoKey> {
  return importAesKey(bytes)
}