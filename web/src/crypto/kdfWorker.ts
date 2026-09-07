/// <reference lib="webworker" />
/**
 * KDF Web Worker — keeps the 64 MiB Argon2id derivation off the main
 * thread. Messages:
 *   { type: 'derive', pass: string, salt: Uint8Array, params: KdfParams }
 * -> { kek: Uint8Array } (32 raw bytes)
 *   { error: string } on failure (content-free messages only)
 */
import { argon2idDerive, parseKdfParams } from './kdf'

export interface KdfWorkerRequest {
  type: 'derive'
  pass: string
  salt: Uint8Array
  paramsJson: string
}

export interface KdfWorkerResponse {
  kek: Uint8Array
}

self.onmessage = async (event: MessageEvent<KdfWorkerRequest>) => {
  const { type, pass, salt, paramsJson } = event.data
  if (type !== 'derive') return
  try {
    const params = parseKdfParams(paramsJson)
    const kek = await argon2idDerive(pass, salt, params)
    ;(self as unknown as Worker).postMessage({ kek }, [kek.buffer])
  } catch (err) {
    // Content-free error only — no key material crosses the boundary.
    ;(self as unknown as Worker).postMessage({
      error: err instanceof Error ? err.message : 'kdf worker error',
    })
  }
}