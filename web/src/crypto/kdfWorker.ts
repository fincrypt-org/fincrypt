/// <reference lib="webworker" />
/**
 * KDF Web Worker — keeps the 64 MiB Argon2id derivation off the main
 * thread. Messages:
 *   { type: 'derive', password: Uint8Array, salt: Uint8Array, params?: KdfParams }
 * -> { kek: Uint8Array }
 *   { type: 'done' } shuts the worker down (zeroizes nothing on the
 *   worker side; WASM memory is freed with the worker itself).
 */
import { deriveKek, validateKdfParams, type KdfParams } from './kdf'

export interface KdfWorkerRequest {
  type: 'derive'
  password: Uint8Array
  salt: Uint8Array
  params?: KdfParams
}

export interface KdfWorkerResponse {
  kek: Uint8Array
}

self.onmessage = async (event: MessageEvent<KdfWorkerRequest>) => {
  const { type, password, salt, params } = event.data
  if (type !== 'derive') return
  try {
    const kek = await deriveKek(password, salt, params ? validateKdfParams(params) : undefined)
    const response: KdfWorkerResponse = { kek }
    ;(self as unknown as Worker).postMessage(response, [kek.buffer])
  } catch (err) {
    // Serialize the error across the worker boundary.
    ;(self as unknown as Worker).postMessage({
      error: err instanceof Error ? err.message : String(err),
    })
  }
}
