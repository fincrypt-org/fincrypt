/**
 * Main-thread client for the KDF Web Worker (C1.1).
 * Falls back to in-thread derivation when Workers are unavailable
 * (happy-dom test environment) — the derivation itself is identical.
 */
import { argon2idDerive, serializeKdfParams, type KdfParams } from './kdf'
import { importAesKey } from './aead'
import type { KdfWorkerRequest, KdfWorkerResponse } from './kdfWorker'

export interface DeriveKekOffThreadResult {
  /** non-extractable AES-GCM KEK */
  kek: CryptoKey
  /** true when a Web Worker ran the derivation (main thread stayed responsive) */
  offThread: boolean
}

/**
 * deriveKekOffThread derives the KEK, preferably in a Worker.
 * Errors from the worker surface here as thrown Errors.
 */
export async function deriveKekOffThread(
  pass: string,
  salt: Uint8Array,
  params: KdfParams,
): Promise<DeriveKekOffThreadResult> {
  try {
    const mod = await import('./kdfWorker?worker&inline')
    const worker = new mod.default()
    try {
      const kekBytes = await new Promise<Uint8Array>((resolve, reject) => {
        const req: KdfWorkerRequest = {
          type: 'derive',
          pass,
          salt,
          paramsJson: serializeKdfParams(params),
        }
        worker.onmessage = (event: MessageEvent<KdfWorkerResponse | { error: string }>) => {
          if ('error' in event.data) {
            reject(new Error(event.data.error))
          } else {
            resolve(event.data.kek)
          }
        }
        worker.onerror = (event) => reject(new Error(`kdf worker: ${event.message}`))
        worker.postMessage(req)
      })
      worker.terminate()
      const kek = await importAesKey(kekBytes)
      return { kek, offThread: true }
    } catch (err) {
      worker.terminate()
      throw err
    }
  } catch (spawnErr) {
    // Worker unavailable (test env / restricted env) — derive inline.
    const kekBytes = await argon2idDerive(pass, salt, params)
    const kek = await importAesKey(kekBytes)
    return { kek, offThread: false }
  }
}
