/**
 * Main-thread client for the KDF Web Worker.
 * Falls back to in-thread derivation when Workers are unavailable
 * (happy-dom test environment, very old browsers) — the derivation
 * itself is identical.
 */
import { deriveKek, type KdfParams } from './kdf'
import type { KdfWorkerRequest, KdfWorkerResponse } from './kdfWorker'

let workerUrl: string | null = null

/** Internal: build the worker from a bundled module (Vite handles the ?worker suffix). */
async function spawnWorker(): Promise<Worker> {
  if (workerUrl == null) {
    // Vite compiles `?worker&inline` to a blob URL so it also works from file:// and strict CSP.
    const mod = await import('./kdfWorker?worker&inline')
    return new mod.default()
  }
  return new Worker(workerUrl)
}

export interface DeriveKekOffThreadResult {
  kek: Uint8Array
  /** true when a Web Worker ran the derivation (main thread stayed responsive) */
  offThread: boolean
}

/**
 * deriveKekOffThread derives the KEK, preferably in a Worker.
 * Errors from the worker surface here as thrown Errors.
 */
export async function deriveKekOffThread(
  password: Uint8Array,
  salt: Uint8Array,
  params?: KdfParams,
): Promise<DeriveKekOffThreadResult> {
  try {
    const worker = await spawnWorker()
    try {
      const kek = await new Promise<Uint8Array>((resolve, reject) => {
        const req: KdfWorkerRequest = { type: 'derive', password, salt, params }
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
      return { kek, offThread: true }
    } catch (err) {
      worker.terminate()
      throw err
    }
  } catch (spawnErr) {
    if (spawnErr instanceof Error && spawnErr.message.startsWith('kdf:')) throw spawnErr
    // Worker unavailable (test env / restricted env) — derive inline.
    const kek = await deriveKek(password, salt, params)
    return { kek, offThread: false }
  }
}
