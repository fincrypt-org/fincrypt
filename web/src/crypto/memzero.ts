/**
 * memzero (C1.3): best-effort JS zeroization (I3).
 * JS cannot guarantee GC never copies a buffer, but writing zeros and
 * dropping references shrinks the window. Documented honestly in
 * API.md and THREAT_MODEL.
 */

/** Overwrite every byte with 0. Best-effort — see module docs. */
export function zeroize(...bufs: Array<Uint8Array | undefined>): void {
  for (const buf of bufs) {
    if (buf) buf.fill(0)
  }
}

/**
 * zeroizeAll walks an object's own Uint8Array-valued properties and
 * zeroizes them. Used by the keystore's lock().
 */
export function zeroizeAll(obj: Record<string, unknown>): void {
  for (const value of Object.values(obj)) {
    if (value instanceof Uint8Array) {
      value.fill(0)
    } else if (value && typeof value === 'object') {
      zeroizeAll(value as Record<string, unknown>)
    }
  }
}