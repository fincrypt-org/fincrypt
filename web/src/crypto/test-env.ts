/**
 * Test environment bridge (C1.0).
 *
 * happy-dom provides a DOM but NO SubtleCrypto. This module installs
 * Node's built-in WebCrypto onto globalThis BEFORE crypto modules are
 * imported, so vitest tests exercise the exact platform implementation
 * a browser ships (same algorithms, same ct‖tag layout, same AAD
 * semantics) — it is a bridge to the platform implementation, NOT a
 * polyfill (polyfills are forbidden; see the no-telemetry/lint rules).
 *
 * The real-browser-native proof is C1.8's `/dev/crypto` Playwright run
 * in actual Chromium — that's where "passes in Node, breaks in
 * browser" is finally ruled out.
 *
 * In real browsers this module is a no-op: `globalThis.crypto.subtle`
 * already exists.
 */

interface CryptoBridgeResult {
  /** 'happy-dom-bridge' when the patch was applied, 'native' otherwise */
  mode: 'happy-dom-bridge' | 'native'
}

/**
 * ensureCrypto returns the SubtleCrypto to use, installing Node's
 * webcrypto when the environment lacks one. Idempotent.
 */
export function getSubtle(): SubtleCrypto {
  if (typeof globalThis.crypto?.subtle !== 'undefined') {
    return globalThis.crypto.subtle
  }
  // Node ships webcrypto as a global since 18/20+ under node:*; in
  // bundled/test contexts it is reachable via globalThis when the
  // runtime is Node 22. Resolve it without importing node: modules in
  // the browser bundle (this file is test-only).
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const nodeCrypto = (globalThis as Record<string, unknown>).crypto as
    { webcrypto?: Crypto } | undefined
  if (nodeCrypto?.webcrypto) {
    return nodeCrypto.webcrypto.subtle
  }
  throw new Error(
    'test-env: no SubtleCrypto available — happy-dom bridge failed and no native crypto exists',
  )
}

/** Install the bridge if needed; returns what happened (for test assertions). */
export function ensureTestCrypto(): CryptoBridgeResult {
  if (typeof globalThis.crypto?.subtle !== 'undefined') return { mode: 'native' }
  const nodeCrypto = (globalThis as Record<string, unknown>).crypto as
    { webcrypto?: Crypto } | undefined
  if (nodeCrypto?.webcrypto) {
    Object.defineProperty(globalThis, 'crypto', {
      value: nodeCrypto.webcrypto,
      configurable: true,
      writable: true,
    })
    return { mode: 'happy-dom-bridge' }
  }
  throw new Error('test-env: cannot establish a WebCrypto implementation for tests')
}
