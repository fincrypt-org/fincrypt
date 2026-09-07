/**
 * Canonical base64 codec (I5): RFC 4648 WITH padding, everywhere.
 * No base64url, no hex — anything else is a bug. serenity-kit/opaque
 * emits base64-URL strings; fromB64 normalizes that alphabet here so
 * the rest of the codebase never sees a second codec.
 */
export function toB64(bytes: Uint8Array): string {
  let binary = ''
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary)
}

/** Accepts RFC 4648 padded base64 (and normalizes base64url from external libs). */
export function fromB64(b64: string): Uint8Array {
  const standard = b64.replace(/-/g, '+').replace(/_/g, '/')
  const binary = atob(standard)
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i)
  return out
}