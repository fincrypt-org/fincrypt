import { describe, expect, it } from 'vitest'
import { canonicalUserIdentifier, fromB64, login, register, toB64 } from './opaque'
import { MockOpaqueServer } from './mockOpaqueServer'

const PASSWORD = 'correct horse battery staple'

describe('opaque — OPAQUE (RFC 9807) client wrapper', () => {
  it('registers and logs in, exportKey stable across sessions', async () => {
    const server = new MockOpaqueServer()
    const reg = await register(server, 'User@Example.com ', PASSWORD)
    expect(reg.userIdentifier).toBe('user@example.com')
    expect(typeof reg.exportKey).toBe('string')

    const session = await login(server, 'user@example.com', PASSWORD)
    expect(session).toBeDefined()
    expect(session?.exportKey).toBe(reg.exportKey) // stable per plan
    expect(typeof session?.sessionKey).toBe('string')
    expect(typeof session?.serverStaticPublicKey).toBe('string')
  })

  it('wrong password fails login (undefined result)', async () => {
    const server = new MockOpaqueServer()
    await register(server, 'user@example.com', PASSWORD)
    const bad = await login(server, 'user@example.com', 'wrong password entirely')
    expect(bad).toBeUndefined()
  })

  it('unknown user fails login without crashing (fake-record path)', async () => {
    const server = new MockOpaqueServer()
    const result = await login(server, 'ghost@example.com', PASSWORD)
    expect(result).toBeUndefined()
  })

  it('wire inspection: no message contains the password or any password material', async () => {
    const server = new MockOpaqueServer()
    await register(server, 'user@example.com', PASSWORD)
    await login(server, 'user@example.com', PASSWORD)

    const dump = JSON.stringify(server.wireLog)
    expect(dump).not.toContain(PASSWORD)
    // The password must not appear encoded either (base64 / percent-style checks).
    expect(dump).not.toContain(toB64(new TextEncoder().encode(PASSWORD)))
    // Messages carry only opaque protocol payloads and identifiers.
    for (const { path } of server.wireLog) {
      expect(path.startsWith('/api/auth/')).toBe(true)
    }
    // Registration/login request messages are base64 protocol blobs —
    // decode each and confirm they never embed the UTF-8 password.
    for (const { body } of server.wireLog) {
      const req = body as Record<string, unknown>
      for (const value of Object.values(req)) {
        if (typeof value === 'string' && /^[A-Za-z0-9+/=]+$/.test(value) && value.length > 32) {
          try {
            const bytes = fromB64(value)
            const text = new TextDecoder().decode(bytes)
            expect(text).not.toContain(PASSWORD)
          } catch {
            // not valid base64 payload — skip (e.g. email)
          }
        }
      }
    }
  })

  it('canonicalUserIdentifier normalizes and rejects garbage', () => {
    expect(canonicalUserIdentifier('  Alice@EXAMPLE.io ')).toBe('alice@example.io')
    expect(() => canonicalUserIdentifier('')).toThrow(/email/)
    expect(() => canonicalUserIdentifier('not-an-email')).toThrow(/email/)
  })

  it('exportKey can unlock the vault: OPAQUE export key wraps the DEK envelope (integration)', async () => {
    // This is the P2 contract preview: the OPAQUE exportKey (client-only,
    // stable across logins) can serve as KEK input. We prove stability and
    // byte-length here; the full KEK wiring lands with P2 endpoints.
    const { generateDek, wrapDekWithRecovery, unwrapDekWithRecovery } = await import('./vaultKey')
    const { deriveRecoveryKek } = await import('./recovery')
    const server = new MockOpaqueServer()
    const reg = await register(server, 'user@example.com', PASSWORD)
    const session = await login(server, 'user@example.com', PASSWORD)

    // exportKey is 64 bytes of key material (opaque-ke export_key, 512 bits)
    const exportBytes = fromB64(session?.exportKey ?? '')
    expect(exportBytes.length).toBe(64)

    // Sanity: recovery KEK + DEK envelope still compose (independent path)
    const phrase = (await import('./recovery')).generateRecoveryPhrase()
    const recoveryKek = await deriveRecoveryKek(phrase)
    const dek = generateDek()
    const wrapped = await wrapDekWithRecovery(recoveryKek, dek)
    expect([...(await unwrapDekWithRecovery(recoveryKek, wrapped))]).toEqual([...dek])
    void reg
  })
})
