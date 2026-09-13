/**
 * Auth store tests (C2.5): register → phrase → login → logout with a
 * mock transport; wire-inspection re-run through the real API path
 * shape; wrong-passphrase handling; D8 uniformity.
 *
 * The OPAQUE roundtrips run against the in-memory server (P1's
 * mockOpaqueServer) standing in for the Go endpoints — the wire shapes
 * are identical (C2.0/interop proved byte equivalence).
 */
import { describe, expect, it, beforeEach, vi } from 'vitest'
import { useAuth } from './authStore'
import { useSessionKeys } from './sessionKeys'
import { MockOpaqueServer } from '../crypto/mockOpaqueServer'
import type { Transport } from '../crypto/opaque'

// The store calls fetch() for the HTTP legs; point fetch at an adapter
// that forwards opaque paths to the in-memory server and handles the
// non-OPAQUE session endpoints in-memory.
class FakeServer implements Transport {
  readonly records = new Map<string, string>()
  readonly wire: Array<{ path: string; body: unknown }> = []
  readonly meByEmail = new Map<
    string,
    { userId: string; email: string; kdfSalt: string; kdfParams: string }
  >()
  readonly unlockByEmail = new Map<
    string,
    { wrappedDek: string; wrappedDekRecovery: string; kdfSalt: string; kdfParams: string }
  >()
  private opaque = new MockOpaqueServer()
  sessionCookie = ''

  async post<TRequest extends object, TResponse>(path: string, body: TRequest): Promise<TResponse> {
    this.wire.push({ path, body })
    const b = body as Record<string, string>
    if (path === '/api/auth/register/start') {
      const res = (await this.opaque.post(path, body)) as { registrationResponse: string }
      const salt = this.randomSalt()
      const key = b.userIdentifier ?? b.email ?? ''
      this.meByEmail.set(key, {
        userId: 'user-' + (this.meByEmail.size + 1),
        email: key,
        kdfSalt: salt,
        kdfParams: '{"alg":"argon2id","m":65536,"t":3,"p":4,"version":1}',
      })
      this.unlockByEmail.set(key, {
        wrappedDek: '',
        wrappedDekRecovery: '',
        kdfSalt: salt,
        kdfParams: '{"alg":"argon2id","m":65536,"t":3,"p":4,"version":1}',
      })
      return { registrationResponse: res.registrationResponse, kdfSalt: salt } as TResponse
    }
    if (path === '/api/auth/register/finish') {
      const key = b.userIdentifier ?? b.email ?? ''
      this.records.set(key, b.registrationRecord ?? '')
      // forward to the opaque server with its expected key name
      await this.opaque.post(path, { ...b, userIdentifier: key })
      // session cookie "set"
      this.sessionCookie = 'session-for-' + b.userIdentifier
      this.unlockByEmail.set(b.userIdentifier ?? '', {
        ...this.unlockByEmail.get(b.userIdentifier ?? ''),
        wrappedDek: b.wrappedDek ?? '',
        wrappedDekRecovery: b.wrappedDekRecovery ?? '',
      } as { wrappedDek: string; wrappedDekRecovery: string; kdfSalt: string; kdfParams: string })
      return { userId: 'user-' + b.userIdentifier } as TResponse
    }
    if (path === '/api/auth/login/start') {
      const res = (await this.opaque.post(path, body)) as { loginResponse: string | null }
      return { serverMsg: res.loginResponse } as TResponse
    }
    if (path === '/api/auth/login/finish') {
      const key = b.email ?? b.userIdentifier ?? ''
      this.sessionCookie = 'session-for-' + key
      const unlock = this.unlockByEmail.get(key) ?? {
        wrappedDek: '',
        wrappedDekRecovery: '',
        kdfSalt: this.randomSalt(),
        kdfParams: '{"alg":"argon2id","m":65536,"t":3,"p":4,"version":1}',
      }
      return {
        userId: this.meByEmail.get(key)?.userId ?? 'user-x',
        kdfSalt: unlock.kdfSalt,
        kdfParams: unlock.kdfParams,
        wrappedDek: unlock.wrappedDek,
        wrappedDekRecovery: unlock.wrappedDekRecovery,
      } as TResponse
    }
    if (path === '/api/auth/me') {
      // find the most recent session
      const emails = [...this.meByEmail.keys()]
      const last = emails[emails.length - 1] ?? ''
      return this.meByEmail.get(last) as TResponse
    }
    if (path === '/api/auth/logout') {
      return {} as TResponse
    }
    throw new Error('fakeServer: unknown path ' + path)
  }

  private randomSalt(): string {
    const bytes = new Uint8Array(32)
    crypto.getRandomValues(bytes)
    let s = ''
    for (const b of bytes) s += String.fromCharCode(b)
    return btoa(s)
  }
}

let fake: FakeServer
let fetchMock: ReturnType<typeof vi.fn>

beforeEach(() => {
  fake = new FakeServer()
  fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input)
    const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : {}
    try {
      const data = await fake.post(path, body)
      return new Response(JSON.stringify(data ?? {}), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    } catch (e) {
      return new Response(JSON.stringify({ error: { code: 'auth_failed', message: String(e) } }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      })
    }
  })
  vi.stubGlobal('fetch', fetchMock)
  useAuth.setState({ status: 'anonymous', email: null, userId: null, busy: false, error: null })
  useSessionKeys.getState().lock()
})

describe('authStore.register (mock transport)', () => {
  it('creates the account, returns the phrase exactly once, and lands locked', async () => {
    const outcome = await useAuth.getState().register({
      email: 'Alice@Example.com',
      password: 'correct-horse-42',
    })
    expect(useAuth.getState().status).toBe('locked')
    expect(useAuth.getState().email).toBe('alice@example.com') // canonicalized
    expect(outcome.recoveryPhrase).toHaveLength(12)
    expect(outcome.confirmIndices).toHaveLength(3)
    // wire inspection: the password never crosses the transport
    for (const { body } of fake.wire) {
      expect(JSON.stringify(body)).not.toContain('correct-horse-42')
    }
  })

  it('sends the OPAQUE registration through the transport', async () => {
    await useAuth.getState().register({ email: 'b@example.com', password: 'pw-123456' })
    const paths = fake.wire.map((w) => w.path)
    expect(paths).toContain('/api/auth/register/start')
    expect(paths).toContain('/api/auth/register/finish')
  })
})

describe('authStore.login', () => {
  it('returns unlock material on success and lands locked', async () => {
    await useAuth.getState().register({ email: 'c@example.com', password: 'pw-123456' })
    const material = await useAuth
      .getState()
      .login({ email: 'c@example.com', password: 'pw-123456' })
    expect(useAuth.getState().status).toBe('locked')
    expect(material.kdfSalt.length).toBe(32)
  })

  it('rejects wrong password with the uniform message and no unlock', async () => {
    await useAuth.getState().register({ email: 'd@example.com', password: 'pw-123456' })
    await expect(
      useAuth.getState().login({ email: 'd@example.com', password: 'wrong-password' }),
    ).rejects.toThrow('invalid credentials')
    expect(useAuth.getState().error).toContain('Authentication failed')
  })

  it('rejects unknown user identically (D8)', async () => {
    await expect(
      useAuth.getState().login({ email: 'ghost@example.com', password: 'whatever' }),
    ).rejects.toThrow()
    expect(useAuth.getState().error).toContain('Authentication failed')
  })
})

describe('authStore.logout', () => {
  it('lands anonymous and clears the keystore', async () => {
    await useAuth.getState().register({ email: 'e@example.com', password: 'pw-123456' })
    await useAuth.getState().logout()
    expect(useAuth.getState().status).toBe('anonymous')
    expect(useSessionKeys.getState().locked).toBe(true)
  })
})
