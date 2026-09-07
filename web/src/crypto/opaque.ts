/**
 * OPAQUE (RFC 9807) client wrapper.
 *
 * The password NEVER leaves the device: the client sends only opaque
 * protocol messages. This wrapper isolates the serenity-kit/opaque
 * calls behind a Transport interface so P2's HTTP endpoints plug in
 * here, and tests can run a full in-memory transport and inspect the
 * wire bytes (mock transport inspection is a plan-mandated test).
 *
 * Wire shapes (JSON, base64 payloads) — the contract P2 implements:
 *   POST /api/auth/register/start    { registrationRequest, userIdentifier }
 *   POST /api/auth/register/finish   { registrationRecord, userIdentifier }
 *   POST /api/auth/login/start       { startLoginRequest, userIdentifier }
 *   POST /api/auth/login/finish      { finishLoginRequest, userIdentifier }
 *
 * The `userIdentifier` is a server-side handle (an opaque record key);
 * we use the lowercase email. The server never sees the password.
 */
import * as opaque from '@serenity-kit/opaque'
import { fromB64, toB64 } from './b64'

export { fromB64, toB64 }

/** JSON request/response pair — mirrors what P2's HTTP handlers will do. */
export interface Transport {
  post<TRequest extends object, TResponse>(path: string, body: TRequest): Promise<TResponse>
}

export interface RegistrationResult {
  /** server-stored OPAQUE record (users.opaque_record); server-owned */
  userIdentifier: string
  /** stable client-only key material from OPAQUE exportKey (base64) */
  exportKey: string
}

export interface LoginResult {
  /** stable client-only key material from OPAQUE exportKey (base64) */
  exportKey: string
  sessionKey: string
  serverStaticPublicKey: string
}



/** canonicalUserIdentifier lowercases the email — the server's citext handles case-insensitivity. */
export function canonicalUserIdentifier(email: string): string {
  const normalized = email.trim().toLowerCase()
  if (normalized.length === 0 || !normalized.includes('@')) {
    throw new Error('opaque: userIdentifier must be a non-empty email')
  }
  return normalized
}

/**
 * register runs the OPAQUE registration flow against the transport.
 * The password is consumed locally by the opaque client and never
 * placed on any message.
 */
export async function register(
  transport: Transport,
  email: string,
  password: string,
): Promise<RegistrationResult> {
  const userIdentifier = canonicalUserIdentifier(email)
  const { clientRegistrationState, registrationRequest } = opaque.client.startRegistration({
    password,
  })
  const { registrationResponse } = await transport.post<
    { registrationRequest: string; userIdentifier: string },
    { registrationResponse: string }
  >('/api/auth/register/start', { registrationRequest, userIdentifier })
  const { registrationRecord, exportKey } = opaque.client.finishRegistration({
    clientRegistrationState,
    registrationResponse,
    password,
  })
  await transport.post<{ registrationRecord: string; userIdentifier: string }, { ok: boolean }>(
    '/api/auth/register/finish',
    { registrationRecord, userIdentifier },
  )
  return { userIdentifier, exportKey }
}

/**
 * login runs the OPAQUE login flow. Returns undefined when the server
 * reports unknown user OR the password is wrong — callers treat both as
 * "invalid credentials" (no user enumeration).
 */
export async function login(
  transport: Transport,
  email: string,
  password: string,
): Promise<LoginResult | undefined> {
  const userIdentifier = canonicalUserIdentifier(email)
  const { clientLoginState, startLoginRequest } = opaque.client.startLogin({ password })
  const loginStart = await transport.post<
    { startLoginRequest: string; userIdentifier: string },
    { loginResponse: string | null }
  >('/api/auth/login/start', { startLoginRequest, userIdentifier })
  if (loginStart.loginResponse == null) return undefined // unknown user (server sent fake-record response)
  const result = opaque.client.finishLogin({
    clientLoginState,
    loginResponse: loginStart.loginResponse,
    password,
  })
  if (result == null) return undefined // wrong password
  // Complete the exchange: server verifies our KE3.
  const loginFinish = await transport.post<
    { finishLoginRequest: string; userIdentifier: string },
    { ok: boolean }
  >('/api/auth/login/finish', { finishLoginRequest: result.finishLoginRequest, userIdentifier })
  if (!loginFinish.ok) return undefined
  return {
    exportKey: result.exportKey,
    sessionKey: result.sessionKey,
    serverStaticPublicKey: result.serverStaticPublicKey,
  }
}
