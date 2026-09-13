/**
 * Auth API (C2.5): the real Transport over the P2 HTTP endpoints.
 * Wire contract per §P2-0: JSON bodies, std-padded b64 payloads
 * (the server accepts either alphabet; we send padded std), uniform
 * error mapping. credentials: 'include' carries the session cookie.
 */
import { apiFetch, ApiError } from './client'
import type { Transport } from '../crypto/opaque'

export { apiFetch, ApiError }

// Server response shapes (§P2-0).
export interface RegisterStartResponse {
  registrationResponse: string // std b64
  kdfSalt: string // std b64, 32 B
}

export interface LoginStartResponse {
  serverMsg: string // std b64
}

export interface LoginFinishResponse {
  userId: string
  kdfSalt: string
  kdfParams: string
  wrappedDek: string
  wrappedDekRecovery: string
}

export interface MeResponse {
  userId: string
  email: string
  kdfSalt: string
  kdfParams: string
}

/**
 * HttpTransport adapts fetch to the crypto layer's Transport interface.
 * The OPAQUE wrapper's wire paths match §P2-0 exactly, so this is a
 * 1:1 passthrough.
 */
export const httpTransport: Transport = {
  async post<TRequest extends object, TResponse>(path: string, body: TRequest): Promise<TResponse> {
    return apiFetch<TResponse>(path, { method: 'POST', body: JSON.stringify(body) })
  },
}

// ─── non-OPAQUE session endpoints ────────────────────────────────────

export function getMe(): Promise<MeResponse> {
  return apiFetch<MeResponse>('/api/auth/me')
}

export async function logout(): Promise<void> {
  try {
    await apiFetch<unknown>('/api/auth/logout', { method: 'POST' })
  } catch (e) {
    if (e instanceof ApiError && e.status === httpUnauthorized) return
    throw e
  }
}

const httpUnauthorized = 401
