/**
 * Auth store (C2.5): anonymous → locked → unlocked lifecycle.
 *
 * Register (all client-side except OPAQUE messages + the finish POST):
 *   1. startRegistration locally (password never leaves the device)
 *   2. POST register/start → registrationResponse + fresh kdfSalt
 *   3. finishRegistration locally → registrationRecord (+ exportKey,
 *      which is NOT part of the v1 key hierarchy — OPAQUE-NOTES.md)
 *   4. KEK = Argon2id(password, salt) → generateDek → wrapDek
 *   5. recovery: generateRecoveryPhrase → deriveRecoveryKek → wrap
 *   6. POST register/finish with both wrapped DEKs + kdfParams
 *   7. phrase shown ONCE via the modal (caller confirms 3 indices)
 *
 * Login: OPAQUE login over the transport, then GET /api/auth/me for
 * identity + unlock material. Wrong password / unknown user both land
 * as the wrapper returning undefined → uniform message (D8).
 *
 * Session state (httpOnly cookie) is separate from unlock state
 * (keystore holds the DEK): 'locked' = cookie present, vault sealed.
 */
import { create } from 'zustand'
import * as opaque from '@serenity-kit/opaque'
import { ApiError, apiFetch, getMe, logout as apiLogout } from '../api/auth'
import {
  deriveKek,
  deriveKekOffThread,
  generateDek,
  generateRecoveryPhrase,
  pickConfirmIndices,
  wrapDek,
  wrapDekWithRecovery,
  opaqueRegister,
  opaqueLogin,
} from '../crypto/index'
import type { KdfParams } from '../crypto/kdf'
import { DEFAULT_KDF_PARAMS } from '../crypto/kdf'
import { fromB64 } from '../crypto/b64'
import type { LoginFinishResponse } from '../api/auth'

export type AuthStatus = 'anonymous' | 'locked' | 'unlocked'

export interface RegisterOutcome {
  userId: string
  /** 12-word phrase, shown ONCE — the modal captures it before unmount */
  recoveryPhrase: string[]
  confirmIndices: number[]
}

export interface LoginUnlockMaterial {
  userId: string
  email: string
  debugSalt: string
  debugParams: unknown
  /** the OPAQUE user identifier the wrap AAD is bound to (canonical email) */
  wrapUserId: string
  kdfSalt: Uint8Array
  kdfParamsJson: string
  wrappedDek: Uint8Array
  wrappedDekRecovery: Uint8Array
}

interface AuthState {
  status: AuthStatus
  email: string | null
  userId: string | null
  /** set while an OPAQUE roundtrip is in flight */
  busy: boolean
  /** last auth error (user-facing message, no key material) */
  error: string | null

  register(args: { email: string; password: string }): Promise<RegisterOutcome>
  login(args: { email: string; password: string }): Promise<LoginUnlockMaterial>
  /** refresh restores 'locked' from the session cookie after a reload. */
  refresh(): Promise<void>
  logout(): Promise<void>
  /** called by the keystore when unlock succeeds (status promotion). */
  markUnlocked(): void
  clearError(): void
}

export const useAuth = create<AuthState>((set) => ({
  status: 'anonymous',
  email: null,
  userId: null,
  busy: false,
  error: null,

  async register(args) {
    const email = args.email.trim().toLowerCase()
    const password = args.password
    set({ busy: true, error: null })
    try {
      // 1. client starts registration (KSF runs here, client-side)
      const started = opaque.client.startRegistration({ password })
      // 2. server half: OPRF evaluation + fresh salt
      const startRes = await apiFetch<{ registrationResponse: string; kdfSalt: string }>(
        '/api/auth/register/start',
        {
          method: 'POST',
          body: JSON.stringify({
            email,
            userIdentifier: email,
            registrationRequest: started.registrationRequest,
          }),
        },
      )
      // 3. client finishes with the server response. serenity's WASM only
      // decodes base64url-no-pad; the server speaks padded std — convert
      // at the boundary (exactly once, both directions, per §P2-0).
      const finished = opaque.client.finishRegistration({
        clientRegistrationState: started.clientRegistrationState,
        registrationResponse: stdToUrl(startRes.registrationResponse),
        password,
      })
      // 4. passphrase KEK → DEK → wrap (worker when available)
      const salt = fromB64(startRes.kdfSalt)
      const params: KdfParams = DEFAULT_KDF_PARAMS
      let kek: CryptoKey
      try {
        const off = await deriveKekOffThread(password, salt, params)
        kek = off.kek
      } catch {
        kek = await deriveKek(password, salt, params)
      }
      const dek = generateDek()
      const wrappedDek = await wrapDek(dek, kek, email)
      // 5. recovery path (D4): phrase → KEK → wrap
      const generated = generateRecoveryPhrase()
      const phrase = generated.words
      const wrappedRecovery = await wrapDekWithRecovery(dek, phrase.join(' '), email)
      // 6. persist
      const finishRes = await apiFetch<{ userId: string }>('/api/auth/register/finish', {
        method: 'POST',
        body: JSON.stringify({
          email,
          registrationRecord: finished.registrationRecord,
          wrappedDek: toB64S(wrappedDek),
          wrappedDekRecovery: toB64S(wrappedRecovery),
          kdfSalt: startRes.kdfSalt,
          kdfParams: params,
        }),
      })
      const confirmIndices = pickConfirmIndices()
      set({ status: 'locked', email, userId: finishRes.userId, busy: false })
      return {
        userId: finishRes.userId,
        recoveryPhrase: phrase,
        confirmIndices,
      }
    } catch (e) {
      set({ busy: false, error: authErrorMessage(e) })
      throw e
    }
  },

  async login(args) {
    const email = args.email.trim().toLowerCase()
    const password = args.password
    set({ busy: true, error: null })
    try {
      // 1. start login (KSF runs client-side)
      const started = opaque.client.startLogin({ password })
      // 2. server: OPRF + masking (fake record for unknown users, D8)
      const startRes = await apiFetch<{ serverMsg: string }>('/api/auth/login/start', {
        method: 'POST',
        body: JSON.stringify({
          email,
          userIdentifier: email,
          startLoginRequest: started.startLoginRequest,
        }),
      })
      // 3. client verifies the server MAC. serenity throws on protocol
      // failures (fake record for unknown users) AND returns undefined on
      // client-detected MAC failures — both are 'invalid credentials' (D8).
      let finished: { finishLoginRequest: string } | undefined | null
      try {
        finished = opaque.client.finishLogin({
          clientLoginState: started.clientLoginState,
          loginResponse: stdToUrl(startRes.serverMsg),
          password,
        })
      } catch {
        finished = undefined
      }
      if (finished == null) {
        const err = new Error('invalid credentials')
        set({
          busy: false,
          error: 'Authentication failed — check your email and passphrase.',
        })
        throw err
      }
      // 4. server verifies our KE3 and releases the unlock material
      const finishRes = await apiFetch<LoginFinishResponse>('/api/auth/login/finish', {
        method: 'POST',
        body: JSON.stringify({ email, finishLoginRequest: finished.finishLoginRequest }),
      })
      // 5. identity echo
      const me = await getMe()
      set({ status: 'locked', email: me.email, userId: me.userId, busy: false })
      return {
        userId: finishRes.userId,
        email: me.email,
        wrapUserId: email,
        kdfSalt: fromB64(finishRes.kdfSalt),
        kdfParamsJson:
          typeof finishRes.kdfParams === 'string'
            ? finishRes.kdfParams
            : JSON.stringify(finishRes.kdfParams),
        wrappedDek: fromB64(finishRes.wrappedDek),
        wrappedDekRecovery: fromB64(finishRes.wrappedDekRecovery),
        debugSalt: finishRes.kdfSalt,
        debugParams: finishRes.kdfParams,
      }
    } catch (e) {
      set({ busy: false, error: authErrorMessage(e) })
      throw e
    }
  },

  async refresh() {
    try {
      const me = await getMe()
      set((prev) => ({
        email: me.email,
        userId: me.userId,
        status: prev.status === 'unlocked' ? 'unlocked' : 'locked',
      }))
    } catch {
      set({ status: 'anonymous', email: null, userId: null })
    }
  },

  async logout() {
    await apiLogout()
    set({ status: 'anonymous', email: null, userId: null })
  },

  markUnlocked: () => set({ status: 'unlocked' }),
  clearError: () => set({ error: null }),
}))

// toB64S is a local alias to avoid importing the whole frozen surface here.
function toB64S(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s)
}

/** stdToUrl converts padded std base64 to serenity's url-no-pad alphabet. */
function stdToUrl(std: string): string {
  // already url-safe (mock server emits serenity's alphabet directly)
  if (std.includes('-') || std.includes('_')) return std
  const bin = atob(std)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function authErrorMessage(e: unknown): string {
  if (e instanceof Error && e.message === 'invalid credentials') {
    return 'Authentication failed — check your email and passphrase.'
  }
  if (e instanceof ApiError) {
    if (e.status === 409) return 'An account with this email already exists.'
    if (e.status === 401) return 'Authentication failed — check your email and passphrase.'
    if (e.status === 429) return 'Too many attempts — wait a minute and try again.'
    return e.message
  }
  return 'Something went wrong — please try again.'
}

// opaqueRegister/opaqueLogin are re-exported so pages import from the
// store module, not the crypto surface directly.
export { opaqueRegister, opaqueLogin }
