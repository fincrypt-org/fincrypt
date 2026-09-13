/**
 * Login page (C2.5): OPAQUE login → KEK → unwrap DEK → keystore →
 * dashboard. Wrong passphrase shows the WrapError message, never a stack.
 */
import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../stores/authStore'
import { useSessionKeys } from '../stores/sessionKeys'

export default function Login() {
  const navigate = useNavigate()
  const { login, busy, error, clearError } = useAuth()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    try {
      const material = await login({ email, password })
      // unlock the keystore with the material from login/finish
      try {
        await useSessionKeys.getState().unlockWithPassphrase({
          pass: password,
          userId: material.userId,
          kdfSalt: material.kdfSalt,
          kdfParamsJson: material.kdfParamsJson,
          wrappedDek: material.wrappedDek,
        })
        useAuth.getState().markUnlocked()
        navigate('/app')
      } catch {
        // WrapError: wrong passphrase for an existing account — the
        // message is user-facing (no stack, no key material)
        navigate('/locked')
      }
    } catch {
      // store error state drives the message
    }
  }

  return (
    <main style={{ padding: '2rem', maxWidth: 640 }}>
      <h1>Log in</h1>
      <p>OPAQUE authentication — the passphrase never leaves this device.</p>
      <form onSubmit={onSubmit} style={{ display: 'grid', gap: '0.75rem', maxWidth: 420 }}>
        <label>
          Email
          <input
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            autoComplete="email"
            style={{ display: 'block', width: '100%', padding: '0.5rem', marginTop: 4 }}
          />
        </label>
        <label>
          Passphrase
          <input
            type="password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            style={{ display: 'block', width: '100%', padding: '0.5rem', marginTop: 4 }}
          />
        </label>
        {error != null && (
          <p role="alert" style={{ color: '#c0392b' }} onClick={() => clearError()}>
            {error}
          </p>
        )}
        <button
          type="submit"
          disabled={busy}
          style={{ padding: '0.6rem 1.2rem', cursor: busy ? 'wait' : 'pointer' }}
        >
          {busy ? 'Verifying…' : 'Log in'}
        </button>
        <p style={{ fontSize: '0.9rem' }}>
          New here? <Link to="/register">Create an account</Link>
        </p>
      </form>
    </main>
  )
}
