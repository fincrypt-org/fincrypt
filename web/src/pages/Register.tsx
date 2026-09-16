/**
 * Register page (C2.5): OPAQUE registration → recovery phrase modal →
 * keystore unlock → dashboard. The password never leaves the device.
 */
import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../stores/authStore'
import { useSessionKeys } from '../stores/sessionKeys'
import RecoveryPhraseModal from '../components/RecoveryPhraseModal'

export default function Register() {
  const navigate = useNavigate()
  const { register, login, busy, error } = useAuth()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [localError, setLocalError] = useState<string | null>(null)
  const [pendingPhrase, setPendingPhrase] = useState<{
    phrase: string[]
    confirmIndices: number[]
  } | null>(null)

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    setLocalError(null)
    if (password !== confirm) {
      setLocalError('Passphrases do not match.')
      return
    }
    if (password.length < 12) {
      setLocalError('Use at least 12 characters — this passphrase encrypts everything.')
      return
    }
    try {
      const outcome = await register({ email, password })
      setPendingPhrase({
        phrase: outcome.recoveryPhrase,
        confirmIndices: outcome.confirmIndices,
      })
    } catch {
      // error is in the store; stay on the form
    }
  }

  async function afterPhraseConfirmed() {
    setPendingPhrase(null)
    // The just-registered session unlocks through the real path: login
    // (OPAQUE) returns the unlock material, then the keystore unwraps.
    try {
      const material = await login({ email, password })
      await useSessionKeys.getState().unlockWithPassphrase({
        pass: password,
        userId: material.wrapUserId,
        recordUserId: material.userId,
        kdfSalt: material.kdfSalt,
        kdfParamsJson: material.kdfParamsJson,
        wrappedDek: material.wrappedDek,
      })
      useAuth.getState().markUnlocked()
    } catch (e) {
      console.error('UNLOCK FAILED:', e)
    }
    navigate('/accounts')  // '/app' route doesn't exist yet in P2
  }

  return (
    <main style={{ padding: '2rem', maxWidth: 640 }}>
      <h1>Create account</h1>
      <p>
        Your passphrase encrypts everything on this device and never leaves it (OPAQUE). You will
        receive a 12-word recovery phrase, shown once.
      </p>
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
            minLength={12}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="new-password"
            style={{ display: 'block', width: '100%', padding: '0.5rem', marginTop: 4 }}
          />
        </label>
        <label>
          Confirm passphrase
          <input
            type="password"
            required
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            autoComplete="new-password"
            style={{ display: 'block', width: '100%', padding: '0.5rem', marginTop: 4 }}
          />
        </label>
        {(localError != null || error != null) && (
          <p role="alert" style={{ color: '#c0392b' }}>
            {localError ?? error}
          </p>
        )}
        <button
          type="submit"
          disabled={busy}
          style={{ padding: '0.6rem 1.2rem', cursor: busy ? 'wait' : 'pointer' }}
        >
          {busy ? 'Creating account…' : 'Create account'}
        </button>
        <p style={{ fontSize: '0.9rem' }}>
          Already have an account? <Link to="/login">Log in</Link>
        </p>
      </form>
      {pendingPhrase != null && (
        <RecoveryPhraseModal
          phrase={pendingPhrase.phrase}
          confirmIndices={pendingPhrase.confirmIndices}
          onConfirmed={() => {
            void afterPhraseConfirmed()
          }}
        />
      )}
    </main>
  )
}
