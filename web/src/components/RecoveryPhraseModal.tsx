/**
 * RecoveryPhraseModal (C2.5): the 12-word phrase is shown EXACTLY once,
 * with a 3-index confirmation (P1's pickConfirmIndices) and an
 * unrecoverability warning. Unmounting without confirmation is blocked
 * until the user either confirms or explicitly declines.
 */
import { useState } from 'react'
import { Link } from 'react-router-dom'

interface Props {
  phrase: string[]
  confirmIndices: number[]
  onConfirmed: () => void
}

export default function RecoveryPhraseModal({ phrase, confirmIndices, onConfirmed }: Props) {
  const [inputs, setInputs] = useState<Record<number, string>>({})
  const [error, setError] = useState<string | null>(null)

  const allFilled = confirmIndices.every((i) => (inputs[i] ?? '').trim().length > 0)

  function confirm() {
    const wrong = confirmIndices.filter(
      (i) => (inputs[i] ?? '').trim().toLowerCase() !== (phrase[i] ?? '').toLowerCase(),
    )
    if (wrong.length > 0) {
      const firstWrong = wrong[0] ?? 0
      setError('Some words do not match — check word ' + (firstWrong + 1) + '.')
      return
    }
    setError(null)
    onConfirmed()
  }

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="recovery-title"
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.55)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '1rem',
        zIndex: 1000,
      }}
    >
      <div
        style={{
          background: 'var(--card, #fff)',
          color: 'var(--foreground, #111)',
          border: '1px solid var(--border, #ddd)',
          borderRadius: 8,
          padding: '1.5rem',
          maxWidth: 560,
          width: '100%',
        }}
      >
        <h2 id="recovery-title" style={{ marginTop: 0 }}>
          Your recovery phrase
        </h2>
        <p style={{ color: 'var(--muted-foreground, #555)' }}>
          Write these 12 words down, in order, and keep them offline.
          <strong> They are shown only this once</strong> — there is no password reset, and without
          this phrase a forgotten passphrase means the data is unrecoverable.
        </p>
        <ol
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(3, 1fr)',
            gap: '0.25rem 1rem',
            padding: '1rem',
            margin: '1rem 0',
            background: 'var(--muted, #f5f5f5)',
            borderRadius: 6,
            listStyle: 'none',
            fontSize: '1.05rem',
          }}
        >
          {phrase.map((word, i) => (
            <li key={i}>
              <span style={{ color: 'var(--muted-foreground, #888)', marginRight: 6 }}>
                {i + 1}.
              </span>
              {word}
            </li>
          ))}
        </ol>
        <p style={{ fontWeight: 600 }}>
          Confirm you wrote it down — enter words {confirmIndices.map((i) => i + 1).join(', ')}:
        </p>
        <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.75rem' }}>
          {confirmIndices.map((i) => (
            <input
              key={i}
              aria-label={'Word ' + (i + 1)}
              value={inputs[i] ?? ''}
              onChange={(e) => setInputs((prev) => ({ ...prev, [i]: e.target.value }))}
              autoComplete="off"
              style={{
                flex: 1,
                padding: '0.5rem',
                border: '1px solid var(--border, #ccc)',
                borderRadius: 4,
                background: 'transparent',
                color: 'inherit',
              }}
            />
          ))}
        </div>
        {error != null && (
          <p role="alert" style={{ color: '#c0392b', margin: '0 0 0.75rem' }}>
            {error}
          </p>
        )}
        <button
          onClick={confirm}
          disabled={!allFilled}
          style={{
            padding: '0.6rem 1.2rem',
            borderRadius: 6,
            border: 'none',
            cursor: allFilled ? 'pointer' : 'not-allowed',
            background: 'var(--accent, #2563eb)',
            color: '#fff',
            fontWeight: 600,
          }}
        >
          I wrote it down
        </button>
        <p
          style={{
            fontSize: '0.85rem',
            color: 'var(--muted-foreground, #777)',
            marginTop: '0.75rem',
          }}
        >
          Lost the phrase already? <Link to="/">Continue without confirming</Link> — you can still
          use the vault with your passphrase, but recovery on a new device will be impossible.
        </p>
      </div>
    </div>
  )
}
