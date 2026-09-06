import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { getHealth, type HealthStatus } from '../api/client'

// Home is the placeholder landing page; the footer shows live backend
// status — day-1 proof of the full dev loop (Vite -> proxy -> Go -> PG).
export default function Home() {
  const [health, setHealth] = useState<HealthStatus | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    getHealth()
      .then((h) => {
        if (!cancelled) setHealth(h)
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e.message : 'unknown error')
      })
    return () => {
      cancelled = true
    }
  }, [])

  return (
    <main style={{ padding: '2rem', fontFamily: 'system-ui' }}>
      <h1>Fincrypt</h1>
      <p>End-to-end encrypted personal finance. The server stores ciphertext only.</p>
      <nav>
        <Link to="/login">Log in</Link> · <Link to="/register">Create account</Link>
      </nav>
      <footer style={{ marginTop: '2rem', color: '#666' }}>
        backend:{' '}
        {health ? (
          <span data-testid="backend-status">{health.status}</span>
        ) : error ? (
          <span data-testid="backend-status">unreachable ({error})</span>
        ) : (
          <span data-testid="backend-status">checking…</span>
        )}
      </footer>
    </main>
  )
}
