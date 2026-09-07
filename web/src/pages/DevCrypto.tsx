import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

/**
 * /dev/crypto — on-device crypto health check (C1.8 DoD).
 *
 * Runs the full local lifecycle in the REAL browser WebCrypto with
 * PASS/FAIL + timings: KDF → wrap → envelope roundtrip → recovery
 * recover → AAD-swap rejection. Not linked in prod nav; Playwright
 * (C1.9) drives this page as the browser-native proof that "passes in
 * Node, breaks in browser" cannot happen.
 *
 * Test params (m=8192) keep the roundtrip fast; vitest's golden-vector
 * suite pins exact bytes.
 */
type StepState = 'pending' | 'running' | 'pass' | 'fail'

interface Step {
  name: string
  state: StepState
  ms?: number
  detail?: string
}

const TEST_PARAMS = { alg: 'argon2id' as const, version: 19 as const, m: 8192, t: 1, p: 1 }

const enc = new TextEncoder()
const dec = new TextDecoder()

const INITIAL_STEPS: Step[] = [
  { name: '1. Argon2id KDF → KEK', state: 'pending' },
  { name: '2. DEK wrap/unwrap (60 B)', state: 'pending' },
  { name: '3. Envelope roundtrip (subkey + AAD)', state: 'pending' },
  { name: '4. Recovery phrase → DEK', state: 'pending' },
  { name: '5. AAD-swap rejected', state: 'pending' },
  { name: 'OVERALL', state: 'pending' },
]

export default function DevCrypto() {
  const [steps, setSteps] = useState<Step[]>(INITIAL_STEPS)
  const [running, setRunning] = useState(false)
  const [verdict, setVerdict] = useState<'idle' | 'pass' | 'fail'>('idle')

  const setStep = useCallback(
    (index: number, state: StepState, ms?: number, detail?: string): void => {
      setSteps((s) => s.map((x, i) => (i === index ? { ...x, state, ms, detail } : x)))
    },
    [],
  )

  const start = useCallback(async (): Promise<void> => {
    setVerdict('idle')
    setSteps(INITIAL_STEPS.map((x) => ({ ...x, state: 'pending' })))
    setRunning(true)
    try {
      const {
        argon2idDerive,
        importKek,
        generateKdfSalt,
        generateDek,
        wrapDek,
        unwrapDek,
        deriveSubkey,
        buildAad,
        encryptBytes,
        decryptBytes,
        generateRecoveryPhrase,
        wrapDekWithRecovery,
        recoverDek,
      } = await import('../crypto/index')

      const userId = 'dev-crypto-user@fincrypt.test'
      const pass = 'dev-crypto-passphrase'

      // 1. Argon2id KDF → KEK
      let t0 = performance.now()
      const kek = await importKek(await argon2idDerive(pass, generateKdfSalt(), TEST_PARAMS))
      setStep(
        0,
        'pass',
        performance.now() - t0,
        `argon2id m=${TEST_PARAMS.m}KiB (worker or fallback)`,
      )

      // 2. DEK wrap/unwrap
      t0 = performance.now()
      const dek = generateDek()
      const wrapped = await wrapDek(dek, kek, userId)
      if (wrapped.length !== 60) throw new Error(`wrapped length ${wrapped.length} != 60`)
      const unwrapped = await unwrapDek(wrapped, kek, userId)
      if (JSON.stringify([...unwrapped]) !== JSON.stringify([...dek]))
        throw new Error('DEK mismatch after unwrap')
      setStep(1, 'pass', performance.now() - t0, '60-byte wrap, DEK roundtrip')

      // 3. envelope roundtrip
      t0 = performance.now()
      const type = 'transactions' as const
      const recordId = 'dev-crypto-record-1'
      const plaintext = 'DEV CRYPTO: envelope roundtrip sample'
      const subkey = await deriveSubkey(unwrapped, type)
      const aad = buildAad(userId, type, recordId)
      const packed = await encryptBytes(subkey, enc.encode(plaintext), aad)
      const pt = await decryptBytes(subkey, packed, aad)
      if (dec.decode(pt) !== plaintext) throw new Error('plaintext mismatch')
      setStep(2, 'pass', performance.now() - t0, 'encrypt/decrypt via HKDF subkey + mandatory AAD')

      // 4. recovery phrase → DEK
      t0 = performance.now()
      const { mnemonic } = generateRecoveryPhrase()
      const wrappedRecovery = await wrapDekWithRecovery(unwrapped, mnemonic, userId)
      const recovered = await recoverDek(wrappedRecovery, mnemonic, userId)
      if (JSON.stringify([...recovered]) !== JSON.stringify([...dek]))
        throw new Error('recovered DEK mismatch')
      setStep(3, 'pass', performance.now() - t0, 'BIP39 phrase → recovery KEK → same DEK')

      // 5. AAD-swap must fail
      t0 = performance.now()
      const otherAad = buildAad(userId, 'chat', 'different-record')
      let swapFailed = false
      try {
        await decryptBytes(subkey, packed, otherAad)
      } catch {
        swapFailed = true
      }
      if (!swapFailed) throw new Error('AAD swap DID NOT fail — binding broken')
      setStep(4, 'pass', performance.now() - t0, 'ciphertext bound to its record')

      setStep(5, 'pass')
      setVerdict('pass')
    } catch (err) {
      setStep(5, 'fail', undefined, err instanceof Error ? err.message : String(err))
      setVerdict('fail')
    } finally {
      setRunning(false)
    }
  }, [setStep])

  // auto-run once on mount — the page doubles as an instant health check
  useEffect(() => {
    void start()
  }, [start])

  return (
    <main style={{ padding: '2rem', fontFamily: 'system-ui', maxWidth: 720 }}>
      <h1>/dev/crypto</h1>
      <p>
        On-device crypto health check. Runs the full lifecycle with the browser&apos;s native
        WebCrypto. Diagnostic only — not linked from the main navigation.
      </p>
      <button onClick={() => void start()} disabled={running} data-testid="dev-crypto-rerun">
        {running ? 'running…' : 're-run'}
      </button>
      <ol style={{ lineHeight: 1.8 }} data-testid="crypto-steps">
        {steps.map((s, i) => (
          <li key={s.name} data-testid={`step-${i}`} data-state={s.state}>
            <strong>{s.name}</strong> — {s.state}
            {typeof s.ms === 'number' ? ` (${s.ms.toFixed(0)} ms)` : ''}
            {s.detail ? ` — ${s.detail}` : ''}
          </li>
        ))}
      </ol>
      <h2 data-testid="crypto-verdict" data-verdict={verdict}>
        {verdict === 'pass'
          ? 'PASS — browser-native crypto healthy'
          : verdict === 'fail'
            ? 'FAIL'
            : '…'}
      </h2>
      <p>
        <Link to="/">back to app</Link>
      </p>
    </main>
  )
}
