/**
 * Decisive probe: run the ENTIRE OPAQUE register→login in the browser's
 * JS context via page.evaluate — bypassing the React store entirely.
 * If this passes, the bug is in the store; if it fails, the browser
 * module itself is broken.
 */
import { expect, test } from '@playwright/test'

test('pure in-browser OPAQUE roundtrip (no store)', async ({ page }) => {
  await page.goto('/register')
  const result = await page.evaluate(async () => {
    const m = await import('/node_modules/.vite/deps/@serenity-kit_opaque.js')
    await m.ready
    const email = `pure-${Date.now()}@example.com`
    const password = 'pure-probe-42'
    const post = async (path: string, body: unknown) => {
      const res = await fetch(path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      return { status: res.status, body: (await res.json()) as Record<string, unknown> }
    }
    const stdToUrl = (std: string) => {
      const bin = atob(std)
      return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
    }
    // register
    const r1 = m.client.startRegistration({ password })
    const s1 = await post('/api/auth/register/start', {
      email,
      userIdentifier: email,
      registrationRequest: r1.registrationRequest,
    })
    if (s1.status !== 200) return 'register/start failed: ' + JSON.stringify(s1.body)
    const r3 = m.client.finishRegistration({
      clientRegistrationState: r1.clientRegistrationState,
      registrationResponse: stdToUrl(s1.body.registrationResponse as string),
      password,
    })
    const s2 = await post('/api/auth/register/finish', {
      email,
      registrationRecord: r3.registrationRecord,
      wrappedDek: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBw',
      wrappedDekRecovery: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBw',
      kdfSalt: s1.body.kdfSalt,
      kdfParams: { alg: 'argon2id', version: 19, m: 65536, t: 3, p: 4 },
    })
    if (s2.status !== 201) return 'register/finish failed: ' + JSON.stringify(s2.body)
    // login
    const l1 = m.client.startLogin({ password })
    const l2 = await post('/api/auth/login/start', {
      email,
      userIdentifier: email,
      startLoginRequest: l1.startLoginRequest,
    })
    if (l2.status !== 200) return 'login/start failed'
    let l3
    try {
      l3 = m.client.finishLogin({
        clientLoginState: l1.clientLoginState,
        loginResponse: stdToUrl(l2.body.serverMsg as string),
        password,
      })
    } catch (e) {
      return 'finishLogin threw: ' + String(e).slice(0, 120)
    }
    if (l3 == null) return 'MAC FAIL'
    const l4 = await post('/api/auth/login/finish', {
      email,
      finishLoginRequest: l3.finishLoginRequest,
    })
    return l4.status === 200 ? 'PURE BROWSER PASS' : 'login/finish failed ' + l4.status
  })
  console.log('RESULT:', result)
  expect(result).toBe('PURE BROWSER PASS')
})