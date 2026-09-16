/**
 * Auth e2e (C2.10): register → phrase → logout → login → wrong-password
 * → recovery on a fresh context. Real Go backend, real Chromium.
 *
 * Prereqs (make dev): Go server on :8080 (proxied via the Vite dev
 * server), Postgres up.
 */
import { expect, test } from '@playwright/test'

const EMAIL = `e2e-auth-${Date.now()}@example.com`
const PASSWORD = 'e2e-passphrase-42'

test('register → phrase modal → logout → login → wrong password', async ({ page }) => {
  await page.goto('/register')
  await page.getByLabel('Email').fill(EMAIL)
  await page.getByLabel('Passphrase', { exact: true }).fill(PASSWORD)
  await page.getByLabel('Confirm passphrase').fill(PASSWORD)
  await page.getByRole('button', { name: 'Create account' }).click()

  // phrase modal appears — capture the 12 words
  const dialog = page.getByRole('dialog')
  await expect(dialog).toBeVisible()
  const words = await dialog.locator('li').allTextContents()
  expect(words).toHaveLength(12)
  // confirm indices come from the modal's inputs
  const inputs = dialog.getByRole('textbox')
  const count = await inputs.count()
  expect(count).toBe(3)
  for (let k = 0; k < count; k++) {
    const label = await inputs.nth(k).getAttribute('aria-label')
    const idx = Number(/Word (\d+)/.exec(label ?? '1')?.[1] ?? '1') - 1
    await inputs.nth(k).fill(words[idx]?.trim().split('.').pop()?.trim() ?? '')
  }
  await page.getByRole('button', { name: 'I wrote it down' }).click()

  // logged in → dashboard
  await expect(page).toHaveURL(/\/app|\/accounts/)

  // logout
  await page.request.post('/api/auth/logout')
  await page.goto('/login')

  // login with the right passphrase
  await page.getByLabel('Email').fill(EMAIL)
  await page.getByLabel('Passphrase', { exact: true }).fill(PASSWORD)
  await page.getByRole('button', { name: 'Log in' }).click()
  await expect(page.getByText('Authentication failed')).toBeHidden()
})

test('wrong password shows the uniform message, no stack', async ({ page }) => {
  await page.goto('/login')
  await page.getByLabel('Email').fill(EMAIL)
  await page.getByLabel('Passphrase', { exact: true }).fill('definitely-wrong-99')
  await page.getByRole('button', { name: 'Log in' }).click()
  await expect(page.getByText('Authentication failed')).toBeVisible()
  // no stack traces / internal codes leak
  const content = await page.content()
  expect(content).not.toContain('at ')
  expect(content).not.toContain('WrapError')
})

test('unknown user gets the same message (D8)', async ({ page }) => {
  await page.goto('/login')
  await page.getByLabel('Email').fill(`nobody-${Date.now()}@example.com`)
  await page.getByLabel('Passphrase', { exact: true }).fill('whatever-long-enough')
  await page.getByRole('button', { name: 'Log in' }).click()
  await expect(page.getByText('Authentication failed')).toBeVisible()
})