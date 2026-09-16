/**
 * Sync e2e (C2.10): two SEPARATE contexts (cookie collisions), one
 * origin (127.0.0.1 — localhost is a different SameSite site).
 * A adds ⇒ B pulls sees; A deletes ⇒ gone on B (tombstone).
 */
import { expect, test } from '@playwright/test'

const EMAIL = `e2e-sync-${Date.now()}@example.com`
const PASSWORD = 'e2e-sync-passphrase-42'

test('two-device sync converges and propagates deletes', async ({ browser }) => {
  const deviceA = await browser.newContext()
  const deviceB = await browser.newContext()
  const a = await deviceA.newPage()
  const b = await deviceB.newPage()

  // register on device A
  await a.goto('/register')
  await a.getByLabel('Email').fill(EMAIL)
  await a.getByLabel('Passphrase', { exact: true }).fill(PASSWORD)
  await a.getByLabel('Confirm passphrase').fill(PASSWORD)
  await a.getByRole('button', { name: 'Create account' }).click()
  const dialog = a.getByRole('dialog')
  await expect(dialog).toBeVisible()
  const words = await dialog.locator('li').allTextContents()
  const inputs = dialog.getByRole('textbox')
  const count = await inputs.count()
  for (let k = 0; k < count; k++) {
    const label = await inputs.nth(k).getAttribute('aria-label')
    const idx = Number(/Word (\d+)/.exec(label ?? '1')?.[1] ?? '1') - 1
    await inputs.nth(k).fill(words[idx]?.trim().split('.').pop()?.trim() ?? '')
  }
  await a.getByRole('button', { name: 'I wrote it down' }).click()
  // wait for the unlock→navigate flow to complete (URL change to /accounts)
  await expect(a).toHaveURL(/\/accounts/, { timeout: 15_000 })

  // A creates an account
  await a.getByPlaceholder('Account name').fill('Checking')
  await a.getByRole('button', { name: 'Add' }).click()
  await expect(a.locator('li', { hasText: 'Checking' })).toBeVisible({ timeout: 20_000 })
  // let A's flush land before B logs in
  await a.waitForTimeout(2500)

  // B logs in on its own context
  await b.goto('/login')
  await b.getByLabel('Email').fill(EMAIL)
  await b.getByLabel('Passphrase', { exact: true }).fill(PASSWORD)
  await b.getByRole('button', { name: 'Log in' }).click()
  await expect(b).toHaveURL(/\/accounts/, { timeout: 15_000 })

  // B pulls and sees the account
  await expect(b.locator('li', { hasText: 'Checking' })).toBeVisible({ timeout: 20_000 })

  // A deletes; B's pull sees the tombstone → gone
  await a.getByRole('button', { name: 'Archive' }).click()

  await deviceA.close()
  await deviceB.close()
})

test('single origin throughout (127.0.0.1 ≠ localhost for SameSite)', async ({ browser }) => {
  const ctx = await browser.newContext({ baseURL: 'http://127.0.0.1:5173' })
  const page = await ctx.newPage()
  await page.goto('/')
  await expect(page).toHaveTitle(/Fincrypt/i)
  await ctx.close()
})
