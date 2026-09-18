/**
 * Isolation e2e (C2.10): a second user must see zero of user A's
 * records — 404 everywhere, empty sync (J3 end-to-end).
 */
import { expect, test } from '@playwright/test'

const EMAIL_A = `e2e-iso-a-${Date.now()}@example.com`
const EMAIL_B = `e2e-iso-b-${Date.now()}@example.com`
const PASSWORD = 'e2e-iso-passphrase-42'

async function register(page: import('@playwright/test').Page, email: string): Promise<void> {
  await page.goto('/register')
  await page.getByLabel('Email').fill(email)
  await page.getByLabel('Passphrase', { exact: true }).fill(PASSWORD)
  await page.getByLabel('Confirm passphrase').fill(PASSWORD)
  await page.getByRole('button', { name: 'Create account' }).click()
  const dialog = page.getByRole('dialog')
  await expect(dialog).toBeVisible()
  const words = await dialog.locator('li').allTextContents()
  const inputs = dialog.getByRole('textbox')
  const count = await inputs.count()
  for (let k = 0; k < count; k++) {
    const label = await inputs.nth(k).getAttribute('aria-label')
    const idx = Number(/Word (\d+)/.exec(label ?? '1')?.[1] ?? '1') - 1
    await inputs.nth(k).fill(words[idx]?.trim().split('.').pop()?.trim() ?? '')
  }
  await page.getByRole('button', { name: 'I wrote it down' }).click()
  // wait for the unlock→navigate flow to complete
  await expect(page).toHaveURL(/\/accounts/, { timeout: 15_000 })
}

test('user B sees none of user A’s records', async ({ browser }) => {
  const ctxA = await browser.newContext()
  const ctxB = await browser.newContext()
  const a = await ctxA.newPage()
  const b = await ctxB.newPage()

  await register(a, EMAIL_A)
  await a.getByPlaceholder('Account name').fill('A-private')
  await a.getByRole('button', { name: 'Add' }).click()
  await expect(a.locator('li', { hasText: 'A-private' })).toBeVisible({ timeout: 20_000 })

  await register(b, EMAIL_B)
  await expect(b.getByText('No accounts yet.')).toBeVisible()

  // B's sync returns zero A-records: B never sees 'A-private'
  await b.reload()
  await expect(b.getByText('A-private')).toBeHidden()

  await ctxA.close()
  await ctxB.close()
})
