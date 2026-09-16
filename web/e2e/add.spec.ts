/**
 * Probe 2: register → confirm → /accounts → ADD an account → check the
 * list. Mirrors freeze.spec's proven flow with a locator assertion.
 */
import { expect, test } from '@playwright/test'

test('register then add account', async ({ page }) => {
  const errors: string[] = []
  page.on('console', (msg) => {
    if (msg.type() === 'error') errors.push(msg.text())
  })
  await page.goto('/register')
  await page.getByLabel('Email').fill(`add-${Date.now()}@example.com`)
  await page.getByLabel('Passphrase', { exact: true }).fill('add-probe-pass-42')
  await page.getByLabel('Confirm passphrase').fill('add-probe-pass-42')
  await page.getByRole('button', { name: 'Create account' }).click()
  const dialog = page.getByRole('dialog')
  await dialog.waitFor({ state: 'visible', timeout: 8000 })
  const words = await dialog.locator('li').allTextContents()
  const inputs = dialog.getByRole('textbox')
  const count = await inputs.count()
  for (let k = 0; k < count; k++) {
    const label = await inputs.nth(k).getAttribute('aria-label')
    const idx = Number(/Word (\d+)/.exec(label ?? '1')?.[1] ?? '1') - 1
    await inputs.nth(k).fill(words[idx]?.trim().split('.').pop()?.trim() ?? '')
  }
  await page.getByRole('button', { name: 'I wrote it down' }).click()
  await expect(page).toHaveURL(/\/accounts/, { timeout: 15_000 })
  await page.getByPlaceholder('Account name').fill('Probe Account')
  await page.getByRole('button', { name: 'Add' }).click()
  const bad = errors.filter((e) => !e.includes('DEBUG'))
  if (bad.length > 0) console.log('CONSOLE ERRORS:', JSON.stringify(bad).slice(0, 400))
  await expect(page.locator('li', { hasText: 'Probe Account' })).toBeVisible({ timeout: 20_000 })
  expect(bad).toEqual([])
})