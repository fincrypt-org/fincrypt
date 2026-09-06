import { expect, test } from '@playwright/test'

// Smoke: the app shell loads and the title renders. The full dev-loop
// proof (backend status in the footer) needs `make dev` running and is
// exercised in P2 flows; CI compose-smoke covers the backend side.
test('app shell loads', async ({ page }) => {
  await page.goto('/')
  await expect(page).toHaveTitle(/Fincrypt/)
  await expect(page.getByRole('heading', { name: 'Fincrypt' })).toBeVisible()
})
