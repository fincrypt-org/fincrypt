import { expect, test } from '@playwright/test'

/**
 * Browser-native crypto proof (C1.9): the /dev/crypto page runs the
 * full lifecycle with Chromium's REAL WebCrypto — the DoD check that
 * rules out "passes in Node, breaks in browser".
 */
test('/dev/crypto roundtrip passes in real Chromium', async ({ page }) => {
  await page.goto('/dev/crypto')

  // Wait for the auto-run verdict (KDF at test params + 4 steps is fast).
  const verdict = page.getByTestId('crypto-verdict')
  await expect(verdict).toHaveAttribute('data-verdict', 'pass', { timeout: 60_000 })

  // Every step passed:
  const steps = page.getByTestId('crypto-steps').locator('li')
  await expect(steps).toHaveCount(6)
  for (let i = 0; i < 5; i++) {
    await expect(page.getByTestId(`step-${i}`)).toHaveAttribute('data-state', 'pass')
  }
  // AAD binding actually enforced (step 5 is the swap-rejection proof):
  await expect(page.getByTestId('step-4')).toContainText('ciphertext bound to its record')
})
