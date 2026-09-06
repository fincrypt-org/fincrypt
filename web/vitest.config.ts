import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

// Vitest shares Vite's plugin pipeline; happy-dom gives the browser-like
// environment the crypto core depends on (WebCrypto semantics).
export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'happy-dom',
    globals: true,
    include: ['src/**/*.test.{ts,tsx}'],
  },
})
