import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Dev proxy: /api -> Go server (make dev). Cookie credentials flow through.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // listen on all interfaces so both localhost and 127.0.0.1 serve the
    // app (the e2e origin-consistency test hits 127.0.0.1 explicitly)
    host: true,
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: false,
      },
    },
  },
  test: {
    environment: 'happy-dom',
    globals: true,
    include: ['src/**/*.test.{ts,tsx}'],
  },
})
