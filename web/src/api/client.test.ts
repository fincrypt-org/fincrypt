import { describe, expect, it } from 'vitest'
import { ApiError, apiFetch } from './client'

// Sanity: the typed client surfaces non-2xx as ApiError with status+code.
describe('apiFetch', () => {
  it('throws ApiError on non-2xx with parsed code', async () => {
    const originalFetch = globalThis.fetch
    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ error: 'nope', code: 'forbidden' }), {
        status: 403,
      })) as typeof fetch
    try {
      await expect(apiFetch('/api/x')).rejects.toMatchObject({
        name: 'ApiError',
        status: 403,
        code: 'forbidden',
      })
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('sends credentials: include on every request', async () => {
    let seenCredentials: string | undefined
    const originalFetch = globalThis.fetch
    globalThis.fetch = (async (_url, init) => {
      seenCredentials = init?.credentials
      return new Response(JSON.stringify({ status: 'ready' }), { status: 200 })
    }) as typeof fetch
    try {
      await apiFetch('/api/readyz')
      expect(seenCredentials).toBe('include')
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('deserializes JSON bodies on 2xx', async () => {
    const originalFetch = globalThis.fetch
    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ status: 'ready' }), { status: 200 })) as typeof fetch
    try {
      await expect(apiFetch<{ status: string }>('/api/readyz')).resolves.toEqual({
        status: 'ready',
      })
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('ApiError is an Error subclass', () => {
    expect(new ApiError(500, 'x', 'msg')).toBeInstanceOf(Error)
  })
})
