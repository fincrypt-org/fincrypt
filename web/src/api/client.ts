// Typed API client. Cookie convention fixed from day 1: the session JWT
// lives in an httpOnly SameSite=Strict cookie, so every request sends
// credentials: 'include' and never touches localStorage.

export class ApiError extends Error {
  readonly status: number
  readonly code: string

  constructor(status: number, code: string, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
  }
}

/** apiFetch performs a JSON request with credentials and typed errors. */
export async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...init?.headers },
    ...init,
  })
  if (!res.ok) {
    let code = 'unknown'
    let message = `request failed with status ${res.status}`
    try {
      const body = (await res.json()) as { error?: string; code?: string }
      if (body.error) message = body.error
      if (body.code) code = body.code
    } catch {
      // non-JSON error body — keep defaults
    }
    throw new ApiError(res.status, code, message)
  }
  return (await res.json()) as T
}

export interface HealthStatus {
  status: string
}

/** getHealth calls the backend readiness endpoint through the dev proxy. */
export function getHealth(): Promise<HealthStatus> {
  return apiFetch<HealthStatus>('/api/readyz')
}
