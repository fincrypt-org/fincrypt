/**
 * In-memory OPAQUE "server" for tests: runs the exact serenity-kit
 * server-side primitives behind a Transport, standing in for the P2 Go
 * endpoints. Lets us assert the full register/login roundtrip and
 * inspect every wire message for password material.
 */
import * as opaque from '@serenity-kit/opaque'
import type { Transport } from './opaque'

await opaque.ready

export class MockOpaqueServer implements Transport {
  private serverSetup = opaque.server.createSetup()
  private records = new Map<string, string>()

  /** every JSON body that traversed the transport, in order */
  readonly wireLog: Array<{ path: string; body: unknown }> = []

  async post<TRequest extends object, TResponse>(path: string, body: TRequest): Promise<TResponse> {
    this.wireLog.push({ path, body })
    const req = body as Record<string, string>
    const userIdentifier: string = req.userIdentifier ?? ''
    switch (path) {
      case '/api/auth/register/start': {
        const { registrationResponse } = opaque.server.createRegistrationResponse({
          serverSetup: this.serverSetup,
          registrationRequest: req.registrationRequest ?? '',
          userIdentifier,
        })
        return { registrationResponse } as TResponse
      }
      case '/api/auth/register/finish': {
        this.records.set(userIdentifier, req.registrationRecord ?? '')
        return { ok: true } as TResponse
      }
      case '/api/auth/login/start': {
        const record = this.records.get(userIdentifier)
        const { loginResponse } = opaque.server.startLogin({
          serverSetup: this.serverSetup,
          registrationRecord: record ?? null,
          startLoginRequest: req.startLoginRequest ?? '',
          userIdentifier,
        })
        // loginResponse may be null for unknown users (fake-record path)
        return { loginResponse: loginResponse ?? null } as TResponse
      }
      case '/api/auth/login/finish': {
        return { ok: true } as TResponse
      }
      default:
        throw new Error(`mockOpaqueServer: unknown path ${path}`)
    }
  }
}
