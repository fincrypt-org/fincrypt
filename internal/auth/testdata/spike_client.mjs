/**
 * C2.0 interop spike driver: runs the REAL serenity-kit/opaque client
 * (the same WASM the browser ships) as a stdio JSON peer so a Go test
 * can drive it through OPAQUE registration and login.
 *
 * Protocol: one JSON object per line on stdin → one JSON object per
 * line on stdout. Commands:
 *   {op:"registerStart", password}        → {registrationRequest}
 *   {op:"registerFinish", registrationResponse, clientRegistrationState, password}
 *                                         → {registrationRecord, exportKey}
 *   {op:"loginStart", password}           → {startLoginRequest}
 *   {op:"loginFinish", loginResponse, clientLoginState, password}
 *                                         → {finishLoginRequest, exportKey} | {failed:true}
 *   {op:"serverRegResponse", serverSetup, registrationRequest, userIdentifier}
 *                                         → {registrationResponse}
 *   {op:"serverLoginStart", serverSetup, registrationRecord|null, startLoginRequest, userIdentifier}
 *                                         → {loginResponse}
 *   {op:"serverLoginFinish", serverLoginState, finishLoginRequest}
 *                                         → {ok:true, sessionKey} | {failed:true}
 *   {op:"serverSetup"}                    → {serverSetup, serverPublicKey}
 *   {op:"getPub"}                         → {publicKey}  (of the last serverSetup)
 *
 * All b64 values are base64url-no-pad (serenity's native alphabet).
 */
import readline from 'node:readline'
import * as opaque from '../../../web/node_modules/@serenity-kit/opaque/esm/index.js'

await opaque.ready

let serverSetup = null
let serverLoginState = null

const rl = readline.createInterface({ input: process.stdin })
rl.on('line', (line) => {
  if (!line.trim()) return
  let req
  try {
    req = JSON.parse(line)
  } catch {
    process.stdout.write(JSON.stringify({ error: 'bad json' }) + '\n')
    return
  }
  try {
    switch (req.op) {
      case 'serverSetup': {
        serverSetup = opaque.server.createSetup()
        process.stdout.write(
          JSON.stringify({
            serverSetup,
            publicKey: opaque.server.getPublicKey(serverSetup),
          }) + '\n',
        )
        break
      }
      case 'registerStart': {
        const { clientRegistrationState, registrationRequest } = opaque.client.startRegistration({
          password: req.password,
        })
        process.stdout.write(
          JSON.stringify({ clientRegistrationState, registrationRequest }) + '\n',
        )
        break
      }
      case 'registerFinish': {
        const { registrationRecord, exportKey } = opaque.client.finishRegistration({
          clientRegistrationState: req.clientRegistrationState,
          registrationResponse: req.registrationResponse,
          password: req.password,
        })
        process.stdout.write(JSON.stringify({ registrationRecord, exportKey }) + '\n')
        break
      }
      case 'loginStart': {
        const { clientLoginState, startLoginRequest } = opaque.client.startLogin({
          password: req.password,
        })
        process.stdout.write(JSON.stringify({ clientLoginState, startLoginRequest }) + '\n')
        break
      }
      case 'loginFinish': {
        const result = opaque.client.finishLogin({
          clientLoginState: req.clientLoginState,
          loginResponse: req.loginResponse,
          password: req.password,
        })
        if (result == null) {
          process.stdout.write(JSON.stringify({ failed: true }) + '\n')
        } else {
          process.stdout.write(
            JSON.stringify({
              finishLoginRequest: result.finishLoginRequest,
              exportKey: result.exportKey,
              sessionKey: result.sessionKey,
            }) + '\n',
          )
        }
        break
      }
      case 'serverRegResponse': {
        const { registrationResponse } = opaque.server.createRegistrationResponse({
          serverSetup: req.serverSetup,
          registrationRequest: req.registrationRequest,
          userIdentifier: req.userIdentifier,
        })
        process.stdout.write(JSON.stringify({ registrationResponse }) + '\n')
        break
      }
      case 'serverLoginStart': {
        const { loginResponse, serverLoginState: sls } = opaque.server.startLogin({
          serverSetup: req.serverSetup,
          registrationRecord: req.registrationRecord,
          startLoginRequest: req.startLoginRequest,
          userIdentifier: req.userIdentifier,
        })
        serverLoginState = sls
        process.stdout.write(JSON.stringify({ loginResponse }) + '\n')
        break
      }
      case 'serverLoginFinish': {
        const { sessionKey } = opaque.server.finishLogin({
          serverLoginState: req.serverLoginState,
          finishLoginRequest: req.finishLoginRequest,
        })
        process.stdout.write(JSON.stringify({ sessionKey }) + '\n')
        break
      }
      case 'ping':
        process.stdout.write(JSON.stringify({ pong: true }) + '\n')
        break
      default:
        process.stdout.write(JSON.stringify({ error: 'unknown op ' + req.op }) + '\n')
    }
  } catch (e) {
    process.stdout.write(JSON.stringify({ error: String(e && e.message ? e.message : e) }) + '\n')
  }
})
rl.on('close', () => process.exit(0))