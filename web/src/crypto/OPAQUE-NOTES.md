# OPAQUE implementation pin (C1.5 spike record)

## Decision

**OPAQUE (RFC 9807), no SRP-6a fallback.** The plan's §0 fallback clause
("SRP-6a only if the OPAQUE WASM/lib is immature") does not trigger —
the implementation below is mature, audited, and passes its own
roundtrip/wrong-password/unknown-user suites.

## Pinned implementation

| | |
|---|---|
| Library | `@serenity-kit/opaque` |
| Version | **1.1.0** |
| License | MIT |
| Underlying | WASM bindings of `opaque-ke` (RustCrypto/Facebook), **NCC-audited** for WhatsApp E2EE backups (June 2021 audit; fixes in v1.2.0+) |
| Ciphersuite | ristretto255 group (library default; P-256 variant exists as `@serenity-kit/opaque-p256`, not used) |
| KSF | library default (`memory-constrained` Argon2id inside OPAQUE; our independent passphrase-KEK KDF is separate — see below) |
| Integrity hash | sha512 of the tarball as installed in `web/package-lock.json` (npm integrity field pins it; `npm ci` enforces) |

## Client API surface (protocol-agnostic)

`opaque.ts` wraps the library behind a `Transport` interface:

- `register(transport, email, password)` → register-start POST →
  register-finish POST. Server stores `registrationRecord` in
  `users.opaque_record`.
- `login(transport, email, password)` → login-start POST → login-finish
  POST. Returns `undefined` on wrong password OR unknown user (both map
  to "invalid credentials"; no user enumeration).
- `canonicalUserIdentifier(email)` — lowercase trim; server-side handle.

Wire format: JSON `{ registrationRequest | startLoginRequest |
registrationRecord | finishLoginRequest, userIdentifier }` — base64url
protocol payloads + identifier only. **Wire-inspection test**
(`opaque.test.ts`) asserts absence of the password, its base64 encoding,
and decodes every message to check for embedded password material.

## Key-design decisions (THREAT_MODEL-delta material)

1. **OPAQUE `export_key` is NOT a KEK and never wraps the DEK.**
   The passphrase KEK is derived exclusively via
   `Argon2id(utf8(passphrase), kdf_salt, kdf_params)` — independent of
   any server-record-derived material. The OPAQUE `exportKey` is
   returned by the wrapper for FUTURE optional uses (e.g. a second
   device-binding factor) but is NOT part of the v1 key hierarchy.
   (This reverses the P1 first-cut test that used exportKey in an
   unlock path — that test now only asserts exportKey stability.)
2. `userIdentifier` = lowercase email (server-side record key). The
   server's citext email column stays the user-facing identity; the
   OPAQUE identifier never needs to be hidden from the client.

## In-process test server

`mockOpaqueServer.ts` runs the library's own server half behind the
same Transport, standing in for the P2 Go endpoints (which will use
`github.com/bytemare/opaque`, written by an RFC author). Live Go
interop is P2 work per the spec.

## Known library quirks (recorded so P2 doesn't rediscover them)

- `await opaque.ready` must precede any call in non-browser contexts.
- `server.startLogin` takes `registrationRecord` (not `record`).
- `server.createRegistrationResponse` requires `userIdentifier`
  (client-side calls do not).
- Its strings are base64-**url**; `b64.ts` normalizes.
- `client.finishLogin` returns `undefined` on failure (not null).
