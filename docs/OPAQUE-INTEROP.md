# OPAQUE Cross-Language Interop — C2.0 Spike Result

**Status: INTEROP PROVEN — no SRP-6a fallback needed.** The serenity-kit
client (the exact WASM the browser ships) completes full OPAQUE
registration and login against the Go server half (`bytemare/opaque`),
with session keys matching byte-for-byte and wrong-password rejected.
Verified 2026-09-13 in `internal/auth/interop_test.go`.

## Pinned pair

| Side | Library | Version |
|---|---|---|
| Client (browser) | `@serenity-kit/opaque` | 1.1.0 (P1 pin) |
| Server (Go) | `github.com/bytemare/opaque` | v0.18.0 |

## Verified ciphersuite (must not drift)

Derived from the shipped WASM (opaque-ke **4.0.1**, `RustCrypto`) and
its Rust source (`serenity-kit/opaque/src/lib.rs`):

- OPRF: `ristretto255-SHA512`
- AKE: `TripleDh<ristretto255, SHA512>`
- KDF/MAC/Hash: SHA-512
- KSF: applied **client-side only** — serenity's `CustomKsf`
  (Argon2id `memory-constrained`: t=3, m=64 MiB, p=4, zero salt) runs
  inside `finishRegistration`/`finishLogin`. The Go server half uses
  the **identity KSF** (`Configuration.KSF = 0`).

## Wire formats (proven by the interop tests)

- Serenity emits **base64url-no-pad**; §P2-0 HTTP carries padded RFC
  4648 std b64. Conversion is at the door, exactly once — the tests
  exercise both directions (`urlToStd`/`respToURL`).
- Message sizes (ristretto255/SHA512): `registrationRequest` 32 B ·
  `registrationResponse` 64 B · `registrationRecord` 192 B · `KE1` 96 B.
- **ServerSetup = 128 B**, layout (opaque-ke 4.0.1, verified in source):
  `oprf_seed(64) || sk(32) || dummy_pk(32)`. The third block is the
  dummy key used ONLY for unknown-user fake responses — it is NOT the
  server's real AKE public key. Go derives the real pk as `sk·G`
  (`TestInteropServerSetupsMatch` proves this equals serenity's
  `getPublicKey`).

## Identities (the trap that cost the first login failure)

Serenity passes **no `identifiers` by default** → opaque-ke falls back
to the **static public keys** as identities (client identity = client's
record pk, server identity = server's static pk). Any Go-side custom
identity (`ServerKeyMaterial.Identity`, custom `ClientIdentity`) breaks
the AKE transcript. P2 rule: **identity fields stay `nil`/pk-derived on
the Go side**; `ServerID = "fincrypt-api-v1"` is reserved for a future
coordinated change on BOTH sides (it would require passing
`identifiers: {server: "fincrypt-api-v1"}` at every serenity call site
plus `Identity` in Go — a THREAT_MODEL delta, not a casual edit).

`credentialIdentifier` (OPRF key derivation input) remains the
lowercase email on both sides — Go `RegistrationResponse(req, email)`
and serenity's `userIdentifier` param. This is invisible to the client
and safe to keep per-user.

## KSF ownership

The stretch is client-side in serenity, so the server stores whatever
the client produced. Server-side KSF parameters (bytemare
`ksf.Argon2id`) are irrelevant and MUST stay identity in P2's handlers.
Consequence: the OPAQUE record's hardness is bounded by the
client-configured KSF (`memory-constrained` default) — the *passphrase*
KEK (separate, 64 MiB Argon2id) is the main defense; this residual is
accepted in THREAT_MODEL.

## Test machinery

- `internal/auth/spikeConfiguration()` — the Go `Configuration` to use
  for all P2 auth code.
- `internal/auth/testdata/spike_client.mjs` — stdio JSON driver around
  the real serenity WASM (runs from `web/node_modules`; kept for
  re-verification and C2.1's handler tests).
- `internal/auth/interop_test.go` — 4 tests: setup layout, full
  register, full login (+ session-key equality), wrong password.

Go module note: `go.mod` pins `github.com/bytemare/opaque v0.18.0`
(promoted from indirect during this spike).