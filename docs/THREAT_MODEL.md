# Fincrypt Threat Model (v1)

Status: normative for v1. This document is the spec that CI gates and the
pre-launch external security review test against. Any change to the
crypto core requires a delta in this file in the same PR
(CONTRIBUTING.md rule 2).

## Product in one line

Web-first personal finance where all user records are encrypted on the
user's device (E2EE) and the operator stores and serves ciphertext only.

## Data zones

| Zone | Contents | Who can read it |
|---|---|---|
| **1. Device (user's browser)** | Passphrase, KEK, DEK, all decrypted data, working set cache (IndexedDB, wiped on sign-out) | The user |
| **2. At-rest E2EE (server + Postgres)** | Envelope ciphertext per row, wrapped DEKs, OPAQUE records, kdf_salt | No one — no key server-side |
| **3. Declared AI processing zone** | Document images / extracted text during smart scan, aggregated plaintext context during chat. Self-host: the user's own endpoint. Hosted: attested enclave (P5, not yet live — until then hosted users get the labeled on-device fallback only) | The user + the declared endpoint, during processing only |

Zone 3 explicitly covers **receipt and statement images** sent for smart
scan. Bytes never travel anywhere else: not to the operator's
infrastructure (until an attested enclave exists there), not to
third-party APIs. Trust labels name the endpoint that processed a
document; connecting an unverified endpoint always shows a downgrade
label. Zone 3 is re-entered transiently for Plaid sync in Phase 4.5 —
session-scoped, disclosed.

## Attacker table

| Attacker | Capabilities | What they get | What stops them / residual |
|---|---|---|---|
| **Curious operator** | Full read on server + DB | Email, row counts, timestamps, deterministic tx dates, IP/UA logs | All content ciphertext; AAD binds rows to (user, type, id) so ciphertext can't be shuffled across records undetected |
| **DB leak (dump/backups)** | Full ciphertext dump | Same as above | Offline passphrase cracking against `kdf_salt` is possible — see residual below |
| **Enclave host (hosted AI tier, P5)** | Host OS on the enclave machine | Encrypted inference traffic only | Nitro attestation with pinned PCRs; tampered PCR must refuse key release (tested) |
| **XSS on the web app** | Script in page context | Everything in Zone 1 while the tab is open | CSP (no inline scripts in prod builds), no third-party scripts ever, keys live in memory only (never localStorage) |
| **Malicious/compromised server (rewind/omit)** | Serve stale or missing rows, rollback deletes | Confusion, not plaintext | Client-tracked row versions detect rewind/omit; not fully prevented — a server can still withhold data (known limitation) |
| **Passphrase/phishing** | Trick user | Everything the passphrase protects | Onboarding shows recovery phrase once with unrecoverability warning; support never asks for passphrase or phrase |

## Honest residual

**A database compromise enables offline passphrase cracking, which means
full data loss.** Password-based E2EE derives keys from the passphrase;
`kdf_salt` and `kdf_params` are stored server-side by necessity.
Argon2id (64 MiB, t=3, p=4 — tunable upward per-user via `kdf_params`)
makes each guess expensive, but a weak passphrase remains a real risk
and no server-side measure fixes it.

Other residuals: metadata (row counts, timing) leaks by design;
deterministic `tx_date` is stored in the clear for range queries; a
malicious server can deny service entirely (availability is not a
confidentiality property).

## Self-hosting model

You are the operator. The consequences are yours to weigh:

- Your Postgres holds ciphertext only — same as hosted.
- The enclave tier is **optional** for self-hosters. Your local AI
  endpoint (e.g. `http://localhost:11434`) has **no attestation**: you
  trust your own machine, which is reasonable — but the trust label in
  the UI says so explicitly.
- Smart scan through your own endpoint sends document images to that
  endpoint in the clear **on your machine only**.

## Crypto implementation record

- **PAKE: OPAQUE (RFC 9807)** — the plan's SRP-6a fallback was NOT needed:
  `@serenity-kit/opaque` 1.1.0 (WASM bindings of `opaque-ke`, which was
  NCC-audited for WhatsApp) implements the finalized RFC with a clean
  browser API and stable client-side `exportKey`. The Go server side
  (Phase 2) uses `github.com/bytemare/opaque`, written by an RFC author.
  Client wrapper: `web/src/crypto/opaque.ts` behind a `Transport`
  interface; wire messages are base64 OPAQUE protocol payloads plus the
  `userIdentifier` (lowercase email) — no password material, asserted by
  a wire-inspection test (`opaque.test.ts`).
- **KDF: Argon2id** via hash-wasm (WASM), parameters in `users.kdf_params`
  (default m=64 MiB, t=3, p=4 — RFC 9106's second recommended profile).
  Verified byte-identical to Go x/crypto and RustCrypto reference KATs.
- **AEAD: AES-256-GCM**, 12-byte random nonce, mandatory AAD
  `v1|user_id|record_type|record_id` (swapping ciphertexts between
  records fails decryption — test-enforced).
- **Subkeys: HKDF-SHA256** off the DEK, info = record type.
- **Recovery: BIP39 12-word phrase** → Argon2id-derived recovery KEK.

## Claims → tests (seeded; grows with the code)

| Claim | Mechanized test | Status |
|---|---|---|
| Server storage is ciphertext-only | CI `no-plaintext`: after e2e, `pg_dump` is grepped for fixture plaintext; canary proves the scan machinery from day 1 | CI gate active (canary) |
| No secrets in the repository | gitleaks on every push, org-level secret scanning + push protection | CI gate active |
| Zero telemetry | CI `no-telemetry`: fails on any analytics dep or dist artifact | CI gate active |
| Request logs never contain bodies or cookies | Go test asserts log output lacks request body and cookie material | unit test (P0) |
| Migration history is immutable | checksum ledger + tamper test | unit test (P0) |
| No password material on the wire (OPAQUE) | wire-inspection test greps every transport message for password/encoded-password | unit test (P1) |
| Wrong passphrase fails unwrap; KDF matches reference KATs | crypto tests vs Go/RustCrypto-verified Argon2id vectors | unit test (P1) |
| AAD mismatch fails decryption | crypto test: swapping ciphertexts between records must fail | unit test (P1) |

## What is deliberately NOT defended against (v1)

- Compromise of the user's device while signed in (Zone 1 is open)
- Weak passphrases (see residual)
- Traffic-analysis / metadata privacy against the operator
- A malicious server withholding rows (detected client-side; not fully
  prevented)
- Quantum adversaries (AES-256 is the margin; OPAQUE/SRP are not PQ) —
  re-evaluated before v2