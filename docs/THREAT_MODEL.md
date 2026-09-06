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
| **Malicious/compromised server (rewind/omit)** | Serve stale or missing rows, rollback deletes | Confusion, not plaintext | Client-tracked row versions detect rewind/omit; **not fully prevented** — a server can still withhold data. Documented limitation, not hidden |
| **Passphrase/phishing** | Trick user | Everything the passphrase protects | Onboarding shows recovery phrase once with unrecoverability warning; support never asks for passphrase or phrase |

## Honest residual

**A database compromise enables offline passphrase cracking, which means
full data loss.** Password-based E2EE derives keys from the passphrase;
`kdf_salt` and `kdf_params` are stored server-side by necessity. We
choose Argon2id (64 MiB, t=3, p=4 — tunable upward per-user via
`kdf_params`) to make each guess expensive, but a weak passphrase is a
real risk and no server-side measure fixes it. This is the known cost of
the "operator can't read your data" model. It is stated, not papered
over.

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

## Claims → tests (seeded; grows with the code)

| Claim | Mechanized test | Status |
|---|---|---|
| Server storage is ciphertext-only | CI `no-plaintext`: after e2e, `pg_dump` is grepped for fixture plaintext; canary proves the scan machinery from day 1 | CI gate active (canary) |
| No secrets in the repository | gitleaks on every push, org-level secret scanning + push protection | CI gate active |
| Zero telemetry | CI `no-telemetry`: fails on any analytics dep or dist artifact | CI gate active |
| Request logs never contain bodies or cookies | Go test asserts log output lacks request body and cookie material | unit test (P0) |
| AAD mismatch fails decryption | crypto test: swapping ciphertexts between records must fail | P1 (planned) |
| Wrong passphrase fails; KDF matches RFC 9106 vectors | crypto tests vs test vectors | P1 (planned) |
| Migration history is immutable | checksum ledger + tamper test | unit test (P0) |

## What is deliberately NOT defended against (v1)

- Compromise of the user's device while signed in (Zone 1 is open)
- Weak passphrases (see residual)
- Traffic-analysis / metadata privacy against the operator
- A malicious server withholding rows (detected client-side; not fully
  prevented)
- Quantum adversaries (AES-256 is the margin; OPAQUE/SRP are not PQ) —
  re-evaluated before v2