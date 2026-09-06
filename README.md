# Fincrypt

**End-to-end encrypted personal finance. The operator cannot read your data.**

Fincrypt is a web-first personal finance platform where every record —
transactions, accounts, budgets, notes, documents, chat — is encrypted on
your device before it leaves it. The server is a dumb ciphertext store:
it can route and store your encrypted rows, but it has no key and no way
to read them. Your passphrase proves who you are without ever being sent
(OPAQUE), and your encryption keys are derived from it on your device.

## What the operator cannot see

- Transaction descriptions, amounts (beyond date-range structure),
  merchants, notes
- Account names, balances, institutions
- Budgets, categories, reports
- Documents you attach (receipts, statements) — encrypted before upload
- AI chat history — encrypted on-device
- Your passphrase — never transmitted, never stored

The operator *can* see: account email, coarse metadata (row counts,
timestamps), and the deterministic transaction dates used for sorting.
That is the whole list.

## How it works, in one paragraph

Two derivations of one passphrase: authentication (OPAQUE — the server
verifies without learning the password) and encryption (Argon2id → KEK →
unwraps a random 32-byte data key). Every row is encrypted with
AES-256-GCM with per-record AAD binding, per-purpose subkeys derived via
HKDF, and tombstone deletes for multi-device sync. Optional smart scan
sends document images only to your declared AI zone (your own endpoint,
or an attested enclave on the hosted tier) — never to the operator, never
to third parties. CSV import and manual entry never leave your device.

## Honest limits (the threat model, compressed)

- **Database compromise still enables offline passphrase cracking.**
  This is inherent to password-based E2EE. We say it plainly rather than
  paper over it: use a strong passphrase. See
  [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full model,
  including what a malicious server can and cannot do.
- **Lost passphrase + lost recovery phrase = permanent loss.** By
  design. Onboarding makes the phrase unmissable.
- Bank-feed sync (Plaid) is a minimal, session-scoped slice in v1 and
  intentionally exposes plaintext to Plaid during that sync window —
  disclosed, not hidden.

## Quickstart

```sh
docker compose up        # app + postgres
# open http://localhost:5173 (dev web) — register, get your recovery phrase
```

Development:

```sh
make dev                 # Go API + postgres
make web-dev             # Vite dev server
make ci                  # all gates CI runs
```

## Backups are safe by accident

Because every stored row is ciphertext, Postgres backups can be taken
naively — a leaked backup is indistinguishable from the live database:
unreadable without user passphrases.

## License

AGPL-3.0 — see [LICENSE](LICENSE). The optional AI model weights are
Apache-2.0 and distributed separately; nothing here depends on
license-contaminated weights.

## Status

Pre-beta. The crypto design is specified in docs/THREAT_MODEL.md and the
code follows it; an external security review gates the beta launch.