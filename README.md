# Fincrypt

Fincrypt is an open-source financial management platform where all data is encrypted end-to-end. Your transactions, accounts, budgets, and documents are encrypted on your device before they leave it — the server stores unreadable ciphertext and holds no keys. No plaintext financial data is ever leaked, to us or to anyone else.

Because it's open source, you can run it yourself and connect it to any open-source model for AI features like smart document scanning and category suggestions. The AI only ever sees what your own setup sends it, on your own terms — or nothing at all, since the core platform works fully without it.

## What it does

- **Track accounts and transactions** — manual entry always works, offline included
- **Smart document scan** — a receipt, invoice, or multi-page bank statement becomes transaction drafts you review and confirm (bring your own open-source vision model, or use the labeled on-device fallback)
- **CSV import** — processed entirely on your device, never uploaded
- **Multi-device sync** — encrypted data syncs across devices; conflicts and deletes are handled automatically
- **Budgets and reports** — category totals, cash flow, charts, all computed on your device from decrypted data

## How it works

The technology is simple: end-to-end encryption.

- Your passphrase derives your encryption keys on your device — it is never sent to the server. Login uses OPAQUE, so authentication proves your identity without revealing the password.
- Every record is encrypted with AES-256-GCM before it reaches the server, bound to your user and record type so nothing can be shuffled or swapped.
- The server is a dumb ciphertext store. A database leak gives an attacker unreadable blobs — nothing else.

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

## Self-hosting

You run the stack, you hold the keys, nothing leaves your machine. Docker Compose brings up the app and Postgres; point the AI features at any open-source model endpoint (Ollama, llama.cpp, anything OpenAI-compatible) and document images and AI queries go there and nowhere else. Full guide coming with the beta.

## Honest limits

- A database leak still lets an attacker try to crack your passphrase offline. A strong passphrase is the real defense — this is inherent to password-based encryption and we won't pretend otherwise.
- Lose your passphrase and your recovery phrase, and your data is gone. That's by design.
- The hosted version exists for convenience, but the codebase is the same: self-host and you're the operator.

## License

AGPL-3.0 — see [LICENSE](LICENSE). Optional AI model weights are Apache-2.0 and distributed separately.

## Status

Pre-beta. An external security review gates the launch. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full security model.