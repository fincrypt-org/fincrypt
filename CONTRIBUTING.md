# Contributing to Fincrypt

Thank you for helping build a personal-finance platform whose operator
cannot read user data. These rules exist to keep that promise auditable.

## Binding rules

These are enforced mechanically where possible and by review everywhere
else. Violations void the E2EE claim and will be reverted.

1. **Migrations are append-only.** Never edit an applied migration file.
   The runner creates the `schema_migrations` ledger itself (before first
   apply — 001 contains app tables only) and checksum-verifies every
   applied file against it; editing `001_initial_schema.sql` after it
   has been applied makes the server refuse to boot. All changes are new
   files (`002_*.sql`, `003_*.sql`, …).

2. **Any change to the crypto core requires a THREAT_MODEL.md delta in
   the same PR.** `web/src/crypto/` and anything the §0 crypto spec
   touches (KDF, AEAD, key derivation, OPAQUE/SRP, recovery) is the
   crypto core. No exceptions — a crypto change without a threat-model
   update is an incomplete change.

3. **Never commit secrets or real fixture data.** Secrets live in the
   environment (see `.env.example` for the shape). Test fixtures use
   obviously fake values. CI runs gitleaks on every push.

4. **Zero telemetry is policy, not preference.** No analytics
   dependencies (CI `no-telemetry` gate fails on sentry/posthog/
   plausible/segment/ga/mixpanel/matomo/firebase-analytics/amplitude),
   no crash reporters, no phone-home. Diagnostics stay on-device.

## Getting started

```sh
docker compose up -d postgres   # database
make dev                        # Go API on :8080
make web-dev                    # Vite dev server on :5173 (proxies /api)
make ci                         # everything CI runs
```

Go 1.22+ (or newer) and Docker are the only host prerequisites.

## Before you open a PR

- `make ci` is green locally.
- New behavior has tests (Go: `go test ./...`; web: `npm run test -- --run`).
- Migrations, if any, are new numbered files.
- No new dependencies that phone home; justify any new dependency in the
  PR description.
- Commit messages follow Conventional Commits (`feat:`, `fix:`, `chore:`, …).

## Code style

Go: gofmt + golangci-lint (config in `.golangci.yml`).
Web: prettier + eslint, TypeScript strict (`tsc --noEmit` must be clean).

## License

By contributing you agree that your contributions are licensed under
the AGPL-3.0 license that covers this repository.