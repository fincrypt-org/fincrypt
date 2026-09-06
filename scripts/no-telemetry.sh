#!/usr/bin/env bash
# no-telemetry check (shared by CI and `make ci`).
# Fails if any analytics dependency or built artifact is found.
set -euo pipefail
cd "$(dirname "$0")/.."

patterns='sentry|posthog|plausible|segment|mixpanel|matomo|firebase-analytics|google-analytics|gtag|amplitude'

echo "scanning package manifests…"
if grep -riE "$patterns" web/package.json web/package-lock.json; then
  echo "ERROR: analytics dependency found — zero telemetry is policy" >&2
  exit 1
fi

echo "scanning go.mod…"
if grep -riE "$patterns" go.mod go.sum; then
  echo "ERROR: analytics dependency found in Go deps" >&2
  exit 1
fi

echo "scanning built dist…"
(cd web && npm ci --silent && npm run build >/dev/null)
if grep -riE "$patterns" web/dist/; then
  echo "ERROR: analytics artifact found in dist" >&2
  exit 1
fi

echo "no telemetry confirmed"