#!/usr/bin/env bash
# no-telemetry check (shared by CI and `make ci`).
# Fails if any analytics dependency or built artifact is found.
# Package-name based (word-boundary + common scope paths) to avoid
# false positives from unrelated "segment"/"plausible" substrings in
# bundled framework code.
set -euo pipefail
cd "$(dirname "$0")/.."

patterns='(@sentry/|sentry-javascript|posthog|plausible-tracker|"segment-analytics"|segment-analytics-js|"@segment/|mixpanel|matomo|firebase-analytics|google-analytics|"gtag\.js"|gtag/js|amplitude-js|@amplitude/)'

scan() {
  # $1 = label, $2 = grep target(s), $3 = extra grep flags
  if grep -rE "$patterns" $3 "$2" 2>/dev/null | grep -q .; then
    echo "ERROR: analytics artifact found in $1 — zero telemetry is policy" >&2
    grep -rE "$patterns" $3 "$2" 2>/dev/null | head -5 >&2
    exit 1
  fi
}

echo "scanning package manifests…"
if grep -qiE "$patterns" web/package.json web/package-lock.json go.mod go.sum; then
  echo "ERROR: analytics dependency found — zero telemetry is policy" >&2
  grep -iE "$patterns" web/package.json web/package-lock.json go.mod go.sum | head -5 >&2
  exit 1
fi

echo "scanning built dist…"
(cd web && npm ci --silent && npm run build >/dev/null)
if grep -rqiE "$patterns" web/dist/; then
  echo "ERROR: analytics artifact found in dist — zero telemetry is policy" >&2
  grep -rqiE "$patterns" web/dist/ | head -3 >&2
  exit 1
fi

echo "no telemetry confirmed"