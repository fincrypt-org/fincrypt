# Security Policy

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report privately via GitHub Security Advisories ("Report a vulnerability"
on the Security tab of this repository), or contact the maintainers at
the address published on the fincrypt-org organization profile.

## Response targets

- **Acknowledgment:** within 3 business days.
- **Triage / severity assessment:** within 7 business days.
- **Fix or mitigation for critical issues:** best effort within 30 days,
  with an interim advisory if the fix takes longer.

## Scope

In scope: this repository (server, web client, migration tooling) and the
published inference/enclave images when they ship.

Out of scope: volumetric DoS, social engineering of our users, issues in
third-party services (Plaid, AWS) — report those to the vendor.

## Key-management contact

Questions about key management, the crypto design, or the threat model
(including responsible-disclosure of crypto-core issues) go through the
same private channel above; a PGP key fingerprint will be published here
before the beta launch.

## Safe harbor

Good-faith research and disclosure following this policy is authorized:
we will not pursue action against anyone who avoids privacy violations,
destroys data, or degrades service availability.

## What we will never ask you for

Your Fincrypt passphrase or recovery phrase. No support channel,
maintainer, or core team member will ever request them — anyone who does
is impersonating us.