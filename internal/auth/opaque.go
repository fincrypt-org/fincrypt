// Package auth hosts the OPAQUE (RFC 9807) server half used by P2's
// authentication endpoints.
//
// The spike driver in testdata/spike_client.mjs runs the real
// serenity-kit/opaque client (the same WASM the browser ships) as a
// stdio peer; the interop test in this package proves the Go server
// half (bytemare/opaque) interops with it byte-for-byte across the
// language boundary. That is the C2.0 gate: every later auth component
// codes against this exact configuration.
package auth

import (
	"crypto"

	"github.com/bytemare/opaque"
)

// ServerID is the OPAQUE server identity — byte-identical on both
// sides (P2-SPEC §P2-0; pitfall 4). The client passes it via the
// serenity `identifiers.server` option; Go sets it in
// ServerKeyMaterial.Identity.
const ServerID = "fincrypt-api-v1"

// Spike configuration: opaque-ke 4.x ciphersuite used by
// @serenity-kit/opaque 1.1.0 (verified from the shipped WASM and its
// Rust source):
//
//	OPRF  ristretto255-SHA512
//	AKE   TripleDh<ristretto255, SHA512>
//	Hash  SHA-512
//	KSF   applied CLIENT-side (serenity CustomKsf, Argon2id
//	      memory-constrained: t=3, m=64MiB, p=4, zero salt) — the
//	      server half never stretches.
//	Wire  base64url-no-pad, converted to padded std b64 at the door.
func spikeConfiguration() *opaque.Configuration {
	return &opaque.Configuration{
		OPRF: opaque.RistrettoSha512,
		AKE:  opaque.RistrettoSha512,
		KDF:  crypto.SHA512,
		MAC:  crypto.SHA512,
		Hash: crypto.SHA512,
		KSF:  0, // 0 = identity KSF (serenity stretches client-side only)
	}
}