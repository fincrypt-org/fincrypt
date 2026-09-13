package api

// Envelope validation (J2): the P1-frozen shape, ported from
// web/src/crypto/envelope.ts parse rules, re-derived server-side.
// A malformed envelope NEVER reaches the DB. No decryption happens
// here — the server is a verifying ciphertext store.

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"

	"fmt"
	"regexp"
	"time"
)

// Envelope is the P1-frozen wire shape — §0 verbatim: fixed key order,
// NO version field, nonce/ciphertext/aad base64.
type Envelope struct {
	RecordID   string `json:"record_id"`
	Type       string `json:"type"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
	Aad        string `json:"aad"`
	Ts         string `json:"ts"`
}

// recordTypes is the closed §0 enum.
var recordTypes = map[string]bool{
	"transactions": true,
	"attachments":  true,
	"chat":         true,
	"accounts":     true,
	"vault":        true,
}

// uuidRe matches the canonical UUID shape (record_id).
var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// envelopeError is a validation failure with a stable reason (400 at
// the door; the message is generic — never echoes payload bytes).
type envelopeError struct{ reason string }

func (e *envelopeError) Error() string { return e.reason }

func envErr(format string, args ...any) error {
	return &envelopeError{reason: fmt.Sprintf(format, args...)}
}

// b64Strict decodes RFC 4648 base64 WITH padding only (I5: canonical).
// URL-safe alphabet and unpadded input are rejected.
func b64Strict(s string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	// re-encode to verify canonical form (no stray characters accepted
	// by Go's decoder that we would consider non-canonical)
	if base64.StdEncoding.EncodeToString(decoded) != s {
		return nil, fmt.Errorf("non-canonical base64")
	}
	return decoded, nil
}

// maxEnvelopeBytes is the per-envelope size cap (§P2-0: 256 KB ⇒ 413).
const maxEnvelopeBytes = 256 * 1024

// maxBatchEnvelopes is the push batch cap (§P2-0: ≤500).
const maxBatchEnvelopes = 500

// futureTolerance is the LWW future-poisoning guard (§P2-0: 5 min).
const futureTolerance = 5 * time.Minute

// buildAad recomputes the canonical AAD server-side (metadata is
// plaintext): "v1|<user>|<type>|<record_id>".
func buildAad(userID, recordType, recordID string) string {
	return "v1|" + userID + "|" + recordType + "|" + recordID
}

// validateEnvelope checks shape, encodings, sizes, AAD binding, and the
// ts guard for ONE envelope against the session user. J2.
func validateEnvelope(userID string, e Envelope) error {
	if e.RecordID == "" || e.Type == "" || e.Nonce == "" || e.Ciphertext == "" || e.Aad == "" || e.Ts == "" {
		return envErr("missing required field")
	}
	if !recordTypes[e.Type] {
		return envErr("unknown record type")
	}
	if !uuidRe.MatchString(e.RecordID) {
		return envErr("record_id is not a canonical uuid")
	}
	nonce, err := b64Strict(e.Nonce)
	if err != nil {
		return envErr("nonce encoding")
	}
	if len(nonce) != 12 {
		return envErr("nonce must be 12 bytes")
	}
	ciphertext, err := b64Strict(e.Ciphertext)
	if err != nil {
		return envErr("ciphertext encoding")
	}
	if len(ciphertext) < 17 {
		return envErr("ciphertext too short (tag+1 minimum)")
	}
	if e.Aad != buildAad(userID, e.Type, e.RecordID) {
		return envErr("aad binding mismatch")
	}
	ts, err := time.Parse(time.RFC3339, e.Ts)
	if err != nil {
		return envErr("ts not RFC 3339")
	}
	if ts.After(time.Now().Add(futureTolerance)) {
		return envErr("ts in the future beyond tolerance")
	}
	return nil
}

// validateBatchCount enforces the batch size cap before parsing.
func validateBatchCount(n int) error {
	if n > maxBatchEnvelopes {
		return envErr("batch too large")
	}
	return nil
}

// envelopeJSON is the strict parse: exact field set, duplicates
// rejected. Decoding uses json.RawMessage so we can detect duplicate
// keys manually (encoding/json silently takes the last).
type envelopeJSON map[string]json.RawMessage

var envelopeFields = map[string]bool{
	"record_id": true, "type": true, "nonce": true,
	"ciphertext": true, "aad": true, "ts": true,
}

// strictEnvelope parses raw JSON into an Envelope with an exact-field-
// set check (unknown fields, missing fields, and duplicate keys all
// rejected — encoding/json would silently take the last duplicate).
func strictEnvelope(raw json.RawMessage) (Envelope, error) {
	if err := rejectDuplicateKeys(raw); err != nil {
		return Envelope{}, err
	}
	var m envelopeJSON
	if err := json.Unmarshal(raw, &m); err != nil {
		return Envelope{}, envErr("not an object")
	}
	if len(m) != len(envelopeFields) {
		return Envelope{}, envErr("field set mismatch")
	}
	for k := range m {
		if !envelopeFields[k] {
			return Envelope{}, envErr("%s", "unknown field")
		}
	}
	var e Envelope
	if err := json.Unmarshal(raw, &e); err != nil {
		return Envelope{}, envErr("shape mismatch")
	}
	return e, nil
}

// rejectDuplicateKeys walks the top-level object's token stream and
// fails on any repeated key.
func rejectDuplicateKeys(raw json.RawMessage) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return envErr("not an object")
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return envErr("not an object")
	}
	seen := map[string]bool{}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return envErr("bad key")
		}
		key, ok := keyTok.(string)
		if !ok {
			return envErr("bad key")
		}
		if seen[key] {
			return envErr("duplicate field")
		}
		seen[key] = true
		var skip any
		if err := dec.Decode(&skip); err != nil {
			return envErr("bad value")
		}
	}
	return nil
}

// decodeB64Flexible decodes std-padded or url-no-pad base64 (either
// alphabet — clients legitimately emit both).
func decodeB64Flexible(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

// randomID is a UUID-shaped id for attachment storage names (C2.4).
//nolint:unused
func randomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto rand failed")
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
