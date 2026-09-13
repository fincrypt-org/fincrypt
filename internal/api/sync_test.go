package api

// C2.3 suites: malformed envelopes (≥12 cases, J2), LWW/tombstones
// (J4), cross-user isolation (J3), convergence (I12). Drives the real
// HTTP handlers against the live Postgres with Go-built envelopes —
// sync never decrypts, so no client is needed.

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fincrypt-org/fincrypt/internal/auth"
)

// testUser is a registered user with a hand-issued session (the session
// layer is stateless; registration only seeds the users row).
type testUser struct {
	id    string
	email string
	ctx   userCtx
}

// userCtx is a type-distinct handle for the two-user isolation matrix.
type userCtx struct{ token string }

func (u userCtx) do(t *testing.T, s *Server, method, path string, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	return authedRequest(t, s, u.token, method, path, body)
}

// syncTestEnv boots a server + two registered, session-holding users.
func syncTestEnv(t *testing.T) (*Server, testUser, testUser) {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	pool, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Skipf("no DB: %v", err)
	}
	t.Cleanup(pool.Close)

	setupB64, err := auth.GenerateServerSetup()
	if err != nil {
		t.Fatal(err)
	}
	svc, err := auth.NewService(pool, testAPILogger(), setupB64)
	if err != nil {
		t.Fatal(err)
	}
	waitForUsersTable(t, pool)
	s := NewServerWithAuthPool(authTestConfig(), pool, svc, testAPILogger())

	u1 := createTestUser(t, s, pool, "syncA-"+uniqSuffix()+"@example.com")
	u2 := createTestUser(t, s, pool, "syncB-"+uniqSuffix()+"@example.com")
	return s, u1, u2
}

// createTestUser inserts the user row directly (sync tests don't
// exercise OPAQUE) and mints a session token with the test key.
func createTestUser(t *testing.T, s *Server, pool *pgxpool.Pool, email string) testUser {
	t.Helper()
	var id string
	err := pool.QueryRow(t.Context(),
		`insert into users (email, opaque_record, kdf_salt, kdf_params, wrapped_dek, wrapped_dek_recovery)
		 values ($1, $2, $3, $4, $5, $6) returning id::text`,
		email, []byte("test-record"), make([]byte, 32), []byte(`{"alg":"argon2id","m":65536,"t":3,"p":4,"version":1}`),
		make([]byte, 48), make([]byte, 48),
	).Scan(&id)
	if err != nil {
		t.Fatalf("createTestUser: %v", err)
	}
	claims := sessionClaims{
		UserID: id,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(sessionTTL)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(s.cfg.SessionKeys[0])
	if err != nil {
		t.Fatal(err)
	}
	return testUser{id: id, email: email, ctx: userCtx{token: signed}}
}

func authedRequest(t *testing.T, s *Server, token, method, path string, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var req *http.Request
	if body != nil {
		raw, _ := json.Marshal(body)
		req = httptest.NewRequestWithContext(t.Context(), method, path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequestWithContext(t.Context(), method, path, nil)
	}
	req.Header.Set("Origin", testOrigin)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	var resp map[string]any
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	}
	return rec, resp
}

// makeEnvelope builds a valid envelope for the user.
func makeEnvelope(t *testing.T, userID, typ, recordID string, ts time.Time, seed byte) Envelope {
	t.Helper()
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	ct := make([]byte, 40)
	ct[0] = seed
	return Envelope{
		RecordID:   recordID,
		Type:       typ,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
		Aad:        buildAad(userID, typ, recordID),
		Ts:         ts.UTC().Format(time.RFC3339Nano),
	}
}

func newUUIDStr() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// ─── happy path ──────────────────────────────────────────────────────

func TestSyncHappyPath(t *testing.T) {
	s, u1, _ := syncTestEnv(t)
	env := makeEnvelope(t, u1.id, "accounts", newUUIDStr(), time.Now().Add(-time.Minute), 1)
	rec, resp := u1.ctx.do(t, s, http.MethodPost, "/api/records/sync", map[string]any{
		"since": nil, "pushes": []map[string]any{envelopeToMap(env)},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("sync = %d: %v", rec.Code, resp)
	}
	// since=nil pull includes the just-pushed record (convergence
	// semantics: changes = everything newer than the cursor).
	// second sync with since=epoch returns the envelope
	rec, resp = u1.ctx.do(t, s, http.MethodPost, "/api/records/sync", map[string]any{
		"since": "2000-01-01T00:00:00Z", "pushes": []map[string]any{},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("pull = %d", rec.Code)
	}
	changes := resp["changes"].([]any)
	if len(changes) != 1 {
		t.Fatalf("pull changes = %d, want 1", len(changes))
	}
	env0 := changes[0].(map[string]any)["envelope"].(map[string]any)
	if env0["record_id"] != env.RecordID {
		t.Fatalf("pulled wrong record: %v", env0)
	}
	if env0["ciphertext"] != env.Ciphertext {
		t.Fatal("ciphertext mutated server-side")
	}
}

func envelopeToMap(e Envelope) map[string]any { //nolint:unparam
	raw, _ := json.Marshal(e)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return m
}

// ─── malformed envelope suite (≥12 cases, J2) ────────────────────────

func TestSyncMalformedEnvelopes(t *testing.T) {
	s, u1, _ := syncTestEnv(t)
	now := time.Now().Add(-time.Minute)
	good := makeEnvelope(t, u1.id, "accounts", newUUIDStr(), now, 1)

	cases := []struct {
		name string
		env  func() map[string]any
	}{
		{"unknown field", func() map[string]any { m := envelopeToMap(good); m["extra"] = "x"; return m }},
		{"missing ciphertext", func() map[string]any { m := envelopeToMap(good); delete(m, "ciphertext"); return m }},
		{"duplicate field", func() map[string]any { return duplicateFieldMap() }},
		{"bad b64 padding", func() map[string]any { m := envelopeToMap(good); m["ciphertext"] = rawNoPad(good.Ciphertext); return m }},
		{"urlsafe alphabet", func() map[string]any {
			m := envelopeToMap(good)
			m["nonce"] = "_-7dzLuqmYh3ZlVE" // url alphabet chars are rejected by strict std parse
			return m
		}},
		{"nonce not 12 bytes", func() map[string]any { m := envelopeToMap(good); m["nonce"] = b64Of(make([]byte, 11)); return m }},
		{"ciphertext too short", func() map[string]any { m := envelopeToMap(good); m["ciphertext"] = b64Of(make([]byte, 16)); return m }},
		{"unparseable ts", func() map[string]any { m := envelopeToMap(good); m["ts"] = "not-a-time"; return m }},
		{"future ts", func() map[string]any {
			m := envelopeToMap(good)
			m["ts"] = time.Now().Add(time.Hour).Format(time.RFC3339Nano)
			return m
		}},
		{"wrong-type aad", func() map[string]any {
			m := envelopeToMap(good)
			m["aad"] = buildAad(u1.id, "transactions", good.RecordID)
			return m
		}},
		{"aad user mismatch", func() map[string]any {
			m := envelopeToMap(good)
			m["aad"] = buildAad("other-user", "accounts", good.RecordID)
			return m
		}},
		{"record_id not uuid", func() map[string]any { m := envelopeToMap(good); m["record_id"] = "not-a-uuid"; return m }},
		{"unknown type", func() map[string]any { m := envelopeToMap(good); m["type"] = "budgets"; return m }},
		{"non-syncable type", func() map[string]any {
			m := envelopeToMap(good)
			m["type"] = "vault"
			m["aad"] = buildAad(u1.id, "vault", good.RecordID)
			return m
		}},
		{"batch 501", func() map[string]any { return nil }}, // handled separately below
	}
	for _, tc := range cases {
		if tc.name == "batch 501" || tc.name == "duplicate field" {
			continue // raw-JSON cases tested below
		}
		rec, resp := u1.ctx.do(t, s, http.MethodPost, "/api/records/sync", map[string]any{
			"since": nil, "pushes": []map[string]any{tc.env()},
		})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (body %v)", tc.name, rec.Code, resp)
		}
	}

	// batch 501
	big := make([]map[string]any, 501)
	for i := range big {
		big[i] = envelopeToMap(makeEnvelope(t, u1.id, "chat", newUUIDStr(), now, 2))
	}
	rec, _ := u1.ctx.do(t, s, http.MethodPost, "/api/records/sync", map[string]any{"since": nil, "pushes": big})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("batch 501: status = %d, want 400", rec.Code)
	}

	// non-JSON content-type
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/records/sync", bytes.NewReader([]byte("junk")))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Origin", testOrigin)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: u1.ctx.token})
	rec2 := httptest.NewRecorder()
	s.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusUnsupportedMediaType {
		t.Errorf("non-JSON content-type: status = %d, want 415", rec2.Code)
	}
}

// duplicateFieldMap can't express duplicate keys via map — handled by
// TestSyncDuplicateFieldRaw below with hand-rolled JSON.
func duplicateFieldMap() map[string]any { return nil }

func rawNoPad(std string) string {
	b, _ := base64.StdEncoding.DecodeString(std)
	return base64.RawStdEncoding.EncodeToString(b) // unpadded ⇒ rejected
}

func urlAlphabet(std string) string {
	b, _ := base64.StdEncoding.DecodeString(std)
	return base64.RawURLEncoding.EncodeToString(b)
}

var _ = urlAlphabet

func b64Of(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// TestSyncDuplicateFieldRaw: duplicate JSON keys are rejected (encoding
// .json would silently take the last). Hand-rolled raw body.
func TestSyncDuplicateFieldRaw(t *testing.T) {
	s, u1, _ := syncTestEnv(t)
	id := newUUIDStr()
	now := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	e := makeEnvelope(t, u1.id, "chat", id, time.Now().Add(-time.Minute), 1)
	raw := fmt.Sprintf(`{"record_id":%q,"type":"chat","nonce":"%s","ciphertext":"%s","aad":"%s","ts":%q,"ts":%q}`,
		id, e.Nonce, e.Ciphertext, e.Aad, now, now)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/records/sync",
		bytes.NewReader([]byte(fmt.Sprintf(`{"since":null,"pushes":[%s]}`, raw))))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", testOrigin)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: u1.ctx.token})
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("duplicate key: status = %d, want 400", rec.Code)
	}
}
