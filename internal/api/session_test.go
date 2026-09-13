package api

// C2.2 tests: session JWT verify, cookie attributes (J6), CSRF/Origin
// (D9), rate limits (D8), audit rows (J5).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func sessionServer(t *testing.T) *Server {
	t.Helper()
	cfg := authTestConfig()
	s := &Server{cfg: cfg, logger: testAPILogger(), rates: newRateTable(), auditQ: noopAudit{}}
	return s
}

func TestIssueAndVerifySession(t *testing.T) {
	s := sessionServer(t)
	rec := httptest.NewRecorder()
	s.issueSession(rec, "user-42")

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("want 1 cookie, got %d", len(cookies))
	}
	c := cookies[0]
	// J6 attribute assertions
	if c.Name != sessionCookie {
		t.Fatalf("cookie name = %q", c.Name)
	}
	if !c.HttpOnly {
		t.Error("cookie not HttpOnly")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Error("cookie SameSite != Lax")
	}
	if c.Path != "/" {
		t.Error("cookie Path != /")
	}
	if c.MaxAge != int(sessionTTL/time.Second) {
		t.Errorf("cookie MaxAge = %d", c.MaxAge)
	}
	if c.Secure {
		t.Error("cookie Secure set in dev (must be prod-only)")
	}

	if userID, ok := s.verifySession(c.Value); !ok || userID != "user-42" {
		t.Fatalf("verifySession = %q, %v", userID, ok)
	}
}

func TestVerifySessionExpired(t *testing.T) {
	s := sessionServer(t)
	// hand-craft an expired token with the same key
	claims := sessionClaims{
		UserID: "user-1",
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * sessionTTL)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-sessionTTL)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(s.cfg.SessionKeys[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.verifySession(signed); ok {
		t.Fatal("expired token accepted")
	}
}

func TestVerifySessionTampered(t *testing.T) {
	s := sessionServer(t)
	rec := httptest.NewRecorder()
	s.issueSession(rec, "user-1")
	value := rec.Result().Cookies()[0].Value
	// flip the payload
	parts := strings.Split(value, ".")
	tampered := parts[0] + ".eyJzdWIiOiJvdGhlciJ9." + parts[2]
	if _, ok := s.verifySession(tampered); ok {
		t.Fatal("tampered token accepted")
	}
	// truncate signature
	if _, ok := s.verifySession(parts[0] + "." + parts[1] + ".AAAA"); ok {
		t.Fatal("forged-signature token accepted")
	}
}

func TestVerifySessionWrongKey(t *testing.T) {
	s := sessionServer(t)
	// sign with a foreign key — must fail against both configured keys
	claims := sessionClaims{UserID: "user-9", RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.verifySession(signed); ok {
		t.Fatal("foreign-key token accepted")
	}
}

func TestVerifySessionAlgNoneRejected(t *testing.T) {
	s := sessionServer(t)
	// unsigned token
	tok := jwt.New(jwt.SigningMethodNone)
	signed, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.verifySession(signed); ok {
		t.Fatal("alg=none token accepted")
	}
}

func TestRequireSession401(t *testing.T) {
	s := sessionServer(t)
	handler := s.requireSession(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/anything", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no cookie → %d, want 401", rec.Code)
	}
	var e errorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil || e.Error.Code == "" {
		t.Fatal("non-envelope 401")
	}
}

func TestMutationCSRF(t *testing.T) {
	s := sessionServer(t)
	handler := s.enforceMutationCSRF(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	// missing Origin ⇒ 403 (D9)
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/auth/x", nil)
	req.Header.Set("Content-Type", "application/json")
	handler(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing Origin → %d, want 403", rec.Code)
	}
	// disallowed origin ⇒ 403
	rec = httptest.NewRecorder()
	req = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/auth/x", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example")
	handler(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("evil Origin → %d, want 403", rec.Code)
	}
	// allowed origin + JSON ⇒ pass
	rec = httptest.NewRecorder()
	req = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/auth/x", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", testOrigin)
	handler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("allowed Origin → %d, want 200", rec.Code)
	}
	// non-JSON content type ⇒ 415
	rec = httptest.NewRecorder()
	req = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/auth/x", nil)
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Origin", testOrigin)
	handler(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain → %d, want 415", rec.Code)
	}
}

func TestProdSameOriginAllowed(t *testing.T) {
	s := sessionServer(t)
	s.cfg.Env = "prod"
	handler := s.enforceMutationCSRF(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://fincrypt.example/api/x", nil)
	req.Host = "fincrypt.example"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://fincrypt.example")
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("prod same-origin → %d, want 200", rec.Code)
	}
}

func TestRateLimit429(t *testing.T) {
	s := sessionServer(t)
	// auth bucket: 10/min/IP
	var last int
	for i := 0; i < 11; i++ {
		if s.rates.allowAuth("1.2.3.4") {
			last = http.StatusOK
		} else {
			last = http.StatusTooManyRequests
			break
		}
	}
	if last != http.StatusTooManyRequests {
		t.Fatal("auth bucket did not trip at 11")
	}
	// a different IP is unaffected
	if !s.rates.allowAuth("5.6.7.8") {
		t.Fatal("per-IP isolation broken")
	}
}

func TestClearSession(t *testing.T) {
	rec := httptest.NewRecorder()
	clearSession(rec)
	c := rec.Result().Cookies()[0]
	if c.MaxAge > 0 {
		t.Fatalf("clear cookie MaxAge = %d, want <= 0", c.MaxAge)
	}
}