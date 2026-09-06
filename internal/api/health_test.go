package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fincrypt-org/fincrypt/internal/config"
)

func testConfig() config.Config {
	return config.Config{
		Env:         "dev",
		Port:        "0",
		LogLevel:    "error",
		DatabaseURL: "postgres://test",
	}
}

func newTestServer(t *testing.T, cfg config.Config) *Server {
	t.Helper()
	// failingPinger always errors: exactly the "database down" state we
	// want to assert by default.
	s := NewServerWithPinger(cfg, failingPinger{}, discardLogger())
	return s
}

// failingPinger is a Pinger that always fails.
type failingPinger struct{}

func (failingPinger) Ping(ctx context.Context) error { return errors.New("db down") }

func TestHealthzAlways200(t *testing.T) {
	s := newTestServer(t, testConfig())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	s.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"ok"`) {
		t.Errorf("/healthz body = %q, want status ok", rec.Body.String())
	}
}

func TestReadyz(t *testing.T) {
	s := newTestServer(t, testConfig())

	// With a zero pool, Ping must fail -> 503.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz with dead pool: status = %d, want 503", rec.Code)
	}
}

func TestPanicBecomes500JSON(t *testing.T) {
	s := newTestServer(t, testConfig())

	// Wrap a panicking handler through the full chain.
	h := s.recoverMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/boom", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("panic handler status = %d, want 500", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "boom") || strings.Contains(body, "goroutine") || strings.Contains(body, "panic") {
		t.Errorf("stack trace leaked into body: %q", body)
	}
	if !strings.Contains(body, "internal server error") {
		t.Errorf("body should be JSON error, got %q", body)
	}
}

func TestLogsContainNoBodyOrCookie(t *testing.T) {
	cfg := testConfig()
	s := NewServer(cfg, nil, captureLogger(t, &logBuf{}))

	sensitiveBody := `{"password":"super-secret-plaintext","cookie":"session=abc123"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/healthz", strings.NewReader(sensitiveBody))
	req.Header.Set("Cookie", "session=abc123; other=xyz")
	s.ServeHTTP(rec, req)

	dumped := capturedLogLines(t)
	for _, line := range dumped {
		if strings.Contains(line, "super-secret-plaintext") ||
			strings.Contains(line, "session=abc123") ||
			strings.Contains(line, "other=xyz") {
			t.Errorf("log line contains request body or cookie: %q", line)
		}
	}
}

func TestRequestIDEchoed(t *testing.T) {
	s := newTestServer(t, testConfig())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	s.ServeHTTP(rec, req)

	if got := rec.Header().Get("X-Request-ID"); got == "" {
		t.Error("X-Request-ID not set on response")
	}

	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req2.Header.Set("X-Request-ID", "fixed-id-123")
	s.ServeHTTP(rec2, req2)
	if got := rec2.Header().Get("X-Request-ID"); got != "fixed-id-123" {
		t.Errorf("existing X-Request-ID not echoed: got %q", got)
	}
}

func TestSecureHeadersPresent(t *testing.T) {
	s := newTestServer(t, testConfig())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	s.ServeHTTP(rec, req)

	for _, h := range []string{"X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Content-Security-Policy"} {
		if rec.Header().Get(h) == "" {
			t.Errorf("missing security header %s", h)
		}
	}
	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", got)
	}
}

func TestCORSDevOnly(t *testing.T) {
	cfg := testConfig()
	cfg.DevOrigin = "http://localhost:5173"
	s := newTestServer(t, cfg)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	s.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Errorf("dev CORS: ACAO = %q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("dev CORS: credentials = %q, want true", got)
	}

	// Same server, different origin -> no CORS headers.
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req2.Header.Set("Origin", "https://evil.example")
	s.ServeHTTP(rec2, req2)
	if got := rec2.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("foreign origin got ACAO = %q", got)
	}

	// No DEV_ORIGIN (prod) -> never.
	prodCfg := testConfig()
	prodCfg.Env = "prod"
	prodS := newTestServer(t, prodCfg)
	rec3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req3.Header.Set("Origin", "http://localhost:5173")
	prodS.ServeHTTP(rec3, req3)
	if got := rec3.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("prod must not emit ACAO, got %q", got)
	}
}

func TestCORSPreflight(t *testing.T) {
	cfg := testConfig()
	cfg.DevOrigin = "http://localhost:5173"
	s := newTestServer(t, cfg)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodOptions, "/api/anything", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("preflight status = %d, want 204", rec.Code)
	}
}

// compile-time guards
var (
	_ = errors.New
)
