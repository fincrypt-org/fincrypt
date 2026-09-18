package auth

import (
	"encoding/base64"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bytemare/opaque"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ─── D7 kdf_params validation ────────────────────────────────────────

func TestAllowedKDFParams(t *testing.T) {
	ok := json.RawMessage(`{"alg":"argon2id","m":65536,"t":3,"p":4,"version":19}`)
	if err := allowedKDFParams(ok); err != nil {
		t.Fatalf("profile params rejected: %v", err)
	}
	bad := []json.RawMessage{
		json.RawMessage(`{"alg":"argon2id","m":32768,"t":3,"p":4,"version":1}`), // downgraded m
		json.RawMessage(`{"alg":"argon2id","m":65536,"t":1,"p":4,"version":1}`), // downgraded t
		json.RawMessage(`{"alg":"argon2i","m":65536,"t":3,"p":4,"version":1}`),  // wrong alg
		json.RawMessage(`{"alg":"argon2id","m":65536,"t":3,"p":4,"version":1}`), // wrong version
		json.RawMessage(`{"alg":"argon2id"}`),                                   // missing fields
		json.RawMessage(`42`),
	}
	for i, b := range bad {
		if err := allowedKDFParams(b); err == nil {
			t.Fatalf("case %d: expected rejection, got nil", i)
		}
	}
}

// ─── GenerateServerSetup shape ───────────────────────────────────────

func TestGenerateServerSetupShape(t *testing.T) {
	b64, err := GenerateServerSetup()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("not std b64: %v", err)
	}
	if len(raw) != 128 {
		t.Fatalf("want 128 bytes, got %d", len(raw))
	}
	// sk must decode as a valid ristretto scalar and derive a valid pk
	srv, _, err := serverFromSetup(raw)
	if err != nil {
		t.Fatalf("generated setup not usable: %v", err)
	}
	if srv == nil {
		t.Fatal("nil server")
	}
}

// NewService rejects wrong-size setups.
func TestNewServiceRejectsBadSetup(t *testing.T) {
	_, err := NewService(nil, testLogger(), "AAAA") // too short
	if err == nil || !strings.Contains(err.Error(), "128 bytes") {
		t.Fatalf("want size error, got %v", err)
	}
}

// ─── full flows through the REAL serenity client + live Postgres ─────

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := osGetenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set — DB-backed tests skipped")
	}
	pool, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Skipf("no DB: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// driver is the serenity stdio client (same as interop_test).
func testDriver(t *testing.T) *driver {
	t.Helper()
	if _, err := osStat(filepath.Join("..", "..", "web", "node_modules", "@serenity-kit", "opaque")); err != nil {
		t.Skip("web node_modules not installed")
	}
	cmd := exec.CommandContext(t.Context(), "node", filepath.Join("..", "internal", "auth", "testdata", "spike_client.mjs"))
	cmd.Dir = filepath.Join("..", "..", "web")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start node: %v", err)
	}
	d := &driver{cmd: cmd, stdin: stdin, stdout: newBufio(stdout)}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	})
	return d
}

var _ = time.Second

// TestServiceRegisterLoginLifecycle: register → wrong password fails →
// right password logs in → unlock material returned, through the REAL
// serenity client and the live Postgres.
func TestServiceRegisterLoginLifecycle(t *testing.T) {
	pool := testPool(t)
	d := testDriver(t)
	setupB64, err := GenerateServerSetup()
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(pool, testLogger(), setupB64)
	if err != nil {
		t.Fatal(err)
	}
	email := "lifecycle-" + uniqSuffix() + "@example.com"
	password := "correct-horse-42"
	wrapped48 := base64.StdEncoding.EncodeToString(make([]byte, 48))
	wrapped48b := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"))

	// register start
	var reg1 struct {
		ClientRegistrationState string `json:"clientRegistrationState"`
		RegistrationRequest     string `json:"registrationRequest"`
	}
	d.call(t, "registerStart", map[string]any{"password": password}, &reg1)
	resp, salt, err := svc.RegisterStart(t.Context(), email, reg1.RegistrationRequest)
	if err != nil {
		t.Fatalf("RegisterStart: %v", err)
	}
	if len(salt) == 0 {
		t.Fatal("empty kdf salt")
	}

	// register finish
	var reg3 struct {
		RegistrationRecord string `json:"registrationRecord"`
		ExportKey          string `json:"exportKey"`
	}
	d.call(t, "registerFinish", map[string]any{
		"clientRegistrationState": reg1.ClientRegistrationState,
		"registrationResponse":    stdToURL(t, resp),
		"password":                password,
	}, &reg3)
	userID, err := svc.RegisterFinish(t.Context(), RegisterFinishBody{
		Email:              email,
		RegistrationRec:    reg3.RegistrationRecord,
		WrappedDek:         wrapped48, // 32B dummy, shape-checked
		WrappedDekRecovery: wrapped48b,
		KdfSalt:            salt,
		KdfParams:          json.RawMessage(`{"alg":"argon2id","m":65536,"t":3,"p":4,"version":19}`),
	})
	if err != nil {
		t.Fatalf("RegisterFinish: %v", err)
	}
	if userID == "" {
		t.Fatal("empty userID")
	}

	// duplicate email ⇒ ErrEmailTaken
	_, err = svc.RegisterFinish(t.Context(), RegisterFinishBody{
		Email:              email,
		RegistrationRec:    reg3.RegistrationRecord,
		WrappedDek:         wrapped48,
		WrappedDekRecovery: wrapped48b,
		KdfSalt:            salt,
		KdfParams:          json.RawMessage(`{"alg":"argon2id","m":65536,"t":3,"p":4,"version":19}`),
	})
	if err == nil || !strings.Contains(err.Error(), "already registered") {
		t.Fatalf("want ErrEmailTaken, got %v", err)
	}

	// login with WRONG password: client fails its own MAC check
	if !loginExpectClientReject(t, d, svc, email, "wrong-password") {
		t.Fatal("wrong-password login did not fail")
	}

	// login with the right password
	loginResp := loginThroughService(t, d, svc, email, password)
	if loginResp == nil {
		t.Fatal("correct-password login failed")
	}
	if loginResp.UserID != userID || loginResp.KdfSalt != salt {
		t.Fatalf("unlock material mismatch: %+v", loginResp)
	}
	if len(loginResp.WrappedDek) == 0 || len(loginResp.WrappedDekRecovery) == 0 {
		t.Fatal("wrapped DEKs not returned")
	}
}

// TestServiceLoginUnknownUserFakePath: unknown email produces a
// login/start response of the SAME SHAPE as a known user (D8) — and the
// client deterministically rejects it at finish (fake record never MACs).
func TestServiceLoginUnknownUserFakePath(t *testing.T) {
	pool := testPool(t)
	d := testDriver(t)
	setupB64, err := GenerateServerSetup()
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(pool, testLogger(), setupB64)
	if err != nil {
		t.Fatal(err)
	}
	if !loginExpectClientReject(t, d, svc, "nobody-"+uniqSuffix()+"@example.com", "any-password") {
		t.Fatal("unknown-user login unexpectedly succeeded")
	}
}

// ─── pending login bookkeeping ───────────────────────────────────────

func TestPendingLoginsTTL(t *testing.T) {
	p := newPendingLogins()
	if err := p.put("a@x", []byte("mac")); err != nil {
		t.Fatal(err)
	}
	if _, ok := p.pop("a@x"); !ok {
		t.Fatal("expected entry")
	}
	if _, ok := p.pop("a@x"); ok {
		t.Fatal("pop must be one-shot")
	}
	// TTL expiry
	p2 := newPendingLogins()
	if err := p2.put("b@x", []byte("m")); err != nil {
		t.Fatal(err)
	}
	p2.mu.Lock()
	e := p2.m["b@x"]
	e.deadline = time.Now().Add(-time.Second)
	p2.m["b@x"] = e
	p2.mu.Unlock()
	if _, ok := p2.pop("b@x"); ok {
		t.Fatal("expired entry popped")
	}
}

// ─── helpers ─────────────────────────────────────────────────────────

// stdToURL converts a std-b64 payload to serenity's url-no-pad alphabet.
func stdToURL(t *testing.T, std string) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(std)
	if err != nil {
		t.Fatalf("std b64: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// loginThroughService runs a full login; returns the finish response or
// nil when the client rejects.
func loginThroughService(t *testing.T, d *driver, svc *Service, email, password string) *LoginFinishResponse {
	t.Helper()
	var l1 struct {
		ClientLoginState  string `json:"clientLoginState"`
		StartLoginRequest string `json:"startLoginRequest"`
	}
	d.call(t, "loginStart", map[string]any{"password": password}, &l1)
	ke2B64, err := svc.LoginStart(t.Context(), email, l1.StartLoginRequest)
	if err != nil {
		t.Fatalf("LoginStart: %v", err)
	}
	var l3 struct {
		FinishLoginRequest string `json:"finishLoginRequest"`
		Failed             bool   `json:"failed"`
	}
	d.call(t, "loginFinish", map[string]any{
		"clientLoginState": l1.ClientLoginState,
		"loginResponse":    stdToURL(t, ke2B64),
		"password":         password,
	}, &l3)
	if l3.Failed {
		return nil
	}
	resp, err := svc.LoginFinish(t.Context(), LoginFinishBody{Email: email, FinishLogin: l3.FinishLoginRequest})
	if err != nil {
		t.Fatalf("LoginFinish: %v", err)
	}
	return resp
}

// loginExpectClientReject reports whether the client rejected the login.
func loginExpectClientReject(t *testing.T, d *driver, svc *Service, email, password string) bool {
	t.Helper()
	var l1 struct {
		ClientLoginState  string `json:"clientLoginState"`
		StartLoginRequest string `json:"startLoginRequest"`
	}
	d.call(t, "loginStart", map[string]any{"password": password}, &l1)
	ke2B64, err := svc.LoginStart(t.Context(), email, l1.StartLoginRequest)
	if err != nil {
		t.Fatalf("LoginStart (unknown user): %v", err)
	}
	var l3 struct {
		Failed bool `json:"failed"`
	}
	d.call(t, "loginFinish", map[string]any{
		"clientLoginState": l1.ClientLoginState,
		"loginResponse":    stdToURL(t, ke2B64),
		"password":         password,
	}, &l3)
	return l3.Failed
}

var _ = opaque.Group(0)
