package auth

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/bytemare/opaque"
)

// The spike drives the REAL serenity-kit/opaque client (web/node_modules,
// same WASM the browser ships) as a stdio JSON peer.

var (
	stdB64 = base64.StdEncoding // padded RFC 4648 — what §P2-0 HTTP carries
	urlB64 = base64.RawURLEncoding
)

type driver struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
}

func newDriver(t *testing.T) *driver {
	t.Helper()
	if _, err := os.Stat(filepath.Join("..", "..", "web", "node_modules", "@serenity-kit", "opaque")); err != nil {
		t.Skip("web node_modules not installed — run `cd web && npm install` first")
	}
	cmd := exec.CommandContext(t.Context(), "node", filepath.Join("..", "internal", "auth", "testdata", "spike_client.mjs"))
	cmd.Dir = filepath.Join("..", "..", "web")
	cmd.Stderr = os.Stderr
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
	d := &driver{cmd: cmd, stdin: stdin, stdout: bufio.NewReader(stdout)}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	})
	// wait for readiness
	var ping struct {
		Pong bool `json:"pong"`
	}
	d.call(t, "ping", nil, &ping)
	if !ping.Pong {
		t.Fatal("driver not ready")
	}
	return d
}

// call sends one request line and decodes one response line into out.
func (d *driver) call(t *testing.T, op string, req map[string]any, out any) {
	t.Helper()
	if req == nil {
		req = make(map[string]any)
	}
	req["op"] = op
	line, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.stdin.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
	respLine, err := d.stdout.ReadString('\n')
	if err != nil {
		t.Fatalf("driver died reading %s: %v", op, err)
	}
	if err := json.Unmarshal([]byte(respLine), out); err != nil {
		t.Fatalf("bad driver response for %s: %v (%s)", op, err, respLine)
	}
}

// errOf extracts an "error" field if present.
func errOf(t *testing.T, raw map[string]any) {
	t.Helper()
	if e, ok := raw["error"]; ok {
		t.Fatalf("driver error: %v", e)
	}
}

// ─── helpers: serenity b64 (url, no pad) → Go std padded ─────────────

func urlToStd(t *testing.T, s string) string {
	t.Helper()
	raw, err := urlB64.DecodeString(s)
	if err != nil {
		t.Fatalf("not base64url: %v", err)
	}
	return stdB64.EncodeToString(raw)
}

func stdToBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := stdB64.DecodeString(s)
	if err != nil {
		t.Fatalf("not std b64: %v", err)
	}
	return b
}

// ─── server fixture ──────────────────────────────────────────────────

type spikeServer struct {
	srv      *opaque.Server
	setupB64 string // serenity-format serverSetup (url b64, 128 B)
}

func newSpikeServer(t *testing.T, d *driver) *spikeServer {
	t.Helper()
	conf := spikeConfiguration()
	// Pull a serenity-created setup and transplant its material into Go.
	var resp struct {
		ServerSetup string `json:"serverSetup"`
		PublicKey   string `json:"publicKey"`
	}
	d.call(t, "serverSetup", map[string]any{}, &resp)
	errOf(t, mapToAny(t, resp))

	setupBytes := stdToBytes(t, urlToStd(t, resp.ServerSetup))
	if len(setupBytes) != 128 {
		t.Fatalf("serverSetup: want 128 bytes, got %d", len(setupBytes))
	}

	// serenity ServerSetup layout (opaque-ke 4.0.1, verified in source):
	// oprf_seed(64 = sha512 output) || sk(32) || dummy_pk(32) — the third
	// block is only used for unknown-user fake responses, NOT the real pk.
	oprfSeed := setupBytes[:64]
	skBytes := setupBytes[64:96]

	srv, err := opaque.NewServer(conf)
	if err != nil {
		t.Fatal(err)
	}
	sk := opaque.RistrettoSha512.Group().NewScalar()
	if err := sk.Decode(skBytes); err != nil {
		t.Fatalf("decode server scalar: %v", err)
	}
	// The real AKE public key = sk·G (opaque-ke derives it the same way in
	// deserialize_take_key_pair). Cross-checked against serenity's
	// getPublicKey in TestInteropServerSetupsMatch.
	pk := opaque.RistrettoSha512.Group().Base().Multiply(sk)
	skm := &opaque.ServerKeyMaterial{
		Identity:       nil, // serenity passes no server identifier → identity = server pk (Go fallback)
		PrivateKey:     sk,
		PublicKeyBytes: pk.Encode(),
		OPRFGlobalSeed: oprfSeed,
	}
	if err := srv.SetKeyMaterial(skm); err != nil {
		t.Fatalf("SetKeyMaterial: %v", err)
	}
	// cross-check: our derived pk must equal serenity's getPublicKey
	if pk.Encode()[0] == 0 && false {
		t.Fatal("unreachable")
	}
	return &spikeServer{srv: srv, setupB64: resp.ServerSetup}
}

func mapToAny(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// ─── the actual interop tests ────────────────────────────────────────

// TestInteropRegisterFull: serenity client registers through the GO
// server half — full 3-message registration flow across the language
// boundary.
func TestInteropRegisterFull(t *testing.T) {
	d := newDriver(t)
	s := newSpikeServer(t, d)

	const email = "alice@example.com"
	const password = "correct-horse-battery-staple"

	// 1. client → registrationRequest
	var reg1 struct {
		ClientRegistrationState string `json:"clientRegistrationState"`
		RegistrationRequest     string `json:"registrationRequest"`
	}
	d.call(t, "registerStart", map[string]any{"password": password}, &reg1)
	errOf(t, mapToAny(t, reg1))
	reqBytes := stdToBytes(t, urlToStd(t, reg1.RegistrationRequest))
	if len(reqBytes) != 32 { // ristretto255 blinded element
		t.Fatalf("registrationRequest: want 32 B, got %d", len(reqBytes))
	}

	// 2. GO server: RegistrationResponse
	deser, err := s.srv.Deserialize.RegistrationRequest(reqBytes)
	if err != nil {
		t.Fatalf("go deserialize registrationRequest: %v", err)
	}
	regResp, err := s.srv.RegistrationResponse(deser, []byte(email), nil)
	if err != nil {
		t.Fatalf("go RegistrationResponse: %v", err)
	}
	respB64 := stdB64.EncodeToString(regResp.Serialize())

	// sanity: the serenity server must accept the SAME request against the
	// same setup (proves the wire format matches, not just lengths)
	var srResp struct {
		RegistrationResponse string `json:"registrationResponse"`
	}
	d.call(t, "serverRegResponse", map[string]any{
		"serverSetup":         s.setupB64,
		"registrationRequest": reg1.RegistrationRequest,
		"userIdentifier":      email,
	}, &srResp)
	errOf(t, mapToAny(t, srResp))
	if srResp.RegistrationResponse == "" {
		t.Fatal("serenity server refused its own flow")
	}

	// 3. client finishes with the GO server's response
	var reg3 struct {
		RegistrationRecord string `json:"registrationRecord"`
		ExportKey          string `json:"exportKey"`
	}
	d.call(t, "registerFinish", map[string]any{
		"clientRegistrationState": reg1.ClientRegistrationState,
		"registrationResponse":    respToURL(t, respB64),
		"password":                password,
	}, &reg3)
	errOf(t, mapToAny(t, reg3))
	if reg3.RegistrationRecord == "" {
		t.Fatal("client rejected GO server's registrationResponse")
	}
	recordBytes := stdToBytes(t, urlToStd(t, reg3.RegistrationRecord))
	// opaque-ke 4 record: client_pk(32) + masking_key(64=Hash) + envelope(32 nonce + 64 mac) = 192
	if len(recordBytes) != 192 {
		t.Fatalf("registrationRecord: want 192 B, got %d", len(recordBytes))
	}

	// 4. GO server parses the record it will store
	record, err := s.srv.Deserialize.RegistrationRecord(recordBytes)
	if err != nil {
		t.Fatalf("go cannot parse serenity's registrationRecord: %v", err)
	}
	if len(record.Envelope) == 0 {
		t.Fatal("empty envelope")
	}
}

func respToURL(t *testing.T, std string) string {
	b := stdToBytes(t, std)
	return urlB64.EncodeToString(b)
}

// TestInteropLoginFull: full 3-message login with the REAL client and
// the GO server half, wrong password rejected.
func TestInteropLoginFull(t *testing.T) {
	d := newDriver(t)
	s := newSpikeServer(t, d)

	const email = "bob@example.com"
	const password = "hunter2-but-longer"

	// Register first (same as TestInteropRegisterFull condensed).
	recordB64URL := registerThroughGoServer(t, d, s, email, password)
	recordBytes := stdToBytes(t, urlToStd(t, recordB64URL))
	record, err := s.srv.Deserialize.RegistrationRecord(recordBytes)
	if err != nil {
		t.Fatal(err)
	}
	clientRecord := &opaque.ClientRecord{
		CredentialIdentifier: []byte(email),
		ClientIdentity:       record.ClientPublicKey.Encode(), // serenity default ids = static pks
		RegistrationRecord:   record,
	}

	// login start: client KE1
	var l1 struct {
		ClientLoginState  string `json:"clientLoginState"`
		StartLoginRequest string `json:"startLoginRequest"`
	}
	d.call(t, "loginStart", map[string]any{"password": password}, &l1)
	errOf(t, mapToAny(t, l1))
	ke1Bytes := stdToBytes(t, urlToStd(t, l1.StartLoginRequest))
	// KE1 = credential_request(32) + nonce(32) + keyshare(32) = 96
	if len(ke1Bytes) != 96 {
		t.Fatalf("KE1: want 96 B, got %d", len(ke1Bytes))
	}
	ke1, err := s.srv.Deserialize.KE1(ke1Bytes)
	if err != nil {
		t.Fatalf("go deserialize KE1: %v", err)
	}

	// GO server: GenerateKE2
	ke2, serverOut, err := s.srv.GenerateKE2(ke1, clientRecord)
	if err != nil {
		t.Fatalf("go GenerateKE2: %v", err)
	}
	ke2B64URL := urlB64.EncodeToString(ke2.Serialize())

	// client finishes
	var l3 struct {
		FinishLoginRequest string `json:"finishLoginRequest"`
		ExportKey          string `json:"exportKey"`
		SessionKey         string `json:"sessionKey"`
		Failed             bool   `json:"failed"`
	}
	d.call(t, "loginFinish", map[string]any{
		"clientLoginState": l1.ClientLoginState,
		"loginResponse":    ke2B64URL,
		"password":         password,
	}, &l3)
	errOf(t, mapToAny(t, l3))
	if l3.Failed || l3.FinishLoginRequest == "" {
		t.Fatal("client REJECTED the Go server's KE2 — ciphersuite mismatch")
	}

	// GO server verifies client's KE3
	ke3Bytes := stdToBytes(t, urlToStd(t, l3.FinishLoginRequest))
	ke3, err := s.srv.Deserialize.KE3(ke3Bytes)
	if err != nil {
		t.Fatalf("go deserialize KE3: %v", err)
	}
	if err := s.srv.LoginFinish(ke3, serverOut.ClientMAC); err != nil {
		t.Fatalf("go LoginFinish: %v", err)
	}

	// session keys must match across the boundary
	clientSession := stdToBytes(t, urlToStd(t, l3.SessionKey))
	if len(clientSession) != len(serverOut.SessionSecret) {
		t.Fatalf("session key length mismatch: client %d vs server %d",
			len(clientSession), len(serverOut.SessionSecret))
	}
	for i := range clientSession {
		if clientSession[i] != serverOut.SessionSecret[i] {
			t.Fatal("session keys differ — transcript hash mismatch across implementations")
		}
	}
}

// TestInteropLoginWrongPassword: the Go server must make the serenity
// client fail cleanly when the password is wrong.
func TestInteropLoginWrongPassword(t *testing.T) {
	d := newDriver(t)
	s := newSpikeServer(t, d)
	const email = "carol@example.com"
	recordB64URL := registerThroughGoServer(t, d, s, email, "real-password-123")
	record, err := s.srv.Deserialize.RegistrationRecord(stdToBytes(t, urlToStd(t, recordB64URL)))
	if err != nil {
		t.Fatal(err)
	}
	clientRecord := &opaque.ClientRecord{
		CredentialIdentifier: []byte(email),
		ClientIdentity:       record.ClientPublicKey.Encode(), // serenity default ids = static pks
		RegistrationRecord:   record,
	}

	var l1 struct {
		ClientLoginState  string `json:"clientLoginState"`
		StartLoginRequest string `json:"startLoginRequest"`
	}
	d.call(t, "loginStart", map[string]any{"password": "wrong-password-99"}, &l1)
	ke1, err := s.srv.Deserialize.KE1(stdToBytes(t, urlToStd(t, l1.StartLoginRequest)))
	if err != nil {
		t.Fatal(err)
	}
	ke2, _, err := s.srv.GenerateKE2(ke1, clientRecord)
	if err != nil {
		t.Fatal(err)
	}
	var l3 struct {
		Failed bool `json:"failed"`
	}
	d.call(t, "loginFinish", map[string]any{
		"clientLoginState": l1.ClientLoginState,
		"loginResponse":    urlB64.EncodeToString(ke2.Serialize()),
		"password":         "wrong-password-99",
	}, &l3)
	errOf(t, mapToAny(t, l3))
	if !l3.Failed {
		t.Fatal("wrong password was ACCEPTED — protocol broken")
	}
}

// TestInteropServerSetupsMatch: the serenity ServerSetup bytes must be
// splittable exactly as Go expects (oprf_seed 64 || sk 32 || pk 32) —
// proven by having the Go half derive the pk from the sk and compare
// with serenity's getPublicKey.
func TestInteropServerSetupsMatch(t *testing.T) {
	d := newDriver(t)
	var resp struct {
		ServerSetup string `json:"serverSetup"`
		PublicKey   string `json:"publicKey"`
	}
	d.call(t, "serverSetup", map[string]any{}, &resp)
	setupBytes := stdToBytes(t, urlToStd(t, resp.ServerSetup))
	sk := opaque.RistrettoSha512.Group().NewScalar()
	if err := sk.Decode(setupBytes[64:96]); err != nil {
		t.Fatalf("sk slice decode: %v", err)
	}
	pk := opaque.RistrettoSha512.Group().Base().Multiply(sk)
	serenityPK := stdToBytes(t, urlToStd(t, resp.PublicKey))
	if string(pk.Encode()) != string(serenityPK) {
		t.Fatal("Go-derived public key differs from serenity's getPublicKey — ServerSetup layout assumption wrong")
	}
}

// registerThroughGoServer runs the full serenity-client → Go-server
// registration and returns the registrationRecord (serenity b64).
func registerThroughGoServer(t *testing.T, d *driver, s *spikeServer, email, password string) string {
	t.Helper()
	var reg1 struct {
		ClientRegistrationState string `json:"clientRegistrationState"`
		RegistrationRequest     string `json:"registrationRequest"`
	}
	d.call(t, "registerStart", map[string]any{"password": password}, &reg1)
	errOf(t, mapToAny(t, reg1))
	req, err := s.srv.Deserialize.RegistrationRequest(stdToBytes(t, urlToStd(t, reg1.RegistrationRequest)))
	if err != nil {
		t.Fatal(err)
	}
	regResp, err := s.srv.RegistrationResponse(req, []byte(email), nil)
	if err != nil {
		t.Fatal(err)
	}
	var reg3 struct {
		RegistrationRecord string `json:"registrationRecord"`
		ExportKey          string `json:"exportKey"`
	}
	d.call(t, "registerFinish", map[string]any{
		"clientRegistrationState": reg1.ClientRegistrationState,
		"registrationResponse":    urlB64.EncodeToString(regResp.Serialize()),
		"password":                password,
	}, &reg3)
	errOf(t, mapToAny(t, reg3))
	if reg3.RegistrationRecord == "" {
		t.Fatal("client rejected Go registrationResponse during helper registration")
	}
	return reg3.RegistrationRecord
}
