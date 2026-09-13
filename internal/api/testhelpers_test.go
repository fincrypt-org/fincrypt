package api

// Shared C2.1+ test helpers: logger sink, serenity driver plumbing,
// unique suffixes. testConfig lives in health_test.go (P0).

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"testing"
)

// logCapture is the process-wide test log buffer.
var logCapture syncBuffer

type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

// testAPILogger returns a logger writing to the shared capture buffer.
func testAPILogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(&logCapture, nil))
}

// testLogBuffer returns all captured log lines and clears the buffer.
func testLogBuffer(_ interface{ Helper() }) []string {
	logCapture.mu.Lock()
	defer logCapture.mu.Unlock()
	out := strings.Split(strings.TrimRight(logCapture.buf.String(), "\n"), "\n")
	logCapture.buf.Reset()
	if len(out) == 1 && out[0] == "" {
		return nil
	}
	return out
}

// uniqSuffix produces a short random suffix for per-test emails.
func uniqSuffix() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

func newBufReader(r interface{ Read([]byte) (int, error) }) *bufio.Reader {
	return bufio.NewReader(r)
}

// driver is the serenity stdio JSON client (same protocol as
// internal/auth's interop tests; duplicated here because Go test
// helpers can't cross package-test boundaries).
type driver struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
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
	if _, err := d.stdin.Write(append(line, 0x0A)); err != nil {
		t.Fatal(err)
	}
	respLine, err := d.stdout.ReadString(0x0A)
	if err != nil {
		t.Fatalf("driver died reading %s: %v", op, err)
	}
	if err := json.Unmarshal([]byte(respLine), out); err != nil {
		t.Fatalf("bad driver response for %s: %v (%s)", op, err, respLine)
	}
}