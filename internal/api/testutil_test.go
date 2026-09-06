package api

import (
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

// discardLogger returns a logger that writes nothing.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

// logBuf captures slog output for log-content assertions.
type logBuf struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *logBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// capturedLogLines runs the log-content assertions: it returns the lines
// captured by the most recent captureLogger call on this test.
func capturedLogLines(t *testing.T) []string {
	t.Helper()
	buf := capturedForTest(t)
	return strings.Split(buf.String(), "\n")
}

// registry maps a test to its log buffer so assertions can read it back.
var (
	regMu sync.Mutex
	reg   = map[string]*logBuf{}
)

func captureLogger(t *testing.T, buf *logBuf) *slog.Logger {
	t.Helper()
	regMu.Lock()
	reg[t.Name()] = buf
	regMu.Unlock()
	t.Cleanup(func() {
		regMu.Lock()
		delete(reg, t.Name())
		regMu.Unlock()
	})
	return slog.New(slog.NewJSONHandler(buf, nil))
}

func capturedForTest(t *testing.T) *logBuf {
	t.Helper()
	regMu.Lock()
	defer regMu.Unlock()
	buf, ok := reg[t.Name()]
	if !ok {
		t.Fatal("no captured logger registered for this test")
	}
	return buf
}
