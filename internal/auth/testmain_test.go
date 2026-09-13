package auth

// Shared test helpers (C2.1): logger, env access, unique suffixes.

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func osGetenv(key string) string { return os.Getenv(key) }

func osStat(path string) (os.FileInfo, error) { return os.Stat(path) }

func newBufio(r io.Reader) *bufio.Reader { return bufio.NewReader(r) }

// uniqSuffix produces a short random suffix for per-test emails.
func uniqSuffix() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}