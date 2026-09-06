package api

import (
	"crypto/rand"
	"encoding/hex"
	"runtime/debug"
	"time"
)

func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000-0000-0000-0000-000000000000"
	}
	// RFC 4122 v4 shaping
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// Indirections for deterministic tests.
var (
	timeNow   = time.Now
	timeSince = func(t time.Time) int64 { return time.Since(t).Milliseconds() }
)

func stackDump() []byte {
	return debug.Stack()
}
