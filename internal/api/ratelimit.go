package api

// Token-bucket rate limiting (D8): in-memory, single-replica v1.
// Buckets are keyed lazily and GC'd on access; capacity refills over
// the window. Deterministic tests use allowN's clock seam.

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// buckets is a lazily-created per-key rate.Limiter table.
type buckets struct {
	mu      sync.Mutex
	m       map[string]*rate.Limiter
	every   time.Duration // one token per `every`
	burst   int           // instantaneous allowance
	lastGC  time.Time
}

func newBuckets(perMinute int, window time.Duration) *buckets {
	return &buckets{
		m:     make(map[string]*rate.Limiter),
		every: window / time.Duration(perMinute),
		burst: perMinute, // burst = a full minute's worth (§P2-0 buckets)
	}
}

func (b *buckets) allow(key string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	l, ok := b.m[key]
	if !ok {
		l = rate.NewLimiter(rate.Every(b.every), b.burst)
		b.m[key] = l
	}
	// opportunistic GC: keep the map bounded (single-replica v1)
	now := time.Now()
	if now.Sub(b.lastGC) > time.Minute && len(b.m) > 10_000 {
		for k, lim := range b.m {
			if lim.Tokens() > float64(b.burst) {
				delete(b.m, k)
			}
		}
		b.lastGC = now
	}
	return l.Allow()
}

// ipBuckets is buckets with a distinct type for readability at call sites.
type ipBuckets = buckets

func newIPBuckets(perMinute int, window time.Duration) *ipBuckets { return newBuckets(perMinute, window) }

type userBuckets = buckets