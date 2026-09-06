package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// writeJSON emits a JSON body with the given status.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if body != nil {
		_ = json.NewEncoder(w).Encode(body)
	}
}

// requestIDFromContext returns the per-request ID, if one was set.
func requestIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(requestIDKey).(string)
	return id, ok
}

// readyPingTimeout bounds the /readyz database probe.
const readyPingTimeout = time.Second

// readyPing wraps a Pinger with the 1s readiness deadline.
func readyPing(ctx context.Context, p Pinger) error {
	pingCtx, cancel := context.WithTimeout(ctx, readyPingTimeout)
	defer cancel()
	return p.Ping(pingCtx)
}
