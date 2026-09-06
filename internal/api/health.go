package api

import (
	"log/slog"
	"net/http"
)

// handleHealth always answers 200 — liveness only.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleReady answers 503 while Postgres is unreachable, 200 once it pings.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if err := readyPing(r.Context(), s.pool); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// log returns the server's structured logger.
func (s *Server) log() *slog.Logger { return s.logger }
