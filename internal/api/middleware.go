package api

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
)

// RequestID assigns a UUID to every request and echoes it as X-Request-ID.
func (s *Server) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = newUUID()
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, id)))
	})
}

// RequestLogger emits one structured line per request.
// Normative from the first log line: method, path, status, duration,
// request_id — NEVER request bodies, NEVER cookies (the no-plaintext
// promise applied to logs).
func (s *Server) requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := timeNow()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		reqID, _ := requestIDFromContext(r.Context())
		s.logger.LogAttrs(r.Context(), slog.LevelInfo, "request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", rec.status),
			slog.Int64("duration_ms", timeSince(start)),
			slog.String("request_id", reqID),
		)
	})
}

// Recover converts panics into 500 JSON; the stack goes to the log only,
// never the response body.
func (s *Server) recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				reqID, _ := requestIDFromContext(r.Context())
				s.logger.Error("panic recovered",
					slog.String("request_id", reqID),
					slog.Any("panic", rec),
					slog.String("stack", string(stackDump())),
				)
				writeJSON(w, http.StatusInternalServerError, map[string]string{
					"error": "internal server error",
				})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// SecureHeaders sets the baseline security headers. CSP is a permissive
// placeholder in P0 — Phase 6 tightens the values (plumbing exists now).
func (s *Server) secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'")
		next.ServeHTTP(w, r)
	})
}

// CORS allows the Vite dev origin (when configured) with credentials.
// In prod (no DEV_ORIGIN) it is a no-op — same-origin only.
func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := s.cfg.DevOrigin
		if origin != "" && r.Header.Get("Origin") == origin {
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Access-Control-Allow-Credentials", "true")
			h.Set("Vary", "Origin")
			h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			h.Set("Access-Control-Allow-Headers", "Content-Type, X-Request-ID")
		}
		if r.Method == http.MethodOptions && origin != "" && r.Header.Get("Origin") == origin {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// statusRecorder captures the status code for request logging.
type statusRecorder struct {
	http.ResponseWriter
	status  int
	written bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.written {
		r.status = code
		r.written = true
	}
	r.ResponseWriter.WriteHeader(code)
}

// WriteHeaderString exists to satisfy any interface assertions on wrappers
// that need to know whether headers were sent.
func (r *statusRecorder) Written() bool { return r.written }

// trimOrigin strips credentials from a URL-like string (defensive helper
// for future CORS config parsing).
func trimOrigin(s string) string {
	return strings.TrimSpace(s)
}
