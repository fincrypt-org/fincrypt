package api

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fincrypt-org/fincrypt/internal/config"
)

// Pinger is the readiness seam: anything that can report DB liveness.
// *pgxpool.Pool satisfies it; tests inject failures.
type Pinger interface {
	Ping(ctx context.Context) error
}

// Server holds everything the HTTP handlers need.
type Server struct {
	cfg     config.Config
	pool    Pinger
	logger  *slog.Logger
	handler http.Handler
}

// NewServer builds the full middleware chain and mounts routes.
// Fixed chain order: RequestID -> RequestLogger -> Recover -> SecureHeaders -> CORS.
// Auth and rate-limit middleware slot in here in later phases (chain
// slots reserved — no logic in P0).
func NewServer(cfg config.Config, pool *pgxpool.Pool, logger *slog.Logger) *Server {
	return NewServerWithPinger(cfg, pool, logger)
}

// NewServerWithPinger is the test seam: same chain, any Pinger.
func NewServerWithPinger(cfg config.Config, pool Pinger, logger *slog.Logger) *Server {
	s := &Server{cfg: cfg, pool: pool, logger: logger}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)

	var h http.Handler = mux
	h = s.cors(h)
	h = s.secureHeaders(h)
	h = s.recoverMiddleware(h)
	h = s.requestLogger(h)
	h = s.requestID(h)
	s.handler = h
	return s
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}
