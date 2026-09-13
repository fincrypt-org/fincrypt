package api

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fincrypt-org/fincrypt/internal/auth"
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
	auth    *auth.Service
}

// NewServer builds the full middleware chain and mounts routes.
// Fixed chain order: RequestID -> RequestLogger -> Recover -> SecureHeaders -> CORS.
// Auth and rate-limit middleware slot in here in later phases (chain
// slots reserved — no logic in P0).
func NewServer(cfg config.Config, pool *pgxpool.Pool, logger *slog.Logger) *Server {
	return NewServerWithPinger(cfg, pool, logger)
}

// NewServerWithPinger is the test seam: same chain, any Pinger.
// The auth service is built from cfg.OpaqueServerSetup (P2: required).
func NewServerWithPinger(cfg config.Config, pool Pinger, logger *slog.Logger) *Server {
	s := &Server{cfg: cfg, pool: pool, logger: logger}
	s.mount(newAuthService(pool, logger, cfg.OpaqueServerSetup))
	return s
}

// NewServerWithAuth is the test seam for handler tests: an explicit
// auth service (may be a wrapper with a stub pool), no Pinger coupling.
func NewServerWithAuth(cfg config.Config, authSvc *auth.Service, logger *slog.Logger) *Server {
	s := &Server{cfg: cfg, logger: logger}
	s.mount(authSvc)
	return s
}

// mount builds the route table and middleware chain around the given
// (possibly nil, in P0-health tests) auth service.
func (s *Server) mount(authSvc *auth.Service) {
	s.auth = authSvc
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
	if authSvc != nil {
		s.registerAuthRoutes(mux)
	}

	var h http.Handler = mux
	h = s.cors(h)
	h = s.secureHeaders(h)
	h = s.recoverMiddleware(h)
	h = s.requestLogger(h)
	h = s.requestID(h)
	s.handler = h
}

// newAuthService wires the auth service; nil-safe for health tests that
// pass a nil *pgxpool.Pool.
func newAuthService(pool Pinger, logger *slog.Logger, setup string) *auth.Service {
	if pool == nil || setup == "" {
		return nil
	}
	svc, err := auth.NewService(pool.(*pgxpool.Pool), logger, setup)
	if err != nil {
		// Fail-fast at boot, consistent with config.Load().
		panic("api: auth service: " + err.Error())
	}
	return svc
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}