package api

// Session middleware (C2.2): JWT (HS256, kid-aware) in the fincrypt_session
// httpOnly cookie, D9 CSRF posture (Origin allowlist + JSON-only on
// mutations), rate limits (D8 table), and the audit-log helper (J5).

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

)

// sessionCookie is the §P2-0 cookie name.
const sessionCookie = "fincrypt_session"

// sessionTTL is the D6 stateless session lifetime.
const sessionTTL = 7 * 24 * time.Hour

// userIDKey indexes the authenticated user id in the request context.
const userIDKey ctxKey = iota + 100

// userIDFromContext returns the authenticated user id, if any.
func userIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(userIDKey).(string)
	return id, ok
}

// sessionClaims is the JWT payload (§P2-0: sub/iat/exp only).
type sessionClaims struct {
	UserID string `json:"sub"`
	jwt.RegisteredClaims
}

// issueSession signs a session JWT with SessionKeys[0] and sets the cookie.
func (s *Server) issueSession(w http.ResponseWriter, userID string) {
	now := time.Now()
	claims := sessionClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(sessionTTL)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(s.cfg.SessionKeys[0])
	if err != nil {
		// Signing failure is a server fault; Recover turns it into 500.
		panic("api: sign session: " + err.Error())
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    signed,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.Env == "prod",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL / time.Second),
	})
}

// clearSession expires the cookie (D6: stateless — nothing else to do).
func clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// verifySession validates the cookie JWT against either key (kid is
// implicit: try Keys[0] then Keys[1]).
func (s *Server) verifySession(tokenString string) (string, bool) {
	var claims sessionClaims
	for _, key := range s.cfg.SessionKeys {
		tok, err := jwt.ParseWithClaims(tokenString, &claims, func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return key, nil
		}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithTimeFunc(time.Now))
		if err == nil && tok.Valid {
			return claims.UserID, true
		}
	}
	return "", false
}

// requireSession wraps a handler, injecting the authenticated user id.
// 401 (never 500) without a valid session.
func (s *Server) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil || c.Value == "" {
			s.writeError(w, http.StatusUnauthorized, "unauthenticated", "authentication required")
			return
		}
		userID, ok := s.verifySession(c.Value)
		if !ok {
			s.writeError(w, http.StatusUnauthorized, "unauthenticated", "authentication required")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), userIDKey, userID)))
	}
}

// ─── CSRF / Origin (D9) ──────────────────────────────────────────────

// allowedOrigin reports whether an Origin header value may call us.
// Dev: the configured DEV_ORIGIN; prod: same-origin only (no cross
// origin allowed at all in v1).
func (s *Server) allowedOrigin(origin string) bool {
	if origin == "" {
		return false // mutations with a missing Origin are rejected (D9)
	}
	if s.cfg.Env == "dev" && s.cfg.DevOrigin != "" {
		return strings.EqualFold(origin, s.cfg.DevOrigin)
	}
	return false // prod: browser-to-same-origin requests still send Origin
	// for non-GET; same-origin requests will carry the site origin, which
	// must then equal the host. Checked against the request host instead:
}

// originAllowedForHost extends allowedOrigin for prod same-origin.
func (s *Server) originAllowedForHost(r *http.Request, origin string) bool {
	if s.cfg.Env == "dev" {
		return s.allowedOrigin(origin)
	}
	// Prod: accept if the origin host:port matches the request Host.
	if origin == "" {
		return false
	}
	o := origin
	if i := strings.Index(o, "://"); i >= 0 {
		o = o[i+3:]
	}
	return strings.EqualFold(o, r.Host)
}

// enforceMutationCSRF wraps state-changing handlers with the D9 checks:
// Origin allowlist + JSON content-type. Missing Origin ⇒ 403.
func (s *Server) enforceMutationCSRF(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if !s.originAllowedForHost(r, origin) {
			s.writeError(w, http.StatusForbidden, "csrf", "origin not allowed")
			return
		}
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			s.writeError(w, http.StatusUnsupportedMediaType, "csrf", "JSON bodies only")
			return
		}
		next(w, r)
	}
}

// enforceOriginOnly is enforceMutationCSRF without the JSON-body rule,
// for the raw-byte attachment endpoint (Origin check still applies).
func (s *Server) enforceOriginOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.originAllowedForHost(r, r.Header.Get("Origin")) {
			s.writeError(w, http.StatusForbidden, "csrf", "origin not allowed")
			return
		}
		next(w, r)
	}
}

// ─── rate limits (D8) ────────────────────────────────────────────────

// rateTable implements the §P2-0 buckets: per-IP for auth, per-user for
// sync. Single-replica in-memory (D6); multi-replica → shared store P6.
type rateTable struct {
	authPerIP   *ipBuckets // 10/min/IP
	syncPerUser *userBuckets
	attachPerUser *userBuckets
}

func newRateTable() *rateTable {
	authPerMin := 10
	if v := os.Getenv("RATE_AUTH_PER_MIN"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			authPerMin = n
		}
	}
	return &rateTable{
		authPerIP:    newIPBuckets(authPerMin, time.Minute),
		syncPerUser:  newBuckets(60, time.Minute),
		attachPerUser: newBuckets(30, time.Minute),
	}
}

// allowAuth consumes one auth slot for the client IP.
func (rt *rateTable) allowAuth(ip string) bool { return rt.authPerIP.allow(ip) }

// allowSync consumes one sync slot for the user. Used by C2.3's sync
// handlers; kept here so the table is complete and testable now.
func (rt *rateTable) allowSync(userID string) bool { return rt.syncPerUser.allow(userID) } //nolint:unused

// allowAttachment consumes one attachment slot for the user (C2.4).
func (rt *rateTable) allowAttachment(userID string) bool { return rt.attachPerUser.allow(userID) } //nolint:unused

// clientIP extracts the remote address host (no XFF trust in v1 —
// behind a proxy this is the proxy's IP; documented residual).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// reject429 writes the uniform rate-limit response.
func (s *Server) reject429(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "60")
	s.writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
}

// ─── audit log (J5) ──────────────────────────────────────────────────

// audit writes one audit row. Schema fields only — action, user (may be
// empty), ip, ua. NEVER bodies, cookies, or ciphertext (J5).
func (s *Server) audit(ctx context.Context, action, userID, ip, ua string) {
	s.auditInsert(ctx, action, userID, ip, ua)
}

// auditInsert is the SQL seam; wired to the real pool in the server
// constructor, stubbed in tests.
func (s *Server) auditInsert(ctx context.Context, action, userID, ip, ua string) {
	if s.auditQ == nil {
		return
	}
	if err := s.auditQ.audit(ctx, action, userID, ip, ua); err != nil {
		// Audit failures never fail the request; log with schema fields only.
		s.logger.Warn("audit insert failed", slog.String("action", action))
	}
}

// auditQuerier is the audit-write seam.
type auditQuerier interface {
	audit(ctx context.Context, action, userID, ip, ua string) error
}

var _ = jwt.ErrTokenExpired