package api

// Auth HTTP handlers (C2.1). Thin door over internal/auth.Service:
// decode JSON, call the service, map sentinel errors to §P2-0 codes.
// Body-never-logged (J5) applies from this first handler on.

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/fincrypt-org/fincrypt/internal/auth"
)

// errorBody is the stable error envelope (§P2-0).
type errorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// writeError emits the envelope with the given status. Generic
// messages only — no key material, no existence leaks (§P2-0).
func (s *Server) writeError(w http.ResponseWriter, status int, code, message string) {
	var e errorBody
	e.Error.Code = code
	e.Error.Message = message
	writeJSON(w, status, e)
}

// registerRoutes mounts the auth endpoints on the mux.
func (s *Server) registerAuthRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/auth/register/start", s.handleRegisterStart)
	mux.HandleFunc("POST /api/auth/register/finish", s.handleRegisterFinish)
	mux.HandleFunc("POST /api/auth/login/start", s.handleLoginStart)
	mux.HandleFunc("POST /api/auth/login/finish", s.handleLoginFinish)
}

func (s *Server) handleRegisterStart(w http.ResponseWriter, r *http.Request) {
	var body auth.RegisterStartBody
	if !s.readBody(w, r, &body) {
		return
	}
	if body.Email == "" || body.RegistrationReq == "" {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "email and registrationRequest are required")
		return
	}
	resp, salt, err := s.auth.RegisterStart(r.Context(), body.Email, body.RegistrationReq)
	if err != nil {
		s.logger.Warn("register/start failed", slog.String("error", err.Error()))
		s.writeError(w, http.StatusBadRequest, "invalid_request", "registration rejected")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"registrationResponse": resp,
		"kdfSalt":              salt,
	})
}

func (s *Server) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	var body auth.RegisterFinishBody
	if !s.readBody(w, r, &body) {
		return
	}
	userID, err := s.auth.RegisterFinish(r.Context(), body)
	if errors.Is(err, auth.ErrEmailTaken) {
		s.writeError(w, http.StatusConflict, "email_taken", "email already registered")
		return
	}
	if err != nil {
		s.logger.Warn("register/finish failed", slog.String("error", err.Error()))
		s.writeError(w, http.StatusBadRequest, "invalid_request", "registration failed")
		return
	}
	// Session cookie issuance lands with C2.2 (session middleware).
	writeJSON(w, http.StatusCreated, map[string]string{"userId": userID})
}

func (s *Server) handleLoginStart(w http.ResponseWriter, r *http.Request) {
	var body auth.LoginStartBody
	if !s.readBody(w, r, &body) {
		return
	}
	if body.Email == "" || body.StartLogin == "" {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "email and startLoginRequest are required")
		return
	}
	resp, err := s.auth.LoginStart(r.Context(), body.Email, body.StartLogin)
	if err != nil {
		// Unknown user already went through the fake-record path inside
		// the service — any error here is a genuine 400/500. Unknown vs
		// known is NOT observable at this step (D8).
		s.logger.Warn("login/start failed", slog.String("error", err.Error()))
		s.writeError(w, http.StatusBadRequest, "invalid_request", "login failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"serverMsg": resp})
}

func (s *Server) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	var body auth.LoginFinishBody
	if !s.readBody(w, r, &body) {
		return
	}
	resp, err := s.auth.LoginFinish(r.Context(), auth.LoginFinishBody{
		Email:       body.Email,
		FinishLogin: body.FinishLogin,
	})
	if errors.Is(err, auth.ErrInvalidCredentials) || errors.Is(err, auth.ErrUnknownUser) ||
		errors.Is(err, auth.ErrNoPendingLogin) {
		// Uniform 401 — no existence oracle (D8).
		s.writeError(w, http.StatusUnauthorized, "auth_failed", "authentication failed")
		return
	}
	if err != nil {
		s.logger.Warn("login/finish failed", slog.String("error", err.Error()))
		s.writeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// readBody decodes a JSON body with a 1 MiB cap. Returns false (and has
// written the error) when the body is unusable. OPAQUE messages are
// ≤1 KiB; the cap is a tripwire, not a feature.
func (s *Server) readBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return false
	}
	return true
}