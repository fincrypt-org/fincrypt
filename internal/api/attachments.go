package api

// Attachments (C2.4): PUT /api/attachments stores a raw envelope
// (client-encrypted) ≤ 10 MiB under a random UUID filename; original
// filename and mime live INSIDE the ciphertext. GET retrieves it
// owner-only (404 everywhere else, J3).

import (
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5"
)

// maxAttachmentBytes is the §P2-0 attachment cap (10 MiB).
const maxAttachmentBytes = 10 << 20

// handleAttachmentPut streams the raw envelope bytes to storage.
// MaxBytesReader caps BEFORE any full read (pitfall 6) so oversized
// bodies never buffer in memory.
func (s *Server) handleAttachmentPut(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthenticated", "authentication required")
		return
	}
	if !s.rates.allowAttachment(userID) {
		s.reject429(w)
		return
	}

	// 10 MiB cap + 1 KB headroom for the multipart/JSON envelope — the
	// body IS the envelope (raw bytes), so the cap is the cap.
	r.Body = http.MaxBytesReader(w, r.Body, maxAttachmentBytes)
	blob, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			s.writeError(w, http.StatusRequestEntityTooLarge, "too_large", "attachment exceeds 10 MiB")
			return
		}
		s.writeError(w, http.StatusBadRequest, "invalid_request", "unreadable body")
		return
	}
	// minimum plausible envelope: 12B nonce + 17B tag
	if len(blob) < 29 {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "attachment too small to be an envelope")
		return
	}

	storedName := randomID() + ".bin" // random UUID filename; real name is inside the ciphertext
	pool, ok := poolOf(s.pool)
	if !ok {
		s.writeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	var id string
	err = pool.QueryRow(r.Context(), `
		insert into encrypted_attachments (user_id, encrypted_blob, mime, stored_name)
		values ($1, $2, $3, $4) returning id::text
	`, userID, blob, "application/octet-stream", storedName,
	).Scan(&id)
	if err != nil {
		s.logger.Warn("attachment store failed", slog.String("error", err.Error()))
		s.writeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.audit(r.Context(), "upload", userID, clientIP(r), r.UserAgent())
	writeJSON(w, http.StatusCreated, map[string]any{
		"attachmentId": id,
		"size":         len(blob),
	})
}

// handleAttachmentGet streams the attachment back — owner-only, 404
// otherwise (J3: 404 never 403).
func (s *Server) handleAttachmentGet(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthenticated", "authentication required")
		return
	}
	attachmentID := r.PathValue("id")
	pool, ok := poolOf(s.pool)
	if !ok {
		s.writeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	var blob []byte
	err := pool.QueryRow(r.Context(),
		`select encrypted_blob from encrypted_attachments where id = $1 and user_id = $2`,
		attachmentID, userID,
	).Scan(&blob)
	if errors.Is(err, pgx.ErrNoRows) {
		// not found OR not yours — indistinguishable (J3)
		s.writeError(w, http.StatusNotFound, "not_found", "attachment not found")
		return
	}
	if err != nil {
		s.logger.Warn("attachment get failed", slog.String("error", err.Error()))
		s.writeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", "attachment") // never inline
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(blob)
}

// registerAttachmentRoutes mounts the attachment routes. The PUT skips
// the JSON-only check (the body is raw envelope bytes) but keeps the
// Origin requirement — a raw-origin enforcement without JSON.
func (s *Server) registerAttachmentRoutes(mux *http.ServeMux) {
	mux.HandleFunc("PUT /api/attachments", s.requireSession(s.enforceOriginOnly(s.handleAttachmentPut)))
	mux.HandleFunc("GET /api/attachments/{id}", s.requireSession(s.handleAttachmentGet))
}
