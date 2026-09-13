package api

// Sync + vault HTTP handlers (C2.3). POST /api/records/sync (unified
// push+pull), DELETE /api/records/{type}/{id}, GET/PUT /api/vault.
// All session-gated, CSRF-guarded, rate-limited, audited (C2.2 seams).

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/fincrypt-org/fincrypt/internal/db"
)

// syncBody is POST /api/records/sync (§P2-0).
type syncBody struct {
	Since  *string         `json:"since"` // RFC3339 | null
	Pushes []json.RawMessage `json:"pushes"`
}

// syncResponse is the 200 body.
type syncResponse struct {
	ServerTime string           `json:"serverTime"`
	Changes    []changeJSON     `json:"changes"`
	NextCursor *string          `json:"nextCursor,omitempty"`
}

// changeJSON is one change object: envelope XOR tombstone (§P2-0).
type changeJSON struct {
	Envelope  *Envelope         `json:"envelope,omitempty"`
	Tombstone *tombstoneJSON    `json:"tombstone,omitempty"`
}

type tombstoneJSON struct {
	RecordID  string `json:"recordId"`
	Type      string `json:"type"`
	DeletedAt string `json:"deletedAt"`
}

// handleSync implements the unified sync endpoint.
func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthenticated", "authentication required")
		return
	}
	if !s.rates.allowSync(userID) {
		s.reject429(w)
		return
	}
	var body syncBody
	if !s.readBody(w, r, &body) {
		return
	}

	// parse since cursor
	var since time.Time
	if body.Since != nil && *body.Since != "" {
		ts, err := time.Parse(time.RFC3339, *body.Since)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_request", "since is not RFC 3339")
			return
		}
		since = ts
	}

	// batch caps first (J2)
	if err := validateBatchCount(len(body.Pushes)); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_envelope", "push rejected")
		return
	}

	// validate + convert pushes
	pushes := make([]db.SyncEnvelope, 0, len(body.Pushes))
	for i, raw := range body.Pushes {
		e, err := strictEnvelope(raw)
		if err != nil {
			s.rejectBatch(w, i, err)
			return
		}
		if err := validateEnvelope(userID, e); err != nil {
			s.rejectBatch(w, i, err)
			return
		}
		// sync only carries the three routed types
		if e.Type == "attachments" || e.Type == "vault" {
			s.writeError(w, http.StatusBadRequest, "invalid_request", "type not syncable")
			return
		}
		if !syncTypeAllowed(e.Type) {
			s.writeError(w, http.StatusBadRequest, "invalid_request", "type not syncable")
			return
		}
		ts, _ := time.Parse(time.RFC3339, e.Ts)
		ciphertext, _ := decodeB64Flexible(e.Ciphertext)
		pushes = append(pushes, db.SyncEnvelope{
			RecordID: e.RecordID,
			Type:     e.Type,
			Blob:     ciphertext,
			Aad:      e.Aad,
			Ts:       ts,
		})
	}

	pool, ok := poolOf(s.pool)
	if !ok {
		s.writeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}

	// push (atomic) — only non-attachment/vault types reach here
	_, err := db.PushEnvelopes(r.Context(), pool, userID, pushes)
	if err != nil {
		s.logger.Warn("sync push failed", slog.String("error", err.Error()))
		s.writeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}

	// pull (delta)
	changes, maxTS, err := db.PullChanges(r.Context(), pool, userID, since, 500)
	if err != nil {
		s.logger.Warn("sync pull failed", slog.String("error", err.Error()))
		s.writeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}

	resp := syncResponse{ServerTime: time.Now().UTC().Format(time.RFC3339)}
	for _, c := range changes {
		if c.Tombstone != nil {
			resp.Changes = append(resp.Changes, changeJSON{Tombstone: &tombstoneJSON{
				RecordID:  c.Tombstone.RecordID,
				Type:      c.Tombstone.Type,
				DeletedAt: c.Tombstone.DeletedAt.UTC().Format(time.RFC3339),
			}})
			continue
		}
		env := c.Envelope
		resp.Changes = append(resp.Changes, changeJSON{Envelope: &Envelope{
			RecordID:   env.RecordID,
			Type:       env.Type,
			Nonce:      "", // packed blob; client splits nonce||ct — see below
			Ciphertext: encodeOpaqueB64(env.Blob),
			Aad:        buildAad(userID, env.Type, env.RecordID),
			Ts:         env.Ts.UTC().Format(time.RFC3339),
		}})
	}
	if !maxTS.IsZero() {
		cursor := maxTS.UTC().Format(time.RFC3339Nano)
		resp.NextCursor = &cursor
	}
	s.audit(r.Context(), "sync", userID, clientIP(r), r.UserAgent())
	writeJSON(w, http.StatusOK, resp)
}

// syncTypeAllowed lists the types routed through sync.
func syncTypeAllowed(t string) bool {
	return t == "transactions" || t == "accounts" || t == "chat"
}

// rejectBatch writes the uniform malformed-batch 400 (J2: the whole
// batch is rejected, never partially applied).
func (s *Server) rejectBatch(w http.ResponseWriter, index int, err error) {
	var ee *envelopeError
	if errors.As(err, &ee) {
		s.logger.Warn("sync batch rejected", slog.Int("index", index))
	} else {
		s.logger.Warn("sync batch rejected", slog.Int("index", index))
	}
	s.writeError(w, http.StatusBadRequest, "invalid_envelope", "push rejected")
}

// encodeOpaqueB64 re-encodes bytes as canonical std base64 (I5).
func encodeOpaqueB64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// handleDelete tombstones one record (LWW-gated).
func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthenticated", "authentication required")
		return
	}
	recordType := r.PathValue("type")
	recordID := r.PathValue("id")
	if !recordTypes[recordType] || !syncTypeAllowed(recordType) {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "unknown record type")
		return
	}
	tsParam := r.URL.Query().Get("ts")
	if tsParam == "" {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "ts required")
		return
	}
	ts, err := time.Parse(time.RFC3339, tsParam)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "ts not RFC 3339")
		return
	}
	if ts.After(time.Now().Add(futureTolerance)) {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "ts in the future")
		return
	}
	pool, ok := poolOf(s.pool)
	if !ok {
		s.writeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	applied, _, err := db.DeleteRecord(r.Context(), pool, userID, recordType, recordID, ts)
	if err != nil {
		s.logger.Warn("delete failed", slog.String("error", err.Error()))
		s.writeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	if !applied {
		// either already deleted or the live row is newer (LWW): both are
		// 409-with-winner semantics; v1 returns 409 without leaking state
		s.writeError(w, http.StatusConflict, "conflict", "delete not applied")
		return
	}
	s.audit(r.Context(), "delete", userID, clientIP(r), r.UserAgent())
	w.WriteHeader(http.StatusNoContent)
}

// registerSyncRoutes mounts the sync + delete routes (session-gated).
func (s *Server) registerSyncRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/records/sync", s.requireSession(s.enforceMutationCSRF(s.handleSync)))
	mux.HandleFunc("DELETE /api/records/{type}/{id}", s.requireSession(s.handleDelete))
}