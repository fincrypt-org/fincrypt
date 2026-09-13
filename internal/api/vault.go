package api

// Vault handlers (C2.3): settings/preferences blob with optimistic
// concurrency (If-Match on blobVersion). D5: budgets live in here.

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
)

// vaultResponse is GET /api/vault.
type vaultResponse struct {
	BlobVersion   int    `json:"blobVersion"`
	EncryptedBlob string `json:"encryptedBlob"` // std b64
}

// handleVaultGet returns the caller's vault blob.
func (s *Server) handleVaultGet(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthenticated", "authentication required")
		return
	}
	pool, ok := poolOf(s.pool)
	if !ok {
		s.writeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	var version int
	var blob []byte
	err := pool.QueryRow(r.Context(),
		`select blob_version, encrypted_blob from vaults where user_id = $1`, userID,
	).Scan(&version, &blob)
	if errors.Is(err, errNoVaultRows) {
		// fresh user: empty vault at version 0
		writeJSON(w, http.StatusOK, vaultResponse{BlobVersion: 0, EncryptedBlob: ""})
		return
	}
	if err != nil {
		s.logger.Warn("vault get failed", slog.String("error", err.Error()))
		s.writeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, vaultResponse{BlobVersion: version, EncryptedBlob: encodeOpaqueB64(blob)})
}

// handleVaultPut replaces the vault blob when If-Match matches the
// current blobVersion; stale writes get 409 + the current version.
func (s *Server) handleVaultPut(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthenticated", "authentication required")
		return
	}
	if !s.rates.allowSync(userID) {
		s.reject429(w)
		return
	}
	ifMatch := r.Header.Get("If-Match")
	if ifMatch == "" {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "If-Match required")
		return
	}
	expected, err := strconv.Atoi(ifMatch)
	if err != nil || expected < 0 {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "If-Match must be a version number")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxEnvelopeBytes) // vault shares the 256 KB cap (D5)
	var body struct {
		EncryptedBlob string `json:"encryptedBlob"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	blob, err := decodeB64Flexible(body.EncryptedBlob)
	if err != nil || len(blob) == 0 {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "encryptedBlob must be non-empty base64")
		return
	}

	pool, ok := poolOf(s.pool)
	if !ok {
		s.writeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}

	// Optimistic concurrency: bump only when the version matches.
	tag, err := pool.Exec(r.Context(), `
		update vaults set
			encrypted_blob = $3,
			blob_version = blob_version + 1,
			last_modified_at = now()
		where user_id = $1 and blob_version = $2
	`, userID, expected, blob)
	if err != nil {
		s.logger.Warn("vault put failed", slog.String("error", err.Error()))
		s.writeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	if tag.RowsAffected() == 0 {
		// either stale If-Match or no vault row yet
		var current int
		qerr := pool.QueryRow(r.Context(),
			`select blob_version from vaults where user_id = $1`, userID,
		).Scan(&current)
		if qerr != nil {
			// no vault row yet: create at version 1 when the client starts at 0
			if expected != 0 {
				s.writeError(w, http.StatusConflict, "conflict", "stale version")
				return
			}
			if _, xerr := pool.Exec(r.Context(),
				`insert into vaults (user_id, encrypted_blob, blob_version) values ($1, $2, 1)`,
				userID, blob,
			); xerr != nil {
				s.logger.Warn("vault create failed", slog.String("error", qerr.Error()))
				s.writeError(w, http.StatusInternalServerError, "internal", "internal error")
				return
			}
			writeJSON(w, http.StatusOK, vaultResponse{BlobVersion: 1, EncryptedBlob: encodeOpaqueB64(blob)})
			return
		}
		w.Header().Set("ETag", strconv.Itoa(current))
		s.writeError(w, http.StatusConflict, "conflict", "stale version")
		return
	}
	newVersion := expected + 1
	w.Header().Set("ETag", strconv.Itoa(newVersion))
	s.audit(r.Context(), "vault_sync", userID, clientIP(r), r.UserAgent())
	writeJSON(w, http.StatusOK, vaultResponse{BlobVersion: newVersion, EncryptedBlob: encodeOpaqueB64(blob)})
}

var errNoVaultRows = errors.New("vault: no row")

// registerVaultRoutes mounts the vault routes.
func (s *Server) registerVaultRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/vault", s.requireSession(s.handleVaultGet))
	mux.HandleFunc("PUT /api/vault", s.requireSession(s.enforceMutationCSRF(s.handleVaultPut)))
}
