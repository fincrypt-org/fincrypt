package api

// Audit-log writes (J5): schema fields only — action, user_id (nullable),
// ip_address (inet), user_agent. NEVER bodies, cookies, or ciphertext.
// The SQL lives here so every handler can share one seam.

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// auditWriter performs audit inserts against the real pool.
type auditWriter struct {
	pool *pgxpool.Pool
}

func newAuditWriter(pool *pgxpool.Pool) *auditWriter {
	if pool == nil {
		return nil
	}
	return &auditWriter{pool: pool}
}

// audit inserts one row; errors are the caller's to swallow (audit
// failure must never fail the request).
func (a *auditWriter) audit(ctx context.Context, action, userID, ip, ua string) error {
	var uid any
	if userID != "" {
		uid = userID
	}
	var ipArg any
	if ip != "" {
		ipArg = ip
	}
	_, err := a.pool.Exec(ctx,
		`insert into audit_log (action, user_id, ip_address, user_agent) values ($1, $2, $3, $4)`,
		action, uid, ipArg, ua,
	)
	return err
}

// noopAudit is the test seam.
type noopAudit struct{}

func (noopAudit) audit(context.Context, string, string, string, string) error { return nil }

var _ auditQuerier = (*auditWriter)(nil)
var _ auditQuerier = noopAudit{}
var _ = pgx.ErrNoRows