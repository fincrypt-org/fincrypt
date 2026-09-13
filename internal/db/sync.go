package db

// Sync persistence (C2.3): atomic LWW envelope upserts, LWW-gated
// tombstones, and the keyset cursor delta pull. All queries are
// user-scoped by construction (J3).

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SyncEnvelope is one pushed envelope after validation: the routing key
// plus the opaque blob. recordID is client-generated; the server never
// invents content.
type SyncEnvelope struct {
	RecordID string
	Type     string
	Blob     []byte // nonce||ciphertext packed — stored verbatim in encrypted_blob
	Aad      string
	Ts       time.Time
}

// PushOutcome is per-envelope result: applied flag + the winning
// envelope as stored (so the pusher converges).
type PushOutcome struct {
	RecordID string
	Applied  bool
	Envelope []byte // the stored blob (winner), encrypted
	Type     string
	Ts       time.Time
}

// Change is one sync-delta change object: either a live envelope or a
// tombstone (never a mutated envelope for a delete — §P2-0).
type Change struct {
	Envelope  *SyncEnvelope
	Tombstone *Tombstone
}

// Tombstone surfaces a deletion to other devices.
type Tombstone struct {
	RecordID  string    `json:"recordId"`
	Type      string    `json:"type"`
	DeletedAt time.Time `json:"deletedAt"`
}

var errUnknownType = errors.New("db: unknown record type")

// PushEnvelopes routes each envelope to its §1 table inside one
// transaction (atomicity: no partial batches). LWW is decided IN SQL
// (ON CONFLICT ... WHERE) — never read-then-write (pitfall 2).
//
// Routing: transactions → encrypted_transactions, accounts → accounts,
// chat → encrypted_chat_messages. attachments/vault are NOT pushed via
// sync (they have their own endpoints) and are rejected by the caller's
// validator before reaching here.
func PushEnvelopes(ctx context.Context, pool *pgxpool.Pool, userID string, pushes []SyncEnvelope) ([]PushOutcome, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	out := make([]PushOutcome, 0, len(pushes))
	for _, p := range pushes {
		var applied bool
		var blob []byte
		var ts time.Time

		// account_key: the schema column stores the parent account's
		// record id. v1 stores the record's own id (the client linkage
		// lives inside its ciphertext); balances are derived client-side.
		switch p.Type {
		case "transactions":
			err = tx.QueryRow(ctx, `
				insert into encrypted_transactions (id, user_id, account_key, encrypted_blob, tx_date, updated_at)
				values ($1, $2, $3, $4, $5::date, $6)
				on conflict (id) do update set
					encrypted_blob = excluded.encrypted_blob,
					updated_at = excluded.updated_at
				where encrypted_transactions.updated_at < excluded.updated_at
				returning true, encrypted_transactions.encrypted_blob, encrypted_transactions.updated_at
			`, p.RecordID, userID, p.RecordID, p.Blob, p.Ts.Format("2006-01-02"), p.Ts,
			).Scan(&applied, &blob, &ts)
			if errors.Is(err, pgx.ErrNoRows) {
				applied = false
				err = tx.QueryRow(ctx,
					`select encrypted_blob, updated_at from encrypted_transactions where id = $1 and user_id = $2`,
					p.RecordID, userID,
				).Scan(&blob, &ts)
			}
			if err != nil {
				return nil, err
			}
		case "accounts":
			err = tx.QueryRow(ctx, `
				insert into accounts (id, user_id, account_key, encrypted_blob, updated_at)
				values ($1, $2, $3, $4, $5)
				on conflict (id) do update set
					encrypted_blob = excluded.encrypted_blob,
					updated_at = excluded.updated_at
				where accounts.updated_at < excluded.updated_at
				returning true, accounts.encrypted_blob, accounts.updated_at
			`, p.RecordID, userID, p.RecordID, p.Blob, p.Ts,
			).Scan(&applied, &blob, &ts)
			if errors.Is(err, pgx.ErrNoRows) {
				applied = false
				err = tx.QueryRow(ctx,
					`select encrypted_blob, updated_at from accounts where id = $1 and user_id = $2`,
					p.RecordID, userID,
				).Scan(&blob, &ts)
			}
			if err != nil {
				return nil, err
			}
		case "chat":
			// Chat rows are append-only in v1; a re-pushed id is ignored.
			err = tx.QueryRow(ctx, `
				insert into encrypted_chat_messages (id, user_id, encrypted_blob, created_at)
				values ($1, $2, $3, $4)
				on conflict (id) do nothing
				returning true, encrypted_chat_messages.encrypted_blob, encrypted_chat_messages.created_at
			`, p.RecordID, userID, p.Blob, p.Ts,
			).Scan(&applied, &blob, &ts)
			if errors.Is(err, pgx.ErrNoRows) {
				applied = false
				err = tx.QueryRow(ctx,
					`select encrypted_blob, created_at from encrypted_chat_messages where id = $1 and user_id = $2`,
					p.RecordID, userID,
				).Scan(&blob, &ts)
			}
			if err != nil {
				return nil, err
			}
		default:
			return nil, errUnknownType
		}
		out = append(out, PushOutcome{
			RecordID: p.RecordID,
			Applied:  applied,
			Envelope: blob,
			Type:     p.Type,
			Ts:       ts,
		})
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteRecord tombstones one record: deleted_at = now, blob zeroed.
// LWW-gated: a delete whose ts is not newer than the live row's update
// is a no-op returning the winner.
func DeleteRecord(ctx context.Context, pool *pgxpool.Pool, userID, recordType, recordID string, ts time.Time) (bool, time.Time, error) {
	table, tsCol, err := tableFor(recordType)
	if err != nil {
		return false, time.Time{}, err
	}
	tag, err := pool.Exec(ctx, `
		update `+table+` set
			deleted_at = $3,
			encrypted_blob = '\x00'::bytea,
			updated_at = $3
		where id = $1 and user_id = $2
		  and deleted_at is null
		  and `+tsCol+` <= $3
	`, recordID, userID, ts)
	if err != nil {
		return false, time.Time{}, err
	}
	return tag.RowsAffected() > 0, ts, nil
}

// PullChanges returns everything for a user updated strictly after the
// cursor, keyset-ordered by (updated_at, id). Tombstoned rows surface
// as Tombstone changes (blob zeroed, never returned as envelopes).
func PullChanges(ctx context.Context, pool *pgxpool.Pool, userID string, since time.Time, limit int) ([]Change, time.Time, error) {
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	var changes []Change
	var maxTS time.Time

	rows, err := pool.Query(ctx, `
		select id, 'transactions' as type, encrypted_blob, updated_at, deleted_at
		  from encrypted_transactions where user_id = $1 and updated_at > $2
		union all
		select id, 'accounts', encrypted_blob, updated_at, deleted_at
		  from accounts where user_id = $1 and updated_at > $2
		union all
		select id, 'chat', encrypted_blob, created_at, null::timestamptz
		  from encrypted_chat_messages where user_id = $1 and created_at > $2
		order by 3 asc, 1 asc
		limit $3
	`, userID, since, limit)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer rows.Close()

	for rows.Next() {
		var id, typ string
		var blob []byte
		var updated time.Time
		var deleted *time.Time
		if err := rows.Scan(&id, &typ, &blob, &updated, &deleted); err != nil {
			return nil, time.Time{}, err
		}
		if deleted != nil {
			changes = append(changes, Change{Tombstone: &Tombstone{RecordID: id, Type: typ, DeletedAt: *deleted}})
		} else {
			changes = append(changes, Change{Envelope: &SyncEnvelope{
				RecordID: id, Type: typ, Blob: blob, Ts: updated,
			}})
		}
		if updated.After(maxTS) {
			maxTS = updated
		}
	}
	if err := rows.Err(); err != nil {
		return nil, time.Time{}, err
	}
	return changes, maxTS, nil
}

func tableFor(recordType string) (string, string, error) {
	switch recordType {
	case "transactions":
		return "encrypted_transactions", "updated_at", nil
	case "accounts":
		return "accounts", "updated_at", nil
	case "chat":
		return "encrypted_chat_messages", "created_at", nil
	default:
		return "", "", errUnknownType
	}
}
