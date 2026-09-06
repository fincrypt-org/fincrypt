package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Migrate applies every pending *.sql in dir, forward-only, under a
// Postgres advisory lock so concurrent boots cannot race.
//
// Invariant: applied files are checksum-verified on every run. Editing a
// migration after it has been applied makes the app refuse to boot —
// migrations are append-only; later changes are new files.
func Migrate(ctx context.Context, pool *pgxpool.Pool, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("db: read migrations dir %s: %w", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // lexicographic == intended numeric order (001_, 002_, ...)

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("db: acquire connection: %w", err)
	}
	defer conn.Release()

	// Serialize concurrent migrations across replicas.
	if _, err := conn.Exec(ctx, "select pg_advisory_lock(724561)"); err != nil {
		return fmt.Errorf("db: advisory lock: %w", err)
	}
	defer func() {
		_, _ = conn.Exec(context.WithoutCancel(ctx), "select pg_advisory_unlock(724561)")
	}()

	if err := ensureLedger(ctx, conn); err != nil {
		return err
	}

	for _, name := range names {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("db: read %s: %w", name, err)
		}
		checksum := checksumOf(data)

		applied, err := appliedChecksum(ctx, conn, name)
		if err != nil {
			return err
		}
		if applied != nil {
			if *applied != checksum {
				return fmt.Errorf(
					"db: migration %s was modified after being applied (ledger checksum %s != file %s) — migrations are append-only; add a new 00N_ file instead of editing history",
					name, short(applied), short(&checksum))
			}
			continue // already applied, unchanged — no-op
		}

		// New migration: run in its own transaction.
		tx, err := conn.Begin(ctx)
		if err != nil {
			return fmt.Errorf("db: begin %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, string(data)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("db: apply %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx,
			"insert into schema_migrations (version, checksum) values ($1, $2)", name, checksum); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("db: record %s: %w", name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("db: commit %s: %w", name, err)
		}
	}
	return nil
}

const ledgerSchema = `
create table if not exists schema_migrations (
  version text primary key,
  checksum text not null,
  applied_at timestamptz not null default now()
);`

func ensureLedger(ctx context.Context, conn *pgxpool.Conn) error {
	if _, err := conn.Exec(ctx, ledgerSchema); err != nil {
		return fmt.Errorf("db: create schema_migrations: %w", err)
	}
	return nil
}

// appliedChecksum returns the recorded checksum for version, or nil when
// the migration has not been applied.
func appliedChecksum(ctx context.Context, conn *pgxpool.Conn, version string) (*string, error) {
	var checksum string
	err := conn.QueryRow(ctx,
		"select checksum from schema_migrations where version = $1", version).Scan(&checksum)
	switch {
	case err == pgx.ErrNoRows:
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("db: read ledger for %s: %w", version, err)
	}
	return &checksum, nil
}

func checksumOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func short(s *string) string {
	if s == nil {
		return "none"
	}
	if len(*s) <= 8 {
		return *s
	}
	return (*s)[:8]
}

// MigrationsFS embeds migrations for containerized runs; unused by the
// dev path (which reads dir from disk) but kept so callers can choose.
var _ fs.FS = nil
