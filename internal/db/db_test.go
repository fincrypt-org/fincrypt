package db

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// testPool returns a pool against DATABASE_URL (skips when unset —
// CI sets it to the postgres service container).
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set; DB tests require a live Postgres (docker compose up -d postgres)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := NewPool(ctx, url, DefaultPoolConfig())
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// freshDB wipes the ledger and all 001 tables so each test starts clean.
func freshDB(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	for _, stmt := range []string{
		`drop table if exists schema_migrations, users, accounts, vaults,
		   encrypted_transactions, encrypted_attachments, encrypted_chat_messages,
		   audit_log cascade`,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("freshDB: %v", err)
		}
	}
}

func TestMigrateApplies001(t *testing.T) {
	pool := testPool(t)
	freshDB(t, pool)
	ctx := context.Background()

	dir := filepath.Join("..", "..", "db", "migrations")
	if err := Migrate(ctx, pool, dir); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	var count int
	if err := pool.QueryRow(ctx, "select count(*) from schema_migrations").Scan(&count); err != nil {
		t.Fatalf("ledger query: %v", err)
	}
	if count != 1 {
		t.Fatalf("ledger rows = %d, want 1", count)
	}

	// All 8 v1 tables exist.
	for _, table := range []string{"users", "accounts", "vaults", "encrypted_transactions",
		"encrypted_attachments", "encrypted_chat_messages", "audit_log", "schema_migrations"} {
		var exists bool
		if err := pool.QueryRow(ctx,
			"select to_regclass($1) is not null", "public."+table).Scan(&exists); err != nil {
			t.Fatalf("table probe: %v", err)
		}
		if !exists {
			t.Errorf("table %s missing after migrate", table)
		}
	}
}

func TestMigrateRerunIsNoop(t *testing.T) {
	pool := testPool(t)
	freshDB(t, pool)
	ctx := context.Background()
	dir := filepath.Join("..", "..", "db", "migrations")

	if err := Migrate(ctx, pool, dir); err != nil {
		t.Fatalf("first Migrate: %v", err)
	}
	var appliedAt [1]time.Time
	if err := pool.QueryRow(ctx,
		"select applied_at from schema_migrations where version = '001_initial_schema.sql'").Scan(&appliedAt[0]); err != nil {
		t.Fatalf("read applied_at: %v", err)
	}

	if err := Migrate(ctx, pool, dir); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	var again time.Time
	if err := pool.QueryRow(ctx,
		"select applied_at from schema_migrations where version = '001_initial_schema.sql'").Scan(&again); err != nil {
		t.Fatalf("re-read applied_at: %v", err)
	}
	if !again.Equal(appliedAt[0]) {
		t.Errorf("re-run changed applied_at: %v -> %v (want no-op)", appliedAt[0], again)
	}
}

func TestMigrateDetectsPostApplyEdit(t *testing.T) {
	pool := testPool(t)
	freshDB(t, pool)
	ctx := context.Background()
	dir := t.TempDir()

	// Copy real migrations into a temp dir we may mutate.
	real, err := os.ReadDir(filepath.Join("..", "..", "db", "migrations"))
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	for _, e := range real {
		data, err := os.ReadFile(filepath.Join("..", "..", "db", "migrations", e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), data, 0o600); err != nil {
			t.Fatalf("copy %s: %v", e.Name(), err)
		}
	}

	if err := Migrate(ctx, pool, dir); err != nil {
		t.Fatalf("apply clean: %v", err)
	}

	// Mutate 001 post-apply — the runner must refuse to boot.
	mutated := filepath.Join(dir, "001_initial_schema.sql")
	orig, err := os.ReadFile(mutated)
	if err != nil {
		t.Fatalf("read 001: %v", err)
	}
	if err := os.WriteFile(mutated, append(orig, []byte("\n-- sneaky edit\n")...), 0o600); err != nil {
		t.Fatalf("mutate 001: %v", err)
	}

	err = Migrate(ctx, pool, dir)
	if err == nil {
		t.Fatal("mutated 001 applied silently — checksum guard failed")
	}
	if got := err.Error(); !containsAny(got, "modified after being applied", "append-only") {
		t.Errorf("error should mention tampering, got: %v", err)
	}
}

func TestMigrateConcurrentBoots(t *testing.T) {
	pool := testPool(t)
	freshDB(t, pool)
	ctx := context.Background()
	dir := filepath.Join("..", "..", "db", "migrations")

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = Migrate(ctx, pool, dir)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent Migrate[%d]: %v", i, err)
		}
	}
	var count int
	if err := pool.QueryRow(ctx, "select count(*) from schema_migrations").Scan(&count); err != nil {
		t.Fatalf("ledger query: %v", err)
	}
	if count != 1 {
		t.Fatalf("after concurrent boots ledger rows = %d, want exactly 1", count)
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) > 0 && stringContains(s, sub) {
			return true
		}
	}
	return false
}

func stringContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
