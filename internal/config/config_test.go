package config

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeEnv writes a temp .env-like environment via t.Setenv.
func genKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestLoadHappyPath(t *testing.T) {
	t.Setenv("ENV", "dev")
	t.Setenv("PORT", "9000")
	t.Setenv("LOG_LEVEL", "debug")
	t.Setenv("DATABASE_URL", "postgres://u:p@localhost:5432/db?sslmode=disable")
	t.Setenv("SESSION_KEYS", genKey(t))
	t.Setenv("DEV_ORIGIN", "http://localhost:5173")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Env != "dev" || cfg.Port != "9000" || cfg.LogLevel != "debug" {
		t.Errorf("unexpected basic fields: %+v", cfg)
	}
	if cfg.DatabaseURL == "" || cfg.DevOrigin != "http://localhost:5173" {
		t.Errorf("unexpected db/origin: %+v", cfg)
	}
	if len(cfg.SessionKeys) != 1 || len(cfg.SessionKeys[0]) != 32 {
		t.Errorf("expected one 32-byte key, got %+v", cfg.SessionKeys)
	}
}

func TestLoadDefaults(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://u:p@localhost:5432/db")
	t.Setenv("SESSION_KEYS", genKey(t))

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Env != "dev" {
		t.Errorf("default Env = %q, want dev", cfg.Env)
	}
	if cfg.Port != "8080" {
		t.Errorf("default Port = %q, want 8080", cfg.Port)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("default LogLevel = %q, want info", cfg.LogLevel)
	}
}

func TestLoadMissingDatabaseURL(t *testing.T) {
	t.Setenv("SESSION_KEYS", genKey(t))

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "DATABASE_URL") {
		t.Fatalf("want DATABASE_URL error, got %v", err)
	}
}

func TestLoadMissingSessionKeys(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://u:p@localhost:5432/db")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "SESSION_KEYS") {
		t.Fatalf("want SESSION_KEYS error, got %v", err)
	}
}

func TestLoadShortSessionKey(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://u:p@localhost:5432/db")
	t.Setenv("SESSION_KEYS", base64.StdEncoding.EncodeToString(make([]byte, 16)))

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "32 bytes") {
		t.Fatalf("want 32-byte error, got %v", err)
	}
}

func TestLoadTwoSessionKeys(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://u:p@localhost:5432/db")
	t.Setenv("SESSION_KEYS", genKey(t)+","+genKey(t))

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.SessionKeys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(cfg.SessionKeys))
	}
}

func TestLoadTooManySessionKeys(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://u:p@localhost:5432/db")
	t.Setenv("SESSION_KEYS", genKey(t)+","+genKey(t)+","+genKey(t))

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "at most 2") {
		t.Fatalf("want max-2 error, got %v", err)
	}
}

func TestLoadInvalidBase64(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://u:p@localhost:5432/db")
	t.Setenv("SESSION_KEYS", "!!!not-base64!!!")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "base64") {
		t.Fatalf("want base64 error, got %v", err)
	}
}

func TestLoadDevOriginDisallowedInProd(t *testing.T) {
	t.Setenv("ENV", "prod")
	t.Setenv("DATABASE_URL", "postgres://u:p@localhost:5432/db")
	t.Setenv("SESSION_KEYS", genKey(t))
	t.Setenv("DEV_ORIGIN", "http://localhost:5173")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "DEV_ORIGIN") {
		t.Fatalf("want DEV_ORIGIN-in-prod error, got %v", err)
	}
}

func TestLoadInvalidEnv(t *testing.T) {
	t.Setenv("ENV", "staging")
	t.Setenv("DATABASE_URL", "postgres://u:p@localhost:5432/db")
	t.Setenv("SESSION_KEYS", genKey(t))

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "ENV") {
		t.Fatalf("want ENV error, got %v", err)
	}
}

// TestEnvExampleParses guards .env.example against drifting out of sync
// with the loader (every var the example sets must be accepted by Load).
func TestEnvExampleParses(t *testing.T) {
	repo := findRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repo, ".env.example"))
	if err != nil {
		t.Fatalf("read .env.example: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf(".env.example line not KEY=VALUE: %q", line)
		}
		switch key {
		case "SESSION_KEYS", "DATABASE_URL":
			// placeholders are intentionally short — only check the key shape
			t.Setenv(key, genKey(t))
		default:
			t.Setenv(key, value)
		}
	}
	if _, err := Load(); err != nil {
		t.Fatalf(".env.example does not satisfy Load: %v", err)
	}
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, ".env.example")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repo root with .env.example not found")
		}
		dir = parent
	}
}
