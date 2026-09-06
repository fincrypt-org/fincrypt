// Package config loads all server configuration from the environment.
// Fail-fast: the server refuses to boot on missing or malformed config
// rather than nil-panicking mid-request in production.
package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// SessionKeys holds the base64-decoded cookie-signing secrets.
// Keys[0] signs the JWT stored in the httpOnly session cookie;
// Keys[1], when present, is the pending rotation key (verify old,
// sign new during key rollover).
type SessionKeys [][]byte

// Config is the full server configuration. Platform vars only —
// AI endpoint / Plaid credentials are added by their own phases.
type Config struct {
	// Env is "dev" or "prod"; gates CSP strictness and log verbosity.
	Env string
	// Port is the HTTP listen port.
	Port string
	// LogLevel is a slog level name ("debug", "info", "warn", "error").
	LogLevel string
	// DatabaseURL is the Postgres connection string.
	DatabaseURL string
	// DevOrigin is the allowed CORS origin for the Vite dev server.
	// Empty disables CORS entirely (prod serves same-origin).
	DevOrigin string
	// SessionKeys holds 1–2 decoded 32-byte cookie-signing secrets.
	SessionKeys SessionKeys
}

// getenv returns the value of key, or "" when unset/blank.
func getenv(key string) string {
	return strings.TrimSpace(os.Getenv(key))
}

// Load reads the environment and validates every field.
// Errors carry a one-line fix hint.
func Load() (Config, error) {
	cfg := Config{
		Env:         getenv("ENV"),
		Port:        getenv("PORT"),
		LogLevel:    getenv("LOG_LEVEL"),
		DatabaseURL: getenv("DATABASE_URL"),
		DevOrigin:   getenv("DEV_ORIGIN"),
	}

	if cfg.Env == "" {
		cfg.Env = "dev"
	}
	if cfg.Env != "dev" && cfg.Env != "prod" {
		return Config{}, fmt.Errorf("config: ENV must be \"dev\" or \"prod\" (got %q); set ENV=dev or ENV=prod", cfg.Env)
	}

	if cfg.Port == "" {
		cfg.Port = "8080"
	}

	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}

	if cfg.DatabaseURL == "" {
		return Config{}, fmt.Errorf("config: DATABASE_URL is required (e.g. DATABASE_URL=postgres://fincrypt:fincrypt@localhost:5432/fincrypt?sslmode=disable)")
	}

	rawKeys := getenv("SESSION_KEYS")
	if rawKeys == "" {
		return Config{}, fmt.Errorf("config: SESSION_KEYS is required (comma-separated base64 of 32-byte random keys); generate with: openssl rand -base64 32")
	}

	keys, err := parseSessionKeys(rawKeys)
	if err != nil {
		return Config{}, err
	}
	cfg.SessionKeys = keys

	if origin := cfg.DevOrigin; origin != "" {
		if cfg.Env == "prod" {
			return Config{}, fmt.Errorf("config: DEV_ORIGIN is not allowed when ENV=prod (prod is same-origin); unset DEV_ORIGIN")
		}
		if !strings.HasPrefix(origin, "http://") && !strings.HasPrefix(origin, "https://") {
			return Config{}, fmt.Errorf("config: DEV_ORIGIN must be an absolute origin like http://localhost:5173 (got %q)", origin)
		}
	}

	return cfg, nil
}

// parseSessionKeys decodes 1–2 comma-separated base64 keys and enforces
// the 32-byte minimum.
func parseSessionKeys(raw string) (SessionKeys, error) {
	parts := strings.Split(raw, ",")
	if len(parts) > 2 {
		return nil, fmt.Errorf("config: SESSION_KEYS accepts at most 2 keys (current + rotation); got %d", len(parts))
	}
	keys := make(SessionKeys, 0, len(parts))
	for i, part := range parts {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(part))
		if err != nil {
			return nil, fmt.Errorf("config: SESSION_KEYS[%d] is not valid base64: %v (generate with: openssl rand -base64 32)", i, err)
		}
		if len(decoded) < 32 {
			return nil, fmt.Errorf("config: SESSION_KEYS[%d] must decode to at least 32 bytes (got %d); generate with: openssl rand -base64 32", i, len(decoded))
		}
		keys = append(keys, decoded)
	}
	return keys, nil
}
