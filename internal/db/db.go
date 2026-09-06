// Package db owns the pgx connection pool and the migration runner.
package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PoolConfig tunes the connection pool.
type PoolConfig struct {
	MaxConns        int32
	MaxConnLifetime time.Duration
	PingTimeout     time.Duration
}

// DefaultPoolConfig matches the plan: MaxConns=10, lifetime 30m, ping 5s.
func DefaultPoolConfig() PoolConfig {
	return PoolConfig{
		MaxConns:        10,
		MaxConnLifetime: 30 * time.Minute,
		PingTimeout:     5 * time.Second,
	}
}

// NewPool opens a pgx connection pool with the given configuration.
func NewPool(ctx context.Context, databaseURL string, pc PoolConfig) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("db: parse DATABASE_URL: %w", err)
	}
	cfg.MaxConns = pc.MaxConns
	cfg.MaxConnLifetime = pc.MaxConnLifetime

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("db: create pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, pc.PingTimeout)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: ping (is Postgres reachable?): %w", err)
	}
	return pool, nil
}

// Ping reports pool readiness; used by /readyz.
func Ping(ctx context.Context, pool *pgxpool.Pool) error {
	pingCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	return pool.Ping(pingCtx)
}
