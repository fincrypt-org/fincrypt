// Command server is the Fincrypt API server.
// Boot order: Load config -> connect pool -> migrate -> serve -> graceful drain.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fincrypt-org/fincrypt/internal/api"
	"github.com/fincrypt-org/fincrypt/internal/config"
	"github.com/fincrypt-org/fincrypt/internal/db"
)

func main() {
	migrateOnly := flag.Bool("migrate-only", false, "apply pending migrations and exit (make migrate)")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel(os.Getenv("LOG_LEVEL")),
	}))
	slog.SetDefault(logger)

	cfg, err := config.Load()
	if err != nil {
		logger.Error("config", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := db.NewPool(ctx, cfg.DatabaseURL, db.DefaultPoolConfig())
	if err != nil {
		logger.Error("database", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := db.Migrate(ctx, pool, migrationsDir()); err != nil {
		logger.Error("migrations", "error", err)
		os.Exit(1)
	}
	logger.Info("migrations applied", "dir", migrationsDir())

	if *migrateOnly {
		logger.Info("migrate-only: done")
		return
	}

	srv := api.NewServer(cfg, pool, logger)
	httpServer := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           srv,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", httpServer.Addr, "env", cfg.Env)
		errCh <- httpServer.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server", "error", err)
			os.Exit(1)
		}
	case <-ctx.Done():
		logger.Info("shutdown signal received; draining")
		drainCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(drainCtx); err != nil {
			logger.Error("graceful shutdown", "error", err)
		}
	}
}

// migrationsDir resolves the migrations directory both for `go run`
// (repo layout) and the container image (/app/db/migrations).
func migrationsDir() string {
	for _, dir := range []string{"db/migrations", "/app/db/migrations"} {
		if st, err := os.Stat(dir); err == nil && st.IsDir() {
			return dir
		}
	}
	return "db/migrations"
}

func logLevel(name string) slog.Level {
	switch name {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
