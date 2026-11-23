// Command server runs the One-Time Secret Service.
package main

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"secret-sharing/internal/config"
	"secret-sharing/internal/ratelimit"
	"secret-sharing/internal/seal"
	"secret-sharing/internal/server"
	"secret-sharing/internal/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("fatal", slog.String("event", "fatal"), slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	rdb := redis.NewClient(&redis.Options{
		Addr:         cfg.RedisAddr,
		PoolSize:     64,
		MinIdleConns: 8,
		DialTimeout:  2 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
		// No client retries: a retried Lua call after a lost reply could spend a View twice.
		MaxRetries: -1,
	})
	defer func() { _ = rdb.Close() }()

	createLim := ratelimit.New(cfg.CreatePerSec, cfg.CreateBurst)
	readLim := ratelimit.New(cfg.ReadPerSec, cfg.ReadBurst)
	unlockLim := ratelimit.New(cfg.UnlockPerSec, cfg.UnlockBurst)
	bytesLim := ratelimit.New(cfg.CreateBytesPerSec, cfg.CreateBytesBurst)
	auxLim := ratelimit.New(cfg.ReadPerSec, cfg.ReadBurst)
	for _, l := range []*ratelimit.Limiter{createLim, readLim, unlockLim, bytesLim, auxLim} {
		go l.RunSweeper(ctx)
	}

	srv, err := server.New(store.Open(rdb), logger, server.Options{
		PublicBaseURL:      cfg.PublicBaseURL,
		KDF:                seal.Params{ArgonTime: cfg.ArgonTime, ArgonMemoryKiB: cfg.ArgonMemoryKiB},
		CreateLimiter:      createLim,
		ReadLimiter:        readLim,
		UnlockLimiter:      unlockLim,
		CreateBytesLimiter: bytesLim,
		AuxLimiter:         auxLim,
	})
	if err != nil {
		return err
	}

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          log.New(fixedLine{logger}, "", 0),
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", slog.String("event", "server.start"), slog.String("addr", cfg.ListenAddr))
		errCh <- httpSrv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	logger.Info("shutting down", slog.String("event", "server.stop"))
	return httpSrv.Shutdown(shutdownCtx)
}

// fixedLine swallows net/http's internal error text (which can include
// request-derived values) and records only that an error occurred.
type fixedLine struct{ log *slog.Logger }

func (f fixedLine) Write(p []byte) (int, error) {
	f.log.Warn("http server error", slog.String("event", "http.server_error"))
	return len(p), nil
}
