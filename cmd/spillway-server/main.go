package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bcnelson/ts-spillway/internal/certmanager"
	"github.com/bcnelson/ts-spillway/internal/config"
	"github.com/bcnelson/ts-spillway/internal/registry"
	"github.com/bcnelson/ts-spillway/internal/server"

	"github.com/redis/go-redis/v9"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg, err := config.LoadServerConfig()
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	// Connect to Redis
	rdb := redis.NewClient(&redis.Options{
		Addr: cfg.RedisAddr,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		logger.Error("failed to connect to Redis", "addr", cfg.RedisAddr, "error", err)
		os.Exit(1)
	}
	logger.Info("connected to Redis", "addr", cfg.RedisAddr)

	// Create store
	store := registry.NewRedisStore(rdb, time.Duration(cfg.HeartbeatTTL)*time.Second)

	// Create cert manager
	certStore := certmanager.NewRedisCertStore(rdb)
	var certIssuer certmanager.CertIssuer

	if cfg.ACMEEmail != "" {
		issuer, err := certmanager.NewACMEIssuer(cfg.ACMEEmail, cfg.ACMEDirectory)
		if err != nil {
			logger.Error("failed to create ACME issuer", "error", err)
			os.Exit(1)
		}
		certIssuer = issuer
		logger.Info("ACME cert issuer configured", "email", cfg.ACMEEmail)
	} else {
		logger.Warn("ACME email not configured, cert issuance disabled")
		certIssuer = &noopIssuer{}
	}

	certMgr := certmanager.NewManager(certStore, certIssuer, logger)

	// Create and start server
	srv := server.New(cfg, store, certMgr, logger)

	if err := srv.Start(ctx); err != nil {
		logger.Error("server startup failed", "error", err)
		os.Exit(1)
	}
	defer srv.Close()

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigCh
	logger.Info("received signal, shutting down", "signal", sig)
	cancel()
}

// noopIssuer is used when ACME is not configured.
type noopIssuer struct{}

func (n *noopIssuer) Issue(_ context.Context, domain string) ([]byte, []byte, time.Time, error) {
	slog.Warn("cert issuance skipped: ACME not configured", "domain", domain)
	return nil, nil, time.Time{}, nil
}
