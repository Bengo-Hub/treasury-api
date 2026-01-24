package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/bengobox/treasury-api/internal/config"
	handlers "github.com/bengobox/treasury-api/internal/http/handlers"
	router "github.com/bengobox/treasury-api/internal/http/router"
	"github.com/bengobox/treasury-api/internal/platform/cache"
	"github.com/bengobox/treasury-api/internal/platform/database"
	"github.com/bengobox/treasury-api/internal/platform/events"
	"github.com/bengobox/treasury-api/internal/platform/secrets"
	"github.com/bengobox/treasury-api/internal/platform/storage"
	"github.com/bengobox/treasury-api/internal/shared/logger"
	authclient "github.com/Bengo-Hub/shared-auth-client"
)

type App struct {
	cfg        *config.Config
	log        *zap.Logger
	httpServer *http.Server
	db         *pgxpool.Pool
	cache      *redis.Client
	events     *nats.Conn
	secrets    secrets.Provider
}

func New(ctx context.Context) (*App, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}

	log, err := logger.New(cfg.App.Env)
	if err != nil {
		return nil, fmt.Errorf("logger init: %w", err)
	}

	dbPool, err := database.NewPool(ctx, cfg.Postgres)
	if err != nil {
		return nil, fmt.Errorf("postgres init: %w", err)
	}

	redisClient := cache.NewClient(cfg.Redis)

	natsConn, err := events.Connect(cfg.Events)
	if err != nil {
		log.Warn("event bus connection failed", zap.Error(err))
	}

	if natsConn != nil {
		if err := events.EnsureStream(ctx, natsConn, cfg.Events); err != nil {
			log.Warn("ensure stream", zap.Error(err))
		}
	}

	storageHealth := storage.NewHealthChecker(cfg.Storage)
	secretsProvider := secrets.NewNoop()

	// Initialize auth-service JWT validator
	var authMiddleware *authclient.AuthMiddleware
	if cfg.Auth.JWKSUrl != "" {
		authConfig := authclient.DefaultConfig(
			cfg.Auth.JWKSUrl,
			cfg.Auth.Issuer,
			cfg.Auth.Audience,
		)
		authConfig.CacheTTL = cfg.Auth.JWKSCacheTTL
		authConfig.RefreshInterval = cfg.Auth.JWKSRefreshInterval
		validator, err := authclient.NewValidator(authConfig)
		if err != nil {
			return nil, fmt.Errorf("auth validator init: %w", err)
		}
		authMiddleware = authclient.NewAuthMiddleware(validator)
	}

	healthHandler := handlers.NewHealth(log, dbPool, redisClient, natsConn, storageHealth)
	ledgerHandler := handlers.NewLedger(log)
	paymentsHandler := handlers.NewPayments()

	httpRouter := router.New(log, healthHandler, ledgerHandler, paymentsHandler, authMiddleware, cfg.HTTP.AllowedOrigins)

	httpServer := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", cfg.HTTP.Host, cfg.HTTP.Port),
		Handler:           httpRouter,
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
		IdleTimeout:       cfg.HTTP.IdleTimeout,
	}

	return &App{
		cfg:        cfg,
		log:        log,
		httpServer: httpServer,
		db:         dbPool,
		cache:      redisClient,
		events:     natsConn,
		secrets:    secretsProvider,
	}, nil
}

func (a *App) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	if a.cfg.HTTP.TLSCertFile != "" && a.cfg.HTTP.TLSKeyFile != "" {
		a.log.Info("treasury http server starting with HTTPS",
			zap.String("addr", a.httpServer.Addr),
			zap.String("cert", a.cfg.HTTP.TLSCertFile),
			zap.String("key", a.cfg.HTTP.TLSKeyFile),
		)
		go func() {
			errCh <- a.httpServer.ListenAndServeTLS(a.cfg.HTTP.TLSCertFile, a.cfg.HTTP.TLSKeyFile)
		}()
	} else {
		a.log.Info("treasury http server starting with HTTP", zap.String("addr", a.httpServer.Addr))
		go func() {
			errCh <- a.httpServer.ListenAndServe()
		}()
	}

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		if err := a.httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("http shutdown: %w", err)
		}

		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("http server error: %w", err)
	}
}

func (a *App) Close() {
	if a.events != nil {
		if err := a.events.Drain(); err != nil {
			a.log.Warn("nats drain failed", zap.Error(err))
		}
		a.events.Close()
	}

	if a.cache != nil {
		if err := a.cache.Close(); err != nil {
			a.log.Warn("redis close failed", zap.Error(err))
		}
	}

	if a.db != nil {
		a.db.Close()
	}

	_ = a.log.Sync()
}
