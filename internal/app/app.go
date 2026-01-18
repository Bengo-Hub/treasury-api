package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"

	"entgo.io/ent/dialect"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	authclient "github.com/Bengo-Hub/shared-auth-client"
	eventslib "github.com/Bengo-Hub/shared-events"
	"github.com/bengobox/treasury-app/internal/config"
	"github.com/bengobox/treasury-app/internal/ent"
	handlers "github.com/bengobox/treasury-app/internal/http/handlers"
	router "github.com/bengobox/treasury-app/internal/http/router"
	"github.com/bengobox/treasury-app/internal/modules/outbox"
	"github.com/bengobox/treasury-app/internal/modules/rbac"
	"github.com/bengobox/treasury-app/internal/platform/cache"
	"github.com/bengobox/treasury-app/internal/platform/database"
	"github.com/bengobox/treasury-app/internal/platform/secrets"
	"github.com/bengobox/treasury-app/internal/platform/storage"
	"github.com/bengobox/treasury-app/internal/services/events"
	"github.com/bengobox/treasury-app/internal/services/usersync"
	"github.com/bengobox/treasury-app/internal/shared/logger"
	_ "github.com/jackc/pgx/v5/stdlib"

	entsql "entgo.io/ent/dialect/sql"
)

type App struct {
	cfg             *config.Config
	log             *zap.Logger
	httpServer      *http.Server
	db              *pgxpool.Pool
	cache           *redis.Client
	events          *nats.Conn
	secrets         secrets.Provider
	outboxPublisher *eventslib.Publisher
	entClient       *ent.Client
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

	natsConn, err := platformevents.Connect(cfg.Events)
	if err != nil {
		log.Warn("event bus connection failed", zap.Error(err))
	}

	var js nats.JetStreamContext
	if natsConn != nil {
		if err := platformevents.EnsureStream(ctx, natsConn, cfg.Events); err != nil {
			log.Warn("ensure stream", zap.Error(err))
		}
		var err error
		js, err = natsConn.JetStream()
		if err != nil {
			log.Warn("failed to get jetstream context, outbox publisher disabled", zap.Error(err))
		}
	}

	storageHealth := storage.NewHealthChecker(cfg.Storage)
	secretsProvider := secrets.NewNoop()

	// Initialize Ent client
	var entClient *ent.Client
	if cfg.Postgres.URL != "" {
		sqlDB, err := sql.Open("pgx", cfg.Postgres.URL)
		if err != nil {
			log.Warn("failed to open Ent database connection", zap.Error(err))
		} else {
			sqlDB.SetMaxIdleConns(10)
			sqlDB.SetMaxOpenConns(25)
			sqlDB.SetConnMaxIdleTime(5 * time.Minute)
			drv := entsql.OpenDB(dialect.Postgres, sqlDB)
			entClient = ent.NewClient(ent.Driver(drv))

			// Run migrations if configured
			if cfg.Postgres.RunMigrations {
				if err := entClient.Schema.Create(ctx); err != nil {
					return nil, fmt.Errorf("ent schema create: %w", err)
				}
				log.Info("ent migrations completed")
			}
			log.Info("ent client initialized")
		}
	}

	// Initialize outbox publisher
	var outboxPublisher *eventslib.Publisher
	if js != nil && entClient != nil {
		sqlDB, err := sql.Open("pgx", cfg.Postgres.URL)
		if err == nil {
			outboxRepo := outbox.NewRepository(sqlDB)
			pubCfg := eventslib.DefaultPublisherConfig(js, outboxRepo, log)
			outboxPublisher = eventslib.NewPublisher(pubCfg)
			log.Info("outbox publisher initialized")
		} else {
			log.Warn("failed to create sql.DB for outbox, publisher disabled", zap.Error(err))
		}
	}

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

		// Initialize API key validator if enabled
		if cfg.Auth.EnableAPIKeyAuth {
			apiKeyValidator := authclient.NewAPIKeyValidator(cfg.Auth.ServiceURL, nil)
			authMiddleware = authclient.NewAuthMiddlewareWithAPIKey(validator, apiKeyValidator)
		} else {
			authMiddleware = authclient.NewAuthMiddleware(validator)
		}
	}

	// Initialize RBAC module
	var rbacRepo rbac.Repository
	var rbacService *rbac.Service
	var userHandler *handlers.UserHandler
	var rbacHandler *handlers.RBACHandler
	if entClient != nil {
		rbacRepo = rbac.NewEntRepository(entClient)
		rbacService = rbac.NewService(rbacRepo, log)

		// Initialize user sync service
		syncService := usersync.NewService(cfg.Auth.ServiceURL, cfg.Auth.APIKey, log)
		userHandler = handlers.NewUserHandler(log, rbacService, syncService, rbacRepo)
		rbacHandler = handlers.NewRBACHandler(log, rbacService, syncService, rbacRepo)
	}

	healthHandler := handlers.NewHealth(log, dbPool, redisClient, natsConn, storageHealth)
	ledgerHandler := handlers.NewLedger(log)
	paymentsHandler := handlers.NewPayments()

	httpRouter := router.New(log, healthHandler, ledgerHandler, paymentsHandler, authMiddleware, userHandler, rbacHandler)

	httpServer := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", cfg.HTTP.Host, cfg.HTTP.Port),
		Handler:           httpRouter,
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
		IdleTimeout:       cfg.HTTP.IdleTimeout,
	}

	return &App{
		cfg:             cfg,
		log:             log,
		httpServer:      httpServer,
		db:              dbPool,
		cache:           redisClient,
		events:          natsConn,
		secrets:         secretsProvider,
		outboxPublisher: outboxPublisher,
		entClient:       entClient,
	}, nil
}

func (a *App) Run(ctx context.Context) error {
	// Start outbox publisher worker
	if a.outboxPublisher != nil {
		go func() {
			if err := a.outboxPublisher.Start(ctx); err != nil {
				a.log.Error("outbox publisher failed", zap.Error(err))
			}
		}()
		a.log.Info("outbox publisher started")
	}

	// Start event consumers for auth-service events
	if a.events != nil && a.entClient != nil {
		js, err := a.events.JetStream()
		if err == nil {
			// Initialize RBAC service for event consumer
			rbacRepo := rbac.NewEntRepository(a.entClient)
			rbacService := rbac.NewService(rbacRepo, a.log)
			userEventConsumer := events.NewUserEventConsumer(rbacService, a.log)

			go func() {
				if err := userEventConsumer.ConsumeUserEvents(ctx, js); err != nil {
					a.log.Error("user event consumer failed", zap.Error(err))
				}
			}()
			a.log.Info("user event consumer started")
		}
	}

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
	// Outbox publisher will stop when context is cancelled (no explicit Stop method)

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

	if a.entClient != nil {
		a.entClient.Close()
	}

	if a.db != nil {
		a.db.Close()
	}

	_ = a.log.Sync()
}
