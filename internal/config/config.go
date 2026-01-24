package config

import (
	"fmt"
	"time"

	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
)

const namespace = "TREASURY"

// Config aggregates runtime configuration for the treasury service.
type Config struct {
	App       AppConfig
	HTTP      HTTPConfig
	GRPC      GRPCConfig
	Postgres  PostgresConfig
	Redis     RedisConfig
	Events    EventsConfig
	Storage   StorageConfig
	Secrets   SecretsConfig
	Telemetry TelemetryConfig
	Auth      AuthConfig
}

type AppConfig struct {
	Name    string `envconfig:"APP_NAME" default:"treasury-api"`
	Env     string `envconfig:"APP_ENV" default:"development"`
	Region  string `envconfig:"APP_REGION" default:"africa-east-1"`
	Version string `envconfig:"APP_VERSION" default:"0.1.0"`
}

type HTTPConfig struct {
	Host           string        `envconfig:"HTTP_HOST" default:"0.0.0.0"`
	Port           int           `envconfig:"HTTP_PORT" default:"4001"`
	ReadTimeout    time.Duration `envconfig:"HTTP_READ_TIMEOUT" default:"20s"`
	WriteTimeout   time.Duration `envconfig:"HTTP_WRITE_TIMEOUT" default:"20s"`
	IdleTimeout    time.Duration `envconfig:"HTTP_IDLE_TIMEOUT" default:"90s"`
	TLSCertFile    string        `envconfig:"TLS_CERT_FILE"`
	TLSKeyFile     string        `envconfig:"TLS_KEY_FILE"`
	AllowedOrigins []string      `envconfig:"HTTP_ALLOWED_ORIGINS" default:"https://books.codevertexitsolutions.com,https://ordersapp.codevertexitsolutions.com,https://pos.codevertexitsolutions.com,https://accounts.codevertexitsolutions.com"`
}

type GRPCConfig struct {
	Port             int    `envconfig:"GRPC_PORT" default:"9091"`
	Reflection       bool   `envconfig:"GRPC_REFLECTION" default:"true"`
	HealthEndpoint   bool   `envconfig:"GRPC_HEALTH_ENABLED" default:"true"`
	TLSCertFile      string `envconfig:"GRPC_TLS_CERT"`
	TLSKeyFile       string `envconfig:"GRPC_TLS_KEY"`
	ClientAuthCACert string `envconfig:"GRPC_CLIENT_CA_CERT"`
}

type PostgresConfig struct {
	URL             string        `envconfig:"POSTGRES_URL" default:"postgres://postgres:postgres@localhost:5432/treasury?sslmode=disable"`
	MaxOpenConns    int           `envconfig:"POSTGRES_MAX_OPEN_CONNS" default:"30"`
	MaxIdleConns    int           `envconfig:"POSTGRES_MAX_IDLE_CONNS" default:"15"`
	ConnMaxLifetime time.Duration `envconfig:"POSTGRES_CONN_MAX_LIFETIME" default:"45m"`
	RunMigrations   bool          `envconfig:"POSTGRES_RUN_MIGRATIONS" default:"false"`
}

type RedisConfig struct {
	Addr        string        `envconfig:"REDIS_ADDR" default:"localhost:6380"`
	Username    string        `envconfig:"REDIS_USERNAME"`
	Password    string        `envconfig:"REDIS_PASSWORD"`
	DB          int           `envconfig:"REDIS_DB" default:"0"`
	TLSRequired bool          `envconfig:"REDIS_TLS_REQUIRED" default:"false"`
	DialTimeout time.Duration `envconfig:"REDIS_DIAL_TIMEOUT" default:"5s"`
}

type EventsConfig struct {
	Bus           string `envconfig:"EVENT_BUS" default:"nats"`
	NATSURL       string `envconfig:"NATS_URL" default:"nats://localhost:4222"`
	StreamName    string `envconfig:"NATS_STREAM" default:"treasury"`
	DeliverGroup  string `envconfig:"NATS_DELIVER_GROUP" default:"treasury-workers"`
	DeadLetterJet string `envconfig:"NATS_DLQ_STREAM" default:"treasury-dlq"`
}

type StorageConfig struct {
	Provider  string `envconfig:"STORAGE_PROVIDER" default:"minio"`
	Endpoint  string `envconfig:"STORAGE_ENDPOINT" default:"http://localhost:9000"`
	AccessKey string `envconfig:"STORAGE_ACCESS_KEY"`
	SecretKey string `envconfig:"STORAGE_SECRET_KEY"`
	Bucket    string `envconfig:"STORAGE_BUCKET" default:"treasury-artifacts"`
	UseSSL    bool   `envconfig:"STORAGE_USE_SSL" default:"false"`
}

type SecretsConfig struct {
	Provider string `envconfig:"SECRETS_PROVIDER" default:"vault"`
	Address  string `envconfig:"SECRETS_ADDRESS" default:"http://localhost:8200"`
	Token    string `envconfig:"SECRETS_TOKEN"`
}

type TelemetryConfig struct {
	OTLPEndpoint string `envconfig:"OTLP_ENDPOINT"`
	MetricsURL   string `envconfig:"METRICS_ENDPOINT"`
	TracingURL   string `envconfig:"TRACING_ENDPOINT"`
}

type AuthConfig struct {
	// Auth Service SSO (JWT) integration
	ServiceURL          string        `envconfig:"AUTH_SERVICE_URL" default:"https://sso.codevertexitsolutions.com"`
	Issuer              string        `envconfig:"AUTH_ISSUER" default:"https://sso.codevertexitsolutions.com"`
	Audience            string        `envconfig:"AUTH_AUDIENCE" default:"bengobox"`
	JWKSUrl             string        `envconfig:"AUTH_JWKS_URL" default:"https://sso.codevertexitsolutions.com/api/v1/.well-known/jwks.json"`
	JWKSCacheTTL        time.Duration `envconfig:"AUTH_JWKS_CACHE_TTL" default:"3600s"`
	JWKSRefreshInterval time.Duration `envconfig:"AUTH_JWKS_REFRESH_INTERVAL" default:"300s"`
	EnableAPIKeyAuth    bool          `envconfig:"AUTH_ENABLE_API_KEY_AUTH" default:"true"`
	APIKey              string        `envconfig:"AUTH_API_KEY"` // For service-to-service user sync
}

// Load gathers configuration from environment variables and optional .env files.
func Load() (*Config, error) {
	_ = godotenv.Load()

	var cfg Config
	if err := envconfig.Process(namespace, &cfg); err != nil {
		return nil, fmt.Errorf("config: failed to load environment variables: %w", err)
	}

	return &cfg, nil
}
