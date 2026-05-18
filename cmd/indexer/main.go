// Package main provides the search indexer service entry point.
// The indexer maintains RediSearch indexes by processing search tasks from Asynq
// and periodically rebuilding from PostgreSQL.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hibiken/asynq"
	"github.com/redis/go-redis/v9"

	"github.com/manchtools/power-manage/server/internal/config"
	"github.com/manchtools/power-manage/server/internal/search"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/postgres"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

// version is set at build time via -ldflags.
var version = "dev"

type Config struct {
	DatabaseURL       string
	ValkeyAddr        string
	ValkeyPassword    string
	ValkeyDB          int
	LogLevel          string
	LogFormat         string
	ReconcileInterval time.Duration
	Concurrency       int
	HealthAddr        string
}

func main() {
	cfg := parseFlags()

	logger := setupLogger(cfg.LogLevel, cfg.LogFormat)
	slog.SetDefault(logger)
	logger.Info("starting search indexer", "version", version, "valkey_addr", cfg.ValkeyAddr, "reconcile_interval", cfg.ReconcileInterval)

	// Setup signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", "signal", sig)
		cancel()
	}()

	// Initialize store with PostgreSQL (needed for warm/rebuild).
	// Use NewWithoutMigrations — only the control server manages the schema.
	st, err := store.NewWithoutMigrations(ctx, cfg.DatabaseURL)
	if err != nil {
		logger.Error("failed to initialize store", "error", err)
		os.Exit(1)
	}
	defer st.Close()
	st.SetLogger(logger)
	st.SetRepos(postgres.NewRepos(st.Queries()))
	logger.Info("database initialized")

	// Initialize go-redis client for RediSearch.
	// Force RESP2 protocol: go-redis v9 auto-negotiates RESP3 with Redis 7+,
	// but RediSearch returns FT.SEARCH results in a different format under
	// RESP3 (map vs array), which breaks result parsers.
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.ValkeyAddr,
		Password: cfg.ValkeyPassword,
		DB:       cfg.ValkeyDB,
		Protocol: 2,
	})
	defer rdb.Close()

	// Test Redis connectivity
	if err := rdb.Ping(ctx).Err(); err != nil {
		logger.Error("failed to connect to Redis", "error", err)
		os.Exit(1)
	}

	// Initialize search index (nil aqClient — indexer doesn't enqueue tasks)
	searchIdx := search.New(rdb, st, nil, logger.With("component", "search"))

	// Ensure indexes exist
	if err := searchIdx.EnsureIndexes(ctx); err != nil {
		logger.Error("failed to ensure search indexes", "error", err)
		os.Exit(1)
	}
	logger.Info("search indexes ensured")

	// Full rebuild from PG on startup (flushes stale data, then rewarms)
	logger.Info("starting initial search index rebuild")
	if err := searchIdx.Rebuild(ctx); err != nil {
		logger.Error("initial search index rebuild failed", "error", err)
		os.Exit(1)
	}
	logger.Info("initial search index rebuild complete")

	// Start periodic reconciliation
	if cfg.ReconcileInterval > 0 {
		searchIdx.StartReconciliation(ctx, cfg.ReconcileInterval)
		logger.Info("periodic reconciliation started", "interval", cfg.ReconcileInterval)
	}

	// Load the Asynq-payload HMAC verifier (audit F-02). Indexer is
	// a consumer of search:* tasks produced by control; the key MUST
	// match control's PM_TASK_SIGNING_KEY or every task in the queue
	// will land in the dead queue.
	taskSigner, err := taskqueue.NewSigner(os.Getenv("PM_TASK_SIGNING_KEY"))
	if err != nil {
		logger.Error("failed to load task signer", "error", err)
		os.Exit(1)
	}
	if taskSigner == nil {
		logger.Error("PM_TASK_SIGNING_KEY is required (audit F-02 — Asynq task verification is mandatory)")
		os.Exit(1)
	}

	// Initialize and start Asynq worker for search task processing
	searchWorker := search.NewWorker(rdb, taskSigner, logger.With("component", "search_worker"))
	mux := asynq.NewServeMux()
	searchWorker.RegisterHandlers(mux)

	aqLogger := logger.With("component", "asynq_server")
	aqServer := asynq.NewServer(
		asynq.RedisClientOpt{
			Addr:     cfg.ValkeyAddr,
			Password: cfg.ValkeyPassword,
			DB:       cfg.ValkeyDB,
		},
		asynq.Config{
			Concurrency: cfg.Concurrency,
			Queues: map[string]int{
				taskqueue.SearchQueue: 1,
			},
			Logger: newAsynqLogger(aqLogger),
			ErrorHandler: asynq.ErrorHandlerFunc(func(ctx context.Context, task *asynq.Task, err error) {
				retried, _ := asynq.GetRetryCount(ctx)
				maxRetry, _ := asynq.GetMaxRetry(ctx)
				aqLogger.Error("task handler failed",
					"task_type", task.Type(),
					"error", err,
					"retry", retried,
					"max_retry", maxRetry,
				)
			}),
		},
	)
	if err := aqServer.Start(mux); err != nil {
		logger.Error("failed to start Asynq server", "error", err)
		os.Exit(1)
	}
	defer aqServer.Shutdown()
	logger.Info("search task worker started", "concurrency", cfg.Concurrency)

	// Start health check HTTP server
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"ok","version":%q}`, version)
	})
	healthServer := &http.Server{
		Addr:    cfg.HealthAddr,
		Handler: healthMux,
	}
	go func() {
		logger.Info("health endpoint listening", "addr", cfg.HealthAddr)
		if err := healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("health server error", "error", err)
		}
	}()

	// Wait for shutdown
	<-ctx.Done()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := healthServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("failed to shutdown health server", "error", err)
	}

	logger.Info("search indexer stopped")
}

func parseFlags() *Config {
	cfg := &Config{}

	flag.StringVar(&cfg.DatabaseURL, "database-url", "", "PostgreSQL connection URL")
	flag.StringVar(&cfg.ValkeyAddr, "valkey-addr", "", "Redis/Valkey address")
	flag.StringVar(&cfg.ValkeyPassword, "valkey-password", "", "Redis/Valkey password")
	flag.IntVar(&cfg.ValkeyDB, "valkey-db", 0, "Redis/Valkey database number")
	flag.StringVar(&cfg.LogLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	flag.StringVar(&cfg.LogFormat, "log-format", "text", "Log format (text, json)")
	flag.DurationVar(&cfg.ReconcileInterval, "reconcile-interval", time.Hour, "Interval for periodic full rebuild (0 to disable)")
	flag.IntVar(&cfg.Concurrency, "concurrency", 5, "Number of concurrent Asynq workers")
	// :8090 was previously :8082, which collided with the control
	// server's InternalListenAddr default on single-host dev setups
	// (#138). Operators on multi-host deploys can still pin either
	// via CONTROL_INTERNAL_LISTEN_ADDR + INDEXER_HEALTH_ADDR.
	flag.StringVar(&cfg.HealthAddr, "health-addr", ":8090", "Health check endpoint address")

	flag.Parse()

	// Environment variable overrides via the shared config helpers
	// (audit F017 + N029 — moved out of inline open-code).
	config.EnvString(&cfg.DatabaseURL, "INDEXER_DATABASE_URL")
	config.EnvString(&cfg.ValkeyAddr, "INDEXER_VALKEY_ADDR")
	config.EnvString(&cfg.ValkeyPassword, "INDEXER_VALKEY_PASSWORD")
	config.EnvInt(&cfg.ValkeyDB, "INDEXER_VALKEY_DB")
	config.EnvString(&cfg.LogLevel, "INDEXER_LOG_LEVEL")
	config.EnvString(&cfg.LogFormat, "INDEXER_LOG_FORMAT")
	config.EnvDuration(&cfg.ReconcileInterval, "INDEXER_RECONCILE_INTERVAL")
	config.EnvInt(&cfg.Concurrency, "INDEXER_CONCURRENCY")
	config.EnvString(&cfg.HealthAddr, "INDEXER_HEALTH_ADDR")

	if cfg.DatabaseURL == "" {
		fmt.Fprintln(os.Stderr, "FATAL: INDEXER_DATABASE_URL (or -database-url) is required")
		os.Exit(1)
	}
	if cfg.ValkeyAddr == "" {
		fmt.Fprintln(os.Stderr, "FATAL: INDEXER_VALKEY_ADDR (or -valkey-addr) is required")
		os.Exit(1)
	}

	return cfg
}

func setupLogger(level, format string) *slog.Logger {
	var logLevel slog.Level
	switch level {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: logLevel}

	var handler slog.Handler
	if format == "json" {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}

	return slog.New(handler)
}

// asynqLogger adapts slog.Logger to asynq.Logger interface.
type asynqLogger struct {
	logger *slog.Logger
}

func newAsynqLogger(l *slog.Logger) *asynqLogger {
	return &asynqLogger{logger: l}
}

func (l *asynqLogger) Debug(args ...any) { l.logger.Debug(fmt.Sprint(args...)) }
func (l *asynqLogger) Info(args ...any)  { l.logger.Info(fmt.Sprint(args...)) }
func (l *asynqLogger) Warn(args ...any)  { l.logger.Warn(fmt.Sprint(args...)) }
func (l *asynqLogger) Error(args ...any) { l.logger.Error(fmt.Sprint(args...)) }
func (l *asynqLogger) Fatal(args ...any) { l.logger.Error(fmt.Sprint(args...)) }
