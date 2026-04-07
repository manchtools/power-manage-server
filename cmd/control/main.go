// Package main provides the control server entry point.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"strconv"

	"connectrpc.com/connect"
	"github.com/hibiken/asynq"
	"github.com/oklog/ulid/v2"
	"github.com/redis/go-redis/v9"
	"golang.org/x/net/http2"

	"github.com/manchtools/power-manage/sdk/gen/go/pm/v1/pmv1connect"
	"github.com/manchtools/power-manage/sdk/go/logging"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/asynqutil"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/control"
	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/middleware"
	"github.com/manchtools/power-manage/server/internal/scim"
	"github.com/manchtools/power-manage/server/internal/search"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

// version is set at build time via -ldflags.
var version = "dev"

type Config struct {
	ListenAddr                   string
	DatabaseURL                  string
	JWTSecret                    string
	CACertPath                   string
	CAKeyPath                    string
	CertValidity                 time.Duration
	LogLevel                     string
	LogFormat                    string
	AdminEmail                   string
	AdminPassword                string
	CORSOrigins                  []string
	GatewayURL                   string
	DynamicGroupEvalInterval     time.Duration
	PasswordAuthEnabled          bool
	SSOCallbackBaseURL           string
	SCIMBaseURL                  string
	TrustedProxies               []string
	CATrustBundlePath            string

	// Public listener TLS (optional — plain HTTP/1.1 when disabled)
	TLSEnabled bool
	TLSCert    string
	TLSKey     string

	// Internal mTLS listener (InternalService for gateway communication)
	InternalListenAddr string
	InternalTLSCert    string
	InternalTLSKey     string

	// Valkey (Asynq task queue)
	ValkeyAddr     string
	ValkeyPassword string
	ValkeyDB       int

}

func main() {
	cfg := parseFlags()

	logger := logging.SetupLogger(cfg.LogLevel, cfg.LogFormat, os.Stderr)
	slog.SetDefault(logger)
	logger.Info("starting control server", "version", version, "listen_addr", cfg.ListenAddr, "gateway_url", cfg.GatewayURL, "dynamic_group_eval_interval", cfg.DynamicGroupEvalInterval)
	if cfg.GatewayURL == "" {
		logger.Warn("CONTROL_GATEWAY_URL is not set - agents will not receive a gateway URL during registration")
	}

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

	// Initialize store with PostgreSQL
	st, err := store.New(ctx, cfg.DatabaseURL)
	if err != nil {
		logger.Error("failed to initialize store", "error", err)
		os.Exit(1)
	}
	defer st.Close()
	logger.Info("database initialized", "url", maskDatabaseURL(cfg.DatabaseURL))

	// Create admin user if specified and not exists
	if cfg.AdminEmail != "" && cfg.AdminPassword != "" {
		if err := ensureAdminUser(ctx, st, cfg.AdminEmail, cfg.AdminPassword, logger); err != nil {
			logger.Error("failed to create admin user", "error", err)
			os.Exit(1)
		}
	}

	// Initialize CA
	certAuth, err := ca.New(cfg.CACertPath, cfg.CAKeyPath, cfg.CertValidity)
	if err != nil {
		logger.Error("failed to initialize CA", "error", err)
		os.Exit(1)
	}
	if cfg.CATrustBundlePath != "" {
		bundlePEM, err := os.ReadFile(cfg.CATrustBundlePath)
		if err != nil {
			logger.Error("failed to read CA trust bundle", "error", err, "path", cfg.CATrustBundlePath)
			os.Exit(1)
		}
		if err := certAuth.SetTrustBundle(bundlePEM); err != nil {
			logger.Error("failed to load CA trust bundle", "error", err)
			os.Exit(1)
		}
		logger.Info("CA trust bundle loaded", "path", cfg.CATrustBundlePath)
	}
	logger.Info("CA initialized", "validity", cfg.CertValidity)

	// Initialize JWT manager
	jwtManager := auth.NewJWTManager(auth.JWTConfig{
		Secret: []byte(cfg.JWTSecret),
	})

	// Start periodic cleanup of expired revoked tokens
	go runPeriodic(ctx, 1*time.Hour, func() {
		if err := st.Queries().CleanupExpiredRevocations(ctx); err != nil {
			logger.Error("failed to cleanup expired token revocations", "error", err)
		}
	}, false)

	// Start periodic evaluation of queued dynamic groups.
	// evaluateDynamicGroups drains the queue in batches of 1000 until empty.
	evaluateDynamicGroups := func() {
		for {
			count, err := st.Queries().EvaluateQueuedDynamicGroups(ctx)
			if err != nil {
				logger.Error("failed to evaluate queued dynamic groups", "error", err)
				return
			}
			if count > 0 {
				logger.Info("evaluated queued dynamic groups", "count", count)
			}
			if count < 1000 {
				return // queue is drained
			}
		}
	}

	evaluateDynamicUserGroups := func() {
		for {
			count, err := st.Queries().EvaluateQueuedDynamicUserGroups(ctx)
			if err != nil {
				logger.Error("failed to evaluate queued dynamic user groups", "error", err)
				return
			}
			if count > 0 {
				logger.Info("evaluated queued dynamic user groups", "count", count)
			}
			if count < 100 {
				return // queue is drained
			}
		}
	}

	if cfg.DynamicGroupEvalInterval > 0 {
		logger.Info("starting dynamic group evaluation worker", "interval", cfg.DynamicGroupEvalInterval)
		go func() {
			// Run immediately on startup to process any groups queued during downtime
			evaluateDynamicGroups()
			evaluateDynamicUserGroups()

			ticker := time.NewTicker(cfg.DynamicGroupEvalInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					evaluateDynamicGroups()
					evaluateDynamicUserGroups()
				case <-ctx.Done():
					return
				}
			}
		}()

		// Periodic full re-evaluation as a safety net (every 24h).
		// Queues all dynamic groups for evaluation; the worker above drains them.
		go runPeriodic(ctx, 24*time.Hour, func() {
			if err := st.Queries().QueueAllDynamicGroups(ctx); err != nil {
				logger.Error("failed to queue full dynamic group re-evaluation", "error", err)
			} else {
				logger.Info("queued full dynamic group re-evaluation")
			}
		}, false)
	} else {
		logger.Info("dynamic group evaluation worker disabled")
	}

	// Start periodic expiry of stale executions (pending/dispatched too long)
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				stale, err := st.Queries().ListStaleExecutions(ctx)
				if err != nil {
					logger.Error("failed to list stale executions", "error", err)
					continue
				}
				for _, exec := range stale {
					errMsg := fmt.Sprintf("execution timed out: device did not respond (status was %s)", exec.Status)
					if err := st.AppendEvent(ctx, store.Event{
						StreamType: "execution",
						StreamID:   exec.ID,
						EventType:  "ExecutionTimedOut",
						Data: map[string]any{
							"error":        errMsg,
							"completed_at": time.Now().Format(time.RFC3339Nano),
						},
						ActorType: "system",
						ActorID:   "expiry",
					}); err != nil {
						logger.Error("failed to expire stale execution", "error", err, "execution_id", exec.ID)
					} else {
						logger.Info("expired stale execution", "execution_id", exec.ID, "status", exec.Status, "device_id", exec.DeviceID)
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Start periodic cleanup of stale OSQuery results
	go runPeriodic(ctx, 5*time.Minute, func() {
		if err := st.Queries().DeleteOldOSQueryResults(ctx); err != nil {
			logger.Error("failed to cleanup old osquery results", "error", err)
		}
	}, false)

	// Initialize secret encryptor
	encryptor, err := crypto.NewEncryptor(os.Getenv("PM_ENCRYPTION_KEY"))
	if err != nil {
		logger.Error("failed to initialize encryptor", "error", err)
		os.Exit(1)
	}
	if encryptor == nil {
		logger.Warn("PM_ENCRYPTION_KEY not set - secrets will be stored unencrypted")
	}

	// Initialize action signer (signs actions so agents can verify authenticity)
	actionSigner := ca.NewActionSigner(certAuth)

	// Setup Connect-RPC service
	svc := api.NewControlService(st, jwtManager, actionSigner, certAuth, cfg.GatewayURL, logger, encryptor, api.ControlServiceConfig{
		PasswordAuthEnabled:       cfg.PasswordAuthEnabled,
		SSOCallbackBaseURL:        cfg.SSOCallbackBaseURL,
		SCIMBaseURL:               cfg.SCIMBaseURL,
	})

	// Seed SSH access for all from env var (one-time: only sets if DB value is still false)
	if v := os.Getenv("CONTROL_SSH_ACCESS_FOR_ALL"); v == "true" || v == "1" {
		settings, err := st.Queries().GetServerSettings(ctx)
		if err == nil && !settings.SshAccessForAll {
			if err := st.AppendEvent(ctx, store.Event{
				StreamType: "server_settings",
				StreamID:   "global",
				EventType:  "ServerSettingUpdated",
				Data: map[string]any{
					"user_provisioning_enabled": settings.UserProvisioningEnabled,
					"ssh_access_for_all":        true,
				},
				ActorType: "system",
				ActorID:   "system",
			}); err != nil {
				logger.Error("failed to seed SSH access for all from env var", "error", err)
			} else {
				logger.Info("seeded SSH access for all from CONTROL_SSH_ACCESS_FOR_ALL env var")
			}
		}
	}

	// Reconcile system roles (Admin/User) with current permission definitions
	if err := auth.ReconcileSystemRoles(ctx, st.Queries(), logger); err != nil {
		logger.Error("failed to reconcile system roles", "error", err)
	}

	// Sync system actions for all users at startup (idempotent)
	if svc.SystemActions() != nil {
		if err := svc.SystemActions().SyncAllUsersSystemActions(ctx); err != nil {
			logger.Error("failed to sync system actions at startup", "error", err)
		}
	}
	// Configure trusted proxies for X-Forwarded-For header validation
	if len(cfg.TrustedProxies) > 0 {
		auth.SetTrustedProxies(cfg.TrustedProxies)
		logger.Info("trusted proxies configured", "proxies", cfg.TrustedProxies)
	}

	// Initialize Asynq task queue (Valkey) if configured
	if cfg.ValkeyAddr != "" {
		aqClient := taskqueue.NewClient(cfg.ValkeyAddr, cfg.ValkeyPassword, cfg.ValkeyDB)
		defer aqClient.Close()

		// Propagate Asynq client to API handlers for dispatch
		svc.SetTaskQueueClient(aqClient)

		// Initialize go-redis client for RediSearch.
		// Force RESP2 protocol: go-redis v9 auto-negotiates RESP3 with Redis 7+,
		// but RediSearch returns FT.SEARCH results in a different format under
		// RESP3 (map vs array), which breaks our result parser.
		rdb := redis.NewClient(&redis.Options{
			Addr:     cfg.ValkeyAddr,
			Password: cfg.ValkeyPassword,
			DB:       cfg.ValkeyDB,
			Protocol: 2,
		})
		defer rdb.Close()

		// Initialize search index (RediSearch backed).
		// The indexer binary handles warm/rebuild/reconciliation and search task processing.
		// The control server only enqueues search tasks and runs FT.SEARCH queries.
		searchIdx := search.New(rdb, st, aqClient, logger.With("component", "search"))
		svc.SetSearchIndex(searchIdx)

		// Index audit events on insertion — the hook fires after every AppendEvent
		// and enqueues the persisted row directly (no DB lookup in the search worker).
		st.OnEventAppended = func(ctx context.Context, ev store.PersistedEvent) {
			id := ulid.ULID(ev.ID).String()
			if err := searchIdx.EnqueueReindex(ctx, search.ScopeAuditEvent, id, &taskqueue.SearchEntityData{
				EventType:  ev.EventType,
				StreamType: ev.StreamType,
				ActorType:  ev.ActorType,
				ActorID:    ev.ActorID,
				StreamID:   ev.StreamID,
				OccurredAt: ev.OccurredAt.Unix(),
			}); err != nil {
				logger.Warn("failed to enqueue audit event reindex", "id", id, "error", err)
			}
		}

		// Ensure indexes exist (idempotent, needed for FT.SEARCH queries).
		if err := searchIdx.EnsureIndexes(context.Background()); err != nil {
			logger.Warn("failed to ensure search indexes", "error", err)
		}

		// Build Asynq mux with inbox worker only (search worker runs in indexer binary)
		inboxWorker := control.NewInboxWorker(st, aqClient, logger.With("component", "inbox_worker"))
		mux := inboxWorker.NewMux()

		// Start Asynq server consuming control:inbox queue only
		aqLogger := logger.With("component", "asynq_server")
		aqServer := asynq.NewServer(
			asynq.RedisClientOpt{
				Addr:     cfg.ValkeyAddr,
				Password: cfg.ValkeyPassword,
				DB:       cfg.ValkeyDB,
			},
			asynq.Config{
				Concurrency: 10,
				Queues: map[string]int{
					taskqueue.ControlInboxQueue: 2,
				},
				Logger: asynqutil.NewLogger(aqLogger),
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

		logger.Info("Asynq task queue initialized", "valkey_addr", cfg.ValkeyAddr, "search_enabled", true)
	}

	loginLimiter := auth.NewRateLimiter(1000, 1*time.Minute)
	refreshLimiter := auth.NewRateLimiter(1000, 1*time.Minute)
	registerLimiter := auth.NewRateLimiter(1000, 1*time.Minute)

	interceptors := connect.WithInterceptors(
		api.NewLoggingInterceptor(logger),
		auth.NewAuthInterceptor(logger, jwtManager, loginLimiter, refreshLimiter, registerLimiter),
		auth.NewAuthzInterceptor(),
	)

	mux := http.NewServeMux()
	path, handler := pmv1connect.NewControlServiceHandler(svc, interceptors)
	mux.Handle(path, handler)

	// Mount SCIM v2 handler
	scimHandler := scim.NewHandler(st, logger)
	mux.Handle("/scim/v2/", scimHandler)

	// Wrap with CORS and security headers middleware
	corsAllowAll := os.Getenv("CONTROL_CORS_ALLOW_ALL") == "true"
	corsHandler := middleware.CORS(cfg.CORSOrigins, corsAllowAll, logger)(mux)
	securedHandler := middleware.RequestID(middleware.SecurityHeaders(corsHandler))

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           securedHandler,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Configure TLS for public listener if enabled
	if cfg.TLSEnabled {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			logger.Error("failed to load public TLS certificate", "error", err)
			os.Exit(1)
		}
		server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		if err := http2.ConfigureServer(server, &http2.Server{}); err != nil {
			logger.Error("failed to configure HTTP/2 for public server", "error", err)
			os.Exit(1)
		}
	}

	// Add health check endpoint.
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"ok","version":%q}`, version)
	})

	// Mount InternalService on a separate mTLS-protected listener.
	// The gateway presents its CA-signed certificate as a client cert.
	internalHandler := api.NewInternalHandler(st, encryptor, logger.With("component", "internal_service"))
	internalPath, internalH := pmv1connect.NewInternalServiceHandler(internalHandler)

	internalMux := http.NewServeMux()
	internalMux.Handle(internalPath, internalH)
	internalMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	internalTLSCert, err := tls.LoadX509KeyPair(cfg.InternalTLSCert, cfg.InternalTLSKey)
	if err != nil {
		logger.Error("failed to load internal TLS certificate", "error", err, "cert", cfg.InternalTLSCert, "key", cfg.InternalTLSKey)
		os.Exit(1)
	}

	internalCAPool := certAuth.TrustPool()

	internalTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{internalTLSCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    internalCAPool,
		MinVersion:   tls.VersionTLS13,
	}

	internalServer := &http.Server{
		Addr:              cfg.InternalListenAddr,
		Handler:           internalMux,
		TLSConfig:         internalTLSConfig,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := http2.ConfigureServer(internalServer, &http2.Server{}); err != nil {
		logger.Error("failed to configure HTTP/2 for internal server", "error", err)
		os.Exit(1)
	}

	// Start public server
	go func() {
		if cfg.TLSEnabled {
			logger.Info("control server listening (TLS)", "addr", cfg.ListenAddr)
			if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				logger.Error("server error", "error", err)
				cancel()
			}
		} else {
			logger.Info("control server listening (plain HTTP)", "addr", cfg.ListenAddr)
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("server error", "error", err)
				cancel()
			}
		}
	}()

	// Start internal mTLS server
	go func() {
		logger.Info("internal mTLS server listening", "addr", cfg.InternalListenAddr)
		if err := internalServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			logger.Error("internal server error", "error", err)
			cancel()
		}
	}()

	// Wait for shutdown
	<-ctx.Done()

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("failed to shutdown server", "error", err)
	}
	if err := internalServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("failed to shutdown internal server", "error", err)
	}

	logger.Info("control server stopped")
}

func parseFlags() *Config {
	cfg := &Config{}

	flag.StringVar(&cfg.ListenAddr, "listen", ":8081", "Listen address")
	flag.StringVar(&cfg.DatabaseURL, "database-url", "", "PostgreSQL connection URL")
	flag.StringVar(&cfg.JWTSecret, "jwt-secret", "", "JWT secret key")
	flag.StringVar(&cfg.CACertPath, "ca-cert", "/certs/ca.crt", "CA certificate path")
	flag.StringVar(&cfg.CAKeyPath, "ca-key", "/certs/ca.key", "CA private key path")
	flag.DurationVar(&cfg.CertValidity, "cert-validity", 8760*time.Hour, "Certificate validity duration")
	flag.StringVar(&cfg.LogLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	flag.StringVar(&cfg.LogFormat, "log-format", "text", "Log format (text, json)")
	flag.StringVar(&cfg.AdminEmail, "admin-email", "", "Initial admin user email")
	flag.StringVar(&cfg.AdminPassword, "admin-password", "", "Initial admin user password")
	flag.StringVar(&cfg.GatewayURL, "gateway-url", "", "Gateway URL returned to agents during registration")
	flag.DurationVar(&cfg.DynamicGroupEvalInterval, "dynamic-group-eval-interval", time.Hour, "Interval for evaluating dynamic groups (min 30m, max 8h, 0 to disable)")
	flag.StringVar(&cfg.CATrustBundlePath, "ca-trust-bundle", "", "PEM file with trusted CA certificates for verification (supports CA rotation)")
	flag.BoolVar(&cfg.TLSEnabled, "tls", false, "Enable TLS on public listener")
	flag.StringVar(&cfg.TLSCert, "tls-cert", "", "TLS certificate for public listener")
	flag.StringVar(&cfg.TLSKey, "tls-key", "", "TLS private key for public listener")
	flag.StringVar(&cfg.InternalListenAddr, "internal-listen", ":8082", "Internal mTLS listen address for gateway communication")
	flag.StringVar(&cfg.InternalTLSCert, "internal-tls-cert", "/certs/control.crt", "TLS certificate for internal mTLS listener")
	flag.StringVar(&cfg.InternalTLSKey, "internal-tls-key", "/certs/control.key", "TLS private key for internal mTLS listener")

	flag.Parse()

	// Environment variable overrides
	envString(&cfg.ListenAddr, "CONTROL_LISTEN_ADDR")
	envString(&cfg.DatabaseURL, "CONTROL_DATABASE_URL")
	envString(&cfg.JWTSecret, "CONTROL_JWT_SECRET")
	envString(&cfg.CACertPath, "CONTROL_CA_CERT")
	envString(&cfg.CAKeyPath, "CONTROL_CA_KEY")
	envString(&cfg.CATrustBundlePath, "CONTROL_CA_TRUST_BUNDLE")
	envBool(&cfg.TLSEnabled, "CONTROL_TLS_ENABLED", []string{"true", "1"}, []string{"false", "0"})
	envString(&cfg.TLSCert, "CONTROL_TLS_CERT")
	envString(&cfg.TLSKey, "CONTROL_TLS_KEY")
	envString(&cfg.InternalListenAddr, "CONTROL_INTERNAL_LISTEN_ADDR")
	envString(&cfg.InternalTLSCert, "CONTROL_INTERNAL_TLS_CERT")
	envString(&cfg.InternalTLSKey, "CONTROL_INTERNAL_TLS_KEY")
	envString(&cfg.AdminEmail, "CONTROL_ADMIN_EMAIL")
	envString(&cfg.AdminPassword, "CONTROL_ADMIN_PASSWORD")
	envString(&cfg.LogLevel, "CONTROL_LOG_LEVEL")
	envString(&cfg.LogFormat, "CONTROL_LOG_FORMAT")
	envString(&cfg.GatewayURL, "CONTROL_GATEWAY_URL")
	envCSV(&cfg.CORSOrigins, "CONTROL_CORS_ORIGINS")
	envDuration(&cfg.DynamicGroupEvalInterval, "CONTROL_DYNAMIC_GROUP_EVAL_INTERVAL")

	// SSO / Identity Provider configuration
	cfg.PasswordAuthEnabled = true // default enabled
	envBool(&cfg.PasswordAuthEnabled, "CONTROL_PASSWORD_AUTH_ENABLED", []string{"true", "1"}, []string{"false", "0"})
	envString(&cfg.SSOCallbackBaseURL, "CONTROL_SSO_CALLBACK_BASE_URL")
	if cfg.SSOCallbackBaseURL == "" && len(cfg.CORSOrigins) > 0 {
		cfg.SSOCallbackBaseURL = cfg.CORSOrigins[0]
	}
	envString(&cfg.SCIMBaseURL, "CONTROL_SCIM_BASE_URL")
	envCSV(&cfg.TrustedProxies, "CONTROL_TRUSTED_PROXIES")

	// Valkey (Asynq task queue) configuration
	envString(&cfg.ValkeyAddr, "CONTROL_VALKEY_ADDR")
	envString(&cfg.ValkeyPassword, "CONTROL_VALKEY_PASSWORD")
	envInt(&cfg.ValkeyDB, "CONTROL_VALKEY_DB")

	// Validate dynamic group evaluation interval (0 to disable, min 30m, max 8h)
	if cfg.DynamicGroupEvalInterval != 0 {
		if cfg.DynamicGroupEvalInterval < 30*time.Minute {
			cfg.DynamicGroupEvalInterval = 30 * time.Minute
		} else if cfg.DynamicGroupEvalInterval > 8*time.Hour {
			cfg.DynamicGroupEvalInterval = 8 * time.Hour
		}
	}

	if cfg.JWTSecret == "" {
		fmt.Fprintln(os.Stderr, "FATAL: CONTROL_JWT_SECRET (or -jwt-secret) is required")
		os.Exit(1)
	}
	if len(cfg.JWTSecret) < 32 {
		fmt.Fprintln(os.Stderr, "FATAL: CONTROL_JWT_SECRET must be at least 32 characters")
		os.Exit(1)
	}

	if cfg.TLSEnabled && (cfg.TLSCert == "" || cfg.TLSKey == "") {
		fmt.Fprintln(os.Stderr, "FATAL: -tls-cert and -tls-key are required when TLS is enabled")
		os.Exit(1)
	}

	return cfg
}

func ensureAdminUser(ctx context.Context, st *store.Store, email, password string, logger *slog.Logger) error {
	// Check if user exists via the projection
	_, err := st.Queries().GetUserByEmail(ctx, email)
	if err == nil {
		logger.Info("admin user already exists", "email", email)
		return nil
	}

	// Create admin user via event sourcing
	passwordHash, err := auth.HashPassword(password)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	id := ulid.Make().String()

	// Append UserCreated event - the trigger will handle projection
	err = st.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   id,
		EventType:  "UserCreated",
		Data: map[string]any{
			"email":         email,
			"password_hash": passwordHash,
			"role":          "admin",
		},
		ActorType: "system",
		ActorID:   "bootstrap",
	})
	if err != nil {
		return fmt.Errorf("create user event: %w", err)
	}

	// Assign the Admin role to the bootstrap user
	adminRole, err := st.Queries().GetRoleByName(ctx, "Admin")
	if err == nil {
		if err := st.AppendEvent(ctx, store.Event{
			StreamType: "user_role",
			StreamID:   id + ":" + adminRole.ID,
			EventType:  "UserRoleAssigned",
			Data: map[string]any{
				"user_id": id,
				"role_id": adminRole.ID,
			},
			ActorType: "system",
			ActorID:   "bootstrap",
		}); err != nil {
			logger.Warn("failed to assign admin role to bootstrap user", "user_id", id, "error", err)
		}
	}

	logger.Info("admin user created", "email", email, "id", id)
	return nil
}

// envString overrides target with the environment variable value if set.
func envString(target *string, key string) {
	if v := os.Getenv(key); v != "" {
		*target = v
	}
}

// envBool sets target based on the environment variable matching true or false values.
// Logs a warning if the value is set but doesn't match any recognized value.
func envBool(target *bool, key string, trueValues, falseValues []string) {
	v := os.Getenv(key)
	if v == "" {
		return
	}
	for _, tv := range trueValues {
		if v == tv {
			*target = true
			return
		}
	}
	for _, fv := range falseValues {
		if v == fv {
			*target = false
			return
		}
	}
	slog.Warn("unrecognized boolean env var value, keeping default", "key", key, "value", v)
}

// envDuration overrides target with the parsed duration if the environment variable is set.
func envDuration(target *time.Duration, key string) {
	if v := os.Getenv(key); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			slog.Warn("invalid duration for env var, keeping default", "key", key, "value", v, "error", err)
			return
		}
		*target = d
	}
}

// envCSV overrides target with a comma-separated environment variable, trimming whitespace
// and filtering empty entries.
func envCSV(target *[]string, key string) {
	if v := os.Getenv(key); v != "" {
		parts := strings.Split(v, ",")
		var filtered []string
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				filtered = append(filtered, p)
			}
		}
		*target = filtered
	}
}

// envInt overrides target with the parsed integer if the environment variable is set.
func envInt(target *int, key string) {
	if v := os.Getenv(key); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			slog.Warn("invalid integer for env var, keeping default", "key", key, "value", v, "error", err)
			return
		}
		*target = n
	}
}

// runPeriodic calls fn on every tick until ctx is cancelled.
// If runImmediately is true, fn is called once before the first tick.
func runPeriodic(ctx context.Context, interval time.Duration, fn func(), runImmediately bool) {
	if runImmediately {
		fn()
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			fn()
		case <-ctx.Done():
			return
		}
	}
}

// maskDatabaseURL masks the password in a database URL for logging.
func maskDatabaseURL(url string) string {
	// Simple masking - replace password portion
	// postgres://user:password@host:port/db -> postgres://user:***@host:port/db
	for i := 0; i < len(url); i++ {
		if url[i] == ':' && i > 10 { // Skip the postgres:// part
			for j := i + 1; j < len(url); j++ {
				if url[j] == '@' {
					return url[:i+1] + "***" + url[j:]
				}
			}
		}
	}
	return url
}
