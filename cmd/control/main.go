// Package main provides the control server entry point.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	urlpkg "net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"

	"github.com/manchtools/power-manage/sdk/gen/go/pm/v1/pmv1connect"
	"github.com/manchtools/power-manage/sdk/go/logging"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/api/template"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/config"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/middleware"
	"github.com/manchtools/power-manage/server/internal/mtls"
	"github.com/manchtools/power-manage/server/internal/scim"
	"github.com/manchtools/power-manage/server/internal/store"
)

// version is set at build time via -ldflags.
var version = "dev"

type Config struct {
	ListenAddr               string
	DatabaseURL              string
	JWTSecret                string
	CACertPath               string
	CAKeyPath                string
	CertValidity             time.Duration
	LogLevel                 string
	LogFormat                string
	AdminEmail               string
	AdminPassword            string
	CORSOrigins              []string
	GatewayURL               string
	TerminalGatewayURL       string // public WebSocket URL of the gateway terminal endpoint, e.g. wss://gw.example.com/terminal
	DynamicGroupEvalInterval time.Duration
	PasswordAuthEnabled      bool
	SSOCallbackBaseURL       string
	SCIMBaseURL              string
	TrustedProxies           []string
	CATrustBundlePath        string

	// Public listener TLS (optional — plain HTTP/1.1 when disabled)
	TLSEnabled bool
	TLSCert    string
	TLSKey     string

	// Internal mTLS listener (InternalService for gateway communication)
	InternalListenAddr string
	InternalTLSCert    string
	InternalTLSKey     string

	// CORS
	CORSAllowAll bool // Allow all origins (development only)

	// Valkey (Asynq task queue)
	ValkeyAddr     string
	ValkeyPassword string
	ValkeyDB       int

	// rc11 #77: derived-projection reconciler for system actions.
	// Interval is the period between full SyncAllUsersSystemActions
	// sweeps (safety net for the post-commit listener); 0 disables
	// the periodic goroutine entirely. Timeout is the per-sweep
	// context deadline so a hung query can't pile up missed ticks.
	SystemActionReconcileInterval time.Duration
	SystemActionReconcileTimeout  time.Duration
}

func main() {
	cfg := parseFlags()

	logger := logging.SetupLogger(cfg.LogLevel, cfg.LogFormat, os.Stderr)
	slog.SetDefault(logger)
	// Redact the gateway URL on the startup line too. If a bad shape
	// slipped in (e.g. https://u:p@host/ despite the validator, or an
	// operator paste-mistake), it shouldn't land in every boot log.
	logger.Info("starting control server", "version", version, "listen_addr", cfg.ListenAddr, "gateway_url", api.RedactGatewayURL(cfg.GatewayURL), "dynamic_group_eval_interval", cfg.DynamicGroupEvalInterval)
	// CONTROL_GATEWAY_URL is fatal when invalid: registration hands
	// it back to the agent verbatim, so any invalid shape — empty
	// string, bare hostname (parses as a relative path), http://
	// (agents refuse h2c), userinfo, or non-https scheme — turns
	// every successful enrollment into an agent that can never
	// connect. api.ValidateGatewayURL is the shared validator
	// (also invoked defensively in the registration handler).
	if err := api.ValidateGatewayURL(cfg.GatewayURL); err != nil {
		// Redact userinfo before logging — the validator rejects
		// URLs that contain credentials, but those credentials
		// shouldn't land in the startup error line regardless.
		logger.Error("CONTROL_GATEWAY_URL is invalid", "gateway_url", api.RedactGatewayURL(cfg.GatewayURL), "error", err)
		os.Exit(1)
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
	st.SetLogger(logger)
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

	if cfg.DynamicGroupEvalInterval > 0 {
		logger.Info("starting dynamic group evaluation worker", "interval", cfg.DynamicGroupEvalInterval)
		startDynamicGroupWorker(ctx, st, cfg.DynamicGroupEvalInterval, logger)
	} else {
		logger.Info("dynamic group evaluation worker disabled")
	}

	startStaleExecutionExpiry(ctx, st, logger)

	// Start periodic cleanup of stale OSQuery results
	go runPeriodic(ctx, 5*time.Minute, func() {
		if err := st.Queries().DeleteOldOSQueryResults(ctx); err != nil {
			logger.Error("failed to cleanup old osquery results", "error", err)
		}
	}, false)

	// Initialize secret encryptor.
	//
	// rc3 note: previously read unprefixed PM_ENCRYPTION_KEY /
	// PM_ENCRYPTION_KEY_REQUIRED. Now namespaced as
	// CONTROL_ENCRYPTION_KEY / CONTROL_ENCRYPTION_KEY_REQUIRED so all
	// control-server knobs live under one prefix. Operators upgrading
	// from rc2 must rename their .env entries — the old names are no
	// longer read.
	encryptor, err := initEncryptor(logger)
	if err != nil {
		logger.Error("failed to initialize encryptor", "error", err)
		os.Exit(1)
	}

	// Initialize action signer (signs actions so agents can verify authenticity)
	actionSigner := ca.NewActionSigner(certAuth)

	// Setup Connect-RPC service
	svc := api.NewControlService(st, jwtManager, actionSigner, certAuth, cfg.GatewayURL, logger, encryptor, api.ControlServiceConfig{
		PasswordAuthEnabled: cfg.PasswordAuthEnabled,
		SSOCallbackBaseURL:  cfg.SSOCallbackBaseURL,
		SCIMBaseURL:         cfg.SCIMBaseURL,
	})

	// One-shot env-driven seed of the global SSH-access-for-all flag.
	seedSSHAccessForAll(ctx, st, logger)

	// Reconcile system roles (Admin/User) with current permission definitions
	if err := auth.ReconcileSystemRoles(ctx, st.Queries(), logger); err != nil {
		logger.Error("failed to reconcile system roles", "error", err)
	}

	// rc11 #77: derived-projection wiring for system actions —
	// projectors.WireAll + startup sweep + post-commit listener +
	// periodic reconciler. See setup.go for the full rationale.
	wireSystemActions(ctx, st, svc, cfg, logger)

	configureTrustedProxies(cfg, logger)

	// Valkey-backed subsystem: taskqueue.Client + RediSearch index +
	// terminal token store + two Asynq servers. nil when the operator
	// hasn't configured CONTROL_VALKEY_ADDR. See valkey.go for the
	// component map.
	valkey, err := newValkeySubsystem(ctx, cfg, st, svc, actionSigner, logger)
	if err != nil {
		// valkey may be partially-initialised on error — Close is
		// nil-safe and only cleans up the components that did
		// construct, so it's still safe to invoke before exiting.
		valkey.Close()
		logger.Error("failed to initialize Valkey subsystem", "error", err)
		os.Exit(1)
	}
	defer valkey.Close()

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

	// Mount SCIM v2 handler. Passes svc.SystemActions() so the SCIM
	// delete path can clean up pm-tty-* / USER actions when the
	// last identity link is removed (rc11 #77).
	scimHandler := scim.NewHandler(st, logger, svc.SystemActions())
	mux.Handle("/scim/v2/", scimHandler)

	// Wrap with CORS and security headers middleware
	corsHandler := middleware.CORS(cfg.CORSOrigins, cfg.CORSAllowAll, logger)(mux)
	securedHandler := middleware.RequestID(middleware.SecurityHeaders(corsHandler))

	server, err := buildPublicServer(cfg, securedHandler)
	if err != nil {
		logger.Error("failed to build public server", "error", err)
		os.Exit(1)
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
	if valkey != nil && valkey.TerminalTokenStore != nil {
		// Shared with the ControlService.StartTerminal handler so the
		// gateway can validate tokens minted on this instance via
		// ProxyValidateTerminalToken.
		internalHandler.SetTerminalTokenStore(valkey.TerminalTokenStore)
	}
	// Server-side `{{ var.NAME }}` substitution for action params.
	// The renderer's StoreResolver reads device labels + group
	// variables from the projection and decrypts SECRET-typed values
	// via the same encryptor that wrote them. See manchtools/power-
	// manage-server#196 (group-based variables, design #59).
	internalHandler.SetRenderer(template.New(template.NewStoreResolver(st, encryptor, logger.With("component", "template"))))
	internalPath, internalH := pmv1connect.NewInternalServiceHandler(internalHandler)

	// Peer-class gate: InternalService handles credential-bearing
	// proxy calls (LUKS keys, LPS passwords). A compromised agent
	// cert must NOT be usable here — only gateway replicas, which
	// present certs issued out of band by setup.sh with a spiffe://
	// peer-class URI, are admitted.
	internalMux := http.NewServeMux()
	internalMux.Handle(internalPath, mtls.RequirePeerClass(logger, mtls.PeerClassGateway)(internalH))
	internalMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	internalServer, err := buildInternalServer(cfg, certAuth, internalMux)
	if err != nil {
		logger.Error("failed to build internal mTLS server", "error", err)
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
	flag.StringVar(&cfg.TerminalGatewayURL, "terminal-gateway-url", "", "Public WebSocket URL of the gateway terminal endpoint (e.g. wss://gw.example.com/terminal). When empty, ControlService.StartTerminal returns CodeUnavailable.")
	flag.DurationVar(&cfg.DynamicGroupEvalInterval, "dynamic-group-eval-interval", time.Hour, "Interval for evaluating dynamic groups (min 30m, max 8h, 0 to disable)")
	// rc11 #77 — system-action reconciliation defaults: 1m interval keeps drift bounded for an
	// operator-visible UX path (role grant → terminal works), 5m sweep timeout is plenty for
	// even a 10k-user fleet because the sync is read-heavy and short-circuits on no-op users.
	flag.DurationVar(&cfg.SystemActionReconcileInterval, "system-action-reconcile-interval", time.Minute, "Period between full SyncAllUsersSystemActions sweeps; 0 disables periodic reconciliation")
	flag.DurationVar(&cfg.SystemActionReconcileTimeout, "system-action-reconcile-timeout", 5*time.Minute, "Per-sweep context deadline for the periodic reconciler")
	flag.StringVar(&cfg.CATrustBundlePath, "ca-trust-bundle", "", "PEM file with trusted CA certificates for verification (supports CA rotation)")
	flag.BoolVar(&cfg.TLSEnabled, "tls", false, "Enable TLS on public listener")
	flag.StringVar(&cfg.TLSCert, "tls-cert", "", "TLS certificate for public listener")
	flag.StringVar(&cfg.TLSKey, "tls-key", "", "TLS private key for public listener")
	flag.StringVar(&cfg.InternalListenAddr, "internal-listen", ":8082", "Internal mTLS listen address for gateway communication")
	flag.StringVar(&cfg.InternalTLSCert, "internal-tls-cert", "/certs/control.crt", "TLS certificate for internal mTLS listener")
	flag.StringVar(&cfg.InternalTLSKey, "internal-tls-key", "/certs/control.key", "TLS private key for internal mTLS listener")

	flag.Parse()

	// Environment variable overrides
	config.EnvString(&cfg.ListenAddr, "CONTROL_LISTEN_ADDR")
	config.EnvString(&cfg.DatabaseURL, "CONTROL_DATABASE_URL")
	config.EnvString(&cfg.JWTSecret, "CONTROL_JWT_SECRET")
	config.EnvString(&cfg.CACertPath, "CONTROL_CA_CERT")
	config.EnvString(&cfg.CAKeyPath, "CONTROL_CA_KEY")
	config.EnvString(&cfg.CATrustBundlePath, "CONTROL_CA_TRUST_BUNDLE")
	config.EnvBool(&cfg.TLSEnabled, "CONTROL_TLS_ENABLED", []string{"true", "1"}, []string{"false", "0"})
	config.EnvString(&cfg.TLSCert, "CONTROL_TLS_CERT")
	config.EnvString(&cfg.TLSKey, "CONTROL_TLS_KEY")
	config.EnvString(&cfg.InternalListenAddr, "CONTROL_INTERNAL_LISTEN_ADDR")
	config.EnvString(&cfg.InternalTLSCert, "CONTROL_INTERNAL_TLS_CERT")
	config.EnvString(&cfg.InternalTLSKey, "CONTROL_INTERNAL_TLS_KEY")
	config.EnvString(&cfg.AdminEmail, "CONTROL_ADMIN_EMAIL")
	config.EnvString(&cfg.AdminPassword, "CONTROL_ADMIN_PASSWORD")
	config.EnvString(&cfg.LogLevel, "CONTROL_LOG_LEVEL")
	config.EnvString(&cfg.LogFormat, "CONTROL_LOG_FORMAT")
	config.EnvString(&cfg.GatewayURL, "CONTROL_GATEWAY_URL")
	config.EnvString(&cfg.TerminalGatewayURL, "CONTROL_TERMINAL_GATEWAY_URL")
	config.EnvCSV(&cfg.CORSOrigins, "CONTROL_CORS_ORIGINS")
	config.EnvDuration(&cfg.DynamicGroupEvalInterval, "CONTROL_DYNAMIC_GROUP_EVAL_INTERVAL")
	config.EnvDuration(&cfg.SystemActionReconcileInterval, "CONTROL_SYSTEM_ACTION_RECONCILE_INTERVAL")
	config.EnvDuration(&cfg.SystemActionReconcileTimeout, "CONTROL_SYSTEM_ACTION_RECONCILE_TIMEOUT")

	// SSO / Identity Provider configuration
	cfg.PasswordAuthEnabled = true // default enabled
	config.EnvBool(&cfg.PasswordAuthEnabled, "CONTROL_PASSWORD_AUTH_ENABLED", []string{"true", "1"}, []string{"false", "0"})
	config.EnvString(&cfg.SSOCallbackBaseURL, "CONTROL_SSO_CALLBACK_BASE_URL")
	if cfg.SSOCallbackBaseURL == "" && len(cfg.CORSOrigins) > 0 {
		cfg.SSOCallbackBaseURL = cfg.CORSOrigins[0]
	}
	config.EnvString(&cfg.SCIMBaseURL, "CONTROL_SCIM_BASE_URL")
	config.EnvCSV(&cfg.TrustedProxies, "CONTROL_TRUSTED_PROXIES")
	config.EnvBool(&cfg.CORSAllowAll, "CONTROL_CORS_ALLOW_ALL", []string{"true", "1"}, []string{"false", "0"})

	// Valkey (Asynq task queue) configuration
	config.EnvString(&cfg.ValkeyAddr, "CONTROL_VALKEY_ADDR")
	config.EnvString(&cfg.ValkeyPassword, "CONTROL_VALKEY_PASSWORD")
	config.EnvInt(&cfg.ValkeyDB, "CONTROL_VALKEY_DB")

	// Validate dynamic group evaluation interval (0 to disable, min 30m, max 8h)
	config.ClampInterval(&cfg.DynamicGroupEvalInterval, 30*time.Minute, 8*time.Hour)

	// Clamp system-action reconcile flags. The interval treats 0 as
	// "disabled, matching StartReconciliation"; the timeout's 0 case
	// would silently break the durability safety net via
	// context.WithTimeout returning an already-cancelled context, so
	// it falls back to the 5min default rather than disabling.
	config.ClampInterval(&cfg.SystemActionReconcileInterval, 10*time.Second, 8*time.Hour)
	config.ClampDurationFloor(&cfg.SystemActionReconcileTimeout, 5*time.Minute, 0)

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

	// Look up Admin role BEFORE emitting the user-creation event so
	// the user INSERT and the role assignment land atomically inside
	// one projector tx (issue #135). If the role lookup fails (no
	// Admin role seeded yet?), log and proceed with no roles - the
	// Go projector treats a missing role_ids key the same as an
	// empty slice and skips the per-role INSERT loop.
	var roleIDs []string
	if adminRole, err := st.Queries().GetRoleByName(ctx, "Admin"); err == nil {
		roleIDs = []string{adminRole.ID}
	} else {
		logger.Warn("failed to look up Admin role for bootstrap user; user will be created with no roles",
			"user_id", id, "error", err)
	}

	// Append UserCreatedWithRoles compound event - the projector
	// inserts the user row AND the per-role assignment row in one tx.
	emailCopy := email
	passwordHashCopy := passwordHash
	role := "admin"
	err = st.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   id,
		EventType:  string(eventtypes.UserCreatedWithRoles),
		Data: payloads.UserCreatedWithRoles{
			Email:        &emailCopy,
			PasswordHash: &passwordHashCopy,
			Role:         &role,
			RoleIDs:      roleIDs,
		},
		ActorType: "system",
		ActorID:   "bootstrap",
	})
	if err != nil {
		return fmt.Errorf("create user event: %w", err)
	}

	logger.Info("admin user created", "email", email, "id", id)
	return nil
}

// Note: env / clamp helpers used by parseFlags live in
// internal/config (FromEnv + Validate + bounded clamps). The
// previous local trampolines were inlined to drop a layer of
// indirection — call sites now reference config.EnvString,
// config.ClampInterval, etc. directly. See manchtools/power-
// manage-server#152 (audit F017+F018).

// maskDatabaseURL masks the password in a database URL for logging.
// Uses net/url parsing so URL-encoded credentials (e.g. passwords that
// contain ':' or '@') are handled correctly; the hand-rolled scan we
// had before could mangle those edge cases.
func maskDatabaseURL(raw string) string {
	u, err := urlpkg.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	if _, hasPassword := u.User.Password(); !hasPassword {
		return raw
	}
	u.User = urlpkg.UserPassword(u.User.Username(), "***")
	return u.String()
}
