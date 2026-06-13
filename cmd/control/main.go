// Package main provides the control server entry point.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"connectrpc.com/connect"

	"github.com/manchtools/power-manage/sdk/gen/go/pm/v1/pmv1connect"
	"github.com/manchtools/power-manage/sdk/go/logging"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/middleware"
	"github.com/manchtools/power-manage/server/internal/mtls"
	"github.com/manchtools/power-manage/server/internal/scim"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/postgres"
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
	st.SetRepos(postgres.NewRepos(st.Queries()))
	logger.Info("database initialized", "url", maskDatabaseURL(cfg.DatabaseURL))

	// NOTE: bootstrap event emissions (ensureAdminUser, seedSSHAccessForAll,
	// bootstrapAllDevicesGroup) live AFTER wireSystemActions below. Tracker
	// #107 / #317: Go-side projector listeners only fire for new events, so
	// any AppendEvent before WireAll silently skips the projection write —
	// the canonical case being a fresh install where the admin user lands
	// in events but not in users_projection, and login then fails.

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

	startStaleExecutionExpiry(ctx, st, logger, time.Now)

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

	// Reconcile system roles (Admin/User) with current permission definitions.
	// Bypasses the event store (direct UPDATE on roles_projection via sqlc),
	// so the ordering vs WireAll doesn't matter for this call.
	// Fail CLOSED: the reconciler is the authority that syncs the Admin/User
	// system roles to the code-defined permission sets (the migration seed is a
	// stale starting point). Booting anyway on failure would serve traffic with
	// drifted system-role permissions, so a failure is fatal (#16).
	if err := auth.ReconcileSystemRoles(ctx, st.Queries(), logger); err != nil {
		logger.Error("failed to reconcile system roles", "error", err)
		os.Exit(1)
	}

	// rc11 #77: derived-projection wiring for system actions —
	// projectors.WireAll + startup sweep + post-commit listener +
	// periodic reconciler. See setup.go for the full rationale.
	//
	// Every bootstrap helper that emits events MUST run AFTER this call
	// (#317). Go-side listeners are only registered here; an AppendEvent
	// before WireAll persists the event but skips the projection write.
	wireSystemActions(ctx, st, svc, cfg, logger)

	// Bootstrap admin user (event-sourced via UserCreatedWithRoles).
	// Runs after WireAll so UserListener materialises users_projection.
	if cfg.AdminEmail != "" && cfg.AdminPassword != "" {
		if err := ensureAdminUser(ctx, st, cfg.AdminEmail, cfg.AdminPassword, logger); err != nil {
			logger.Error("failed to create admin user", "error", err)
			os.Exit(1)
		}
	}

	// One-shot env-driven seed of the global SSH-access-for-all flag.
	// Emits ServerSettingUpdated; needs ServerSettingsListener registered.
	seedSSHAccessForAll(ctx, st, logger)

	// Boot-time seed of the "All Devices" dynamic group. Runs AFTER
	// WireAll so the DeviceGroupCreated event flows through the
	// registered projector listener (#242 Wave H — replaces the
	// PL/pgSQL DO block in migration 008).
	bootstrapAllDevicesGroup(ctx, st, logger)

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

	// Per-procedure rate limits (audit F036 / #145 / #142). Shared
	// limiters keyed by client IP; a determined attacker behind many
	// IPs can rotate sources but the per-procedure ceiling is tight
	// enough that any single IP is locked out of credential-spray
	// patterns within seconds. Login + VerifyLoginTOTP + SSOCallback
	// share one limiter — they're all auth-attempt vectors that a
	// defender treats as one logical "attempt" per IP.
	rateLimiters := auth.RateLimiters{
		Login:       auth.NewRateLimiter(10, 1*time.Minute), // credential-spray defense
		Refresh:     auth.NewRateLimiter(60, 1*time.Minute), // legitimate refreshes are frequent
		Register:    auth.NewRateLimiter(5, 1*time.Minute),  // registration spam protection
		Logout:      auth.NewRateLimiter(30, 1*time.Minute), // legitimate multi-session logout ceiling
		RenewCert:   auth.NewRateLimiter(5, 1*time.Minute),  // cert rotation = once/lifetime, not in tight loop
		AuthMethods: auth.NewRateLimiter(30, 1*time.Minute), // unauth email-lookup oracle — bound bulk enumeration
	}

	interceptors := connect.WithInterceptors(
		api.NewLoggingInterceptor(logger),
		auth.NewAuthInterceptor(logger, jwtManager, rateLimiters),
		api.NewValidationInterceptor(),
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

	// Public health endpoint — minimal response so unauthenticated
	// callers cannot enumerate server versions for vulnerability
	// scanning (audit F-26). The version is still reachable via
	// authenticated control RPCs (GetServerVersion equivalent) and
	// via the mTLS-protected internal /health below for operator
	// scrape tools.
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Mount InternalService on a separate mTLS-protected listener.
	// The gateway presents its CA-signed certificate as a client cert.
	internalHandler := api.NewInternalHandler(st, encryptor, logger.With("component", "internal_service"), actionSigner)
	if valkey != nil && valkey.TerminalTokenStore != nil {
		// Shared with the ControlService.StartTerminal handler so the
		// gateway can validate tokens minted on this instance via
		// ProxyValidateTerminalToken.
		internalHandler.SetTerminalTokenStore(valkey.TerminalTokenStore)
	}
	if valkey != nil && valkey.GatewayRegistry != nil {
		// Confine every device-origin InternalService request to the gateway the
		// device is actually live on (server#403). Wired whenever the
		// Valkey-backed routing registry is available; a nil resolver (no
		// registry) keeps the documented single-gateway bypass.
		internalHandler.SetDeviceGatewayResolver(valkey.GatewayRegistry)
	}
	internalPath, internalH := pmv1connect.NewInternalServiceHandler(
		internalHandler,
		connect.WithInterceptors(api.NewValidationInterceptor()),
	)

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

// Note: parseFlags / applyEnvOverrides / clampDurations /
// mustValidateConfig live in flags.go.
// ensureAdminUser / maskDatabaseURL live in admin_user.go.
