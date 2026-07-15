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

	"github.com/manchtools/power-manage-sdk/gen/go/pm/v1/pmv1connect"
	"github.com/manchtools/power-manage-sdk/logging"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/archive"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/datastore"
	"github.com/manchtools/power-manage/server/internal/inventorysched"
	"github.com/manchtools/power-manage/server/internal/middleware"
	"github.com/manchtools/power-manage/server/internal/mtls"
	"github.com/manchtools/power-manage/server/internal/pii"
	"github.com/manchtools/power-manage/server/internal/projectors"
	"github.com/manchtools/power-manage/server/internal/retention"
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

	// Gateway self-enrollment (spec 31). The shared bootstrap token a gateway
	// presents to GatewayAuthService.EnrollGateway. Empty disables enrollment
	// (every attempt is rejected). PM_GATEWAY_ENROLL_TOKEN — a cross-service
	// secret shared with the gateway (same PM_* convention as PM_TASK_SIGNING_KEY).
	GatewayEnrollToken string

	// CORS
	CORSAllowAll bool // Allow all origins (development only)

	// Valkey (Asynq task queue)
	ValkeyAddr     string
	ValkeyPassword string
	ValkeyDB       int
	// Datastore mutual-TLS + per-service ACL (spec 32): ACL user + client-cert
	// material for connecting to Valkey over mTLS. Control boot requires them
	// (fail closed) once spec 32 lands; empty on pre-spec-32 deployments.
	ValkeyUsername string
	ValkeyTLSCert  string
	ValkeyTLSKey   string
	ValkeyTLSCA    string

	// rc11 #77: derived-projection reconciler for system actions.
	// Interval is the period between full SyncAllUsersSystemActions
	// sweeps (safety net for the post-commit listener); 0 disables
	// the periodic goroutine entirely. Timeout is the per-sweep
	// context deadline so a hung query can't pile up missed ticks.
	SystemActionReconcileInterval time.Duration
	SystemActionReconcileTimeout  time.Duration

	// Spec 19 audit-log retention (env-only config by decision — no
	// RPC/UI surface). Retention.Enabled activates the rolling
	// snapshot+prune worker; validation is fatal at boot (a destructive
	// feature must never run on a half-read config).
	Retention retention.EnvConfig

	// Spec 22: server-side inventory collection scheduler. Default
	// true; CONTROL_INVENTORY_SCHEDULER_ENABLED=false is the escape
	// hatch for change-frozen environments that must not run osquery
	// on a cadence (manual RefreshDeviceInventory and the
	// inventory_overdue computation are unaffected).
	InventorySchedulerEnabled bool
}

func main() {
	// `control doctor` is a standalone, read-only stack-health pass
	// (#322). It must run WITHOUT booting the server, so it intercepts before
	// parseFlags (which would choke on the positional subcommand).
	// docref: begin doctor-subcommand
	if len(os.Args) > 1 && os.Args[1] == "doctor" {
		os.Exit(runDoctor(os.Args[2:]))
	}
	// docref: end doctor-subcommand

	// `control rebuild-projections [target…]` is the operator entry point
	// for the emergency projection replay (spec 21 / #505). Like doctor it
	// intercepts before parseFlags and never boots the server.
	// docref: begin rebuild-subcommand
	if len(os.Args) > 1 && os.Args[1] == "rebuild-projections" {
		os.Exit(runRebuildProjections(os.Args[2:]))
	}
	// docref: end rebuild-subcommand

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

	// spec 32: datastore access is mutual-TLS only — no plaintext fallback.
	// Fail closed here (require a verify-full DSN carrying client-cert material)
	// so a misconfigured deployment aborts rather than reaching Postgres in the
	// clear. setup.sh provisions the certs and the verify-full DSN.
	if err := datastore.RequirePostgresTLS(cfg.DatabaseURL); err != nil {
		logger.Error("datastore mTLS required (spec 32)", "error", err)
		os.Exit(1)
	}

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

	// Sweep expired SSO auth_states (spec 29 S3). They are otherwise deleted only
	// on a successful Consume, so an unauthenticated GetSSOLoginURL flood would
	// grow the table unboundedly. Same 1h cadence as the revocation sweep.
	go runPeriodic(ctx, 1*time.Hour, func() {
		if err := st.Queries().CleanupExpiredAuthStates(ctx); err != nil {
			logger.Error("failed to cleanup expired SSO auth states", "error", err)
		}
	}, false)

	if cfg.DynamicGroupEvalInterval > 0 {
		logger.Info("starting dynamic group evaluation worker", "interval", cfg.DynamicGroupEvalInterval)
		startDynamicGroupWorker(ctx, st, cfg.DynamicGroupEvalInterval, logger)
	} else {
		logger.Info("dynamic group evaluation worker disabled")
	}

	startStaleExecutionExpiry(ctx, st, logger, time.Now)

	// Spec 19 audit-log retention: rolling snapshot + prune of the event
	// log. Config was validated at parse time (fatal on violation); the
	// archive store and worker construction are fatal too — a destructive
	// worker either boots correctly or the server does not boot.
	if cfg.Retention.Enabled {
		arch, err := archive.New(cfg.Retention.ArchiveConfig())
		if err != nil {
			logger.Error("failed to initialize retention archive store", "error", err)
			os.Exit(1)
		}
		if err := startRetentionWorker(ctx, st, arch, cfg.Retention, logger); err != nil {
			logger.Error("failed to start retention worker", "error", err)
			os.Exit(1)
		}
		logger.Info("audit-log retention enabled",
			"window", cfg.Retention.Window, "interval", cfg.Retention.Interval, "archive_path", cfg.Retention.ArchivePath)
	} else {
		logger.Info("audit-log retention disabled (CONTROL_RETENTION_ENABLED=false); the event log grows unbounded")
	}

	// Start periodic cleanup of stale OSQuery results
	go runPeriodic(ctx, 5*time.Minute, func() {
		if err := st.Queries().DeleteOldOSQueryResults(ctx); err != nil {
			logger.Error("failed to cleanup old osquery results", "error", err)
		}
	}, false)

	// Initialize secret encryptor. CONTROL_ENCRYPTION_KEY is MANDATORY —
	// the former CONTROL_ENCRYPTION_KEY_REQUIRED=false plaintext opt-out was
	// removed (WS11 #4); a missing key is a fatal boot error so secrets at
	// rest can never be stored unencrypted, even by accident.
	encryptor, err := initEncryptor(logger)
	if err != nil {
		logger.Error("failed to initialize encryptor", "error", err)
		os.Exit(1)
	}

	// Spec 19: PII envelope encryption. The sealer encrypts pii-tagged
	// payload fields under the subject user's DEK at append (fail-closed
	// — plaintext PII never reaches the immutable log); the opener
	// decrypts at projection-build time. Wired BEFORE any bootstrap
	// event emission (ensureAdminUser below) so the very first user
	// event is already sealed.
	piiSealer, err := pii.NewSealer(encryptor, st.Repos().UserEncryptionKey)
	if err != nil {
		logger.Error("failed to initialize PII sealer", "error", err)
		os.Exit(1)
	}
	st.SetPIISealer(piiSealer)
	piiMinter, err := pii.NewMinter(encryptor, st.Repos().UserEncryptionKey)
	if err != nil {
		logger.Error("failed to initialize PII minter", "error", err)
		os.Exit(1)
	}
	st.SetPIIMinter(piiMinter)
	piiOpener, err := pii.NewOpener(encryptor, st.Repos().UserEncryptionKey)
	if err != nil {
		logger.Error("failed to initialize PII opener", "error", err)
		os.Exit(1)
	}
	projectors.SetPIIOpener(piiOpener)

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

	// Spec 22: server-side inventory collection scheduler. Requests
	// signed inventory from stale connected devices once per fixed
	// tick; policy (device override > group min > 24h default) lives
	// in the projections. AC 10: the escape hatch logs one boot line
	// and starts nothing — manual RefreshDeviceInventory and the
	// inventory_overdue computation are unaffected.
	if !cfg.InventorySchedulerEnabled {
		logger.Info("inventory collection scheduler disabled (CONTROL_INVENTORY_SCHEDULER_ENABLED=false); inventory refresh is manual-only")
	} else if valkey == nil {
		logger.Warn("inventory collection scheduler enabled but no task queue configured (CONTROL_VALKEY_ADDR empty) — scheduler not started")
	} else {
		startInventoryScheduleWorker(ctx, st, valkey.aqClient, actionSigner, logger)
		logger.Info("inventory collection scheduler enabled",
			"tick", inventorysched.Tick, "default_interval_minutes", inventorysched.DefaultIntervalMinutes)
	}

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
		GetCRL:      auth.NewRateLimiter(30, 1*time.Minute), // agent CRL fetch — generous headroom over the legitimate few-per-hour cadence (retries, many agents behind one NAT)
		AuthMethods: auth.NewRateLimiter(30, 1*time.Minute), // unauth email-lookup oracle — bound bulk enumeration
		SSO:         auth.NewRateLimiter(10, 1*time.Minute), // expensive unauth endpoint (DB write + outbound discovery)
		// WS11 #6 — per-USER ceilings on authenticated control RPCs (keyed by
		// user ID, not IP). Authenticated is a generous general ceiling
		// (~10 rps sustained per user) that bounds a stolen token / runaway
		// client; Expensive is a tighter ceiling applied on top for the
		// self-discovered heavy set (query evaluation, search, rebuild,
		// log/osquery fan-out).
		Authenticated: auth.NewRateLimiter(600, 1*time.Minute),
		Expensive:     auth.NewRateLimiter(60, 1*time.Minute),
	}

	interceptors := connect.WithInterceptors(
		api.NewLoggingInterceptor(logger),
		// Bound every unary handler's wall-clock (WS13 #10). Backstops the DB
		// statement_timeout for non-DB blocking; streaming passes through.
		api.NewRequestDeadlineInterceptor(api.RequestDeadline),
		auth.NewAuthInterceptor(logger, jwtManager, rateLimiters),
		api.NewValidationInterceptor(),
		auth.NewAuthzInterceptor(),
	)

	// controlMaxRequestBytes bounds how much of a single request body the
	// control server will buffer before the handler runs (WS13 #4). Without it,
	// an UNAUTHENTICATED caller (Login/Register are public) could stream an
	// arbitrarily large body and force unbounded allocation pre-auth. 8 MiB is
	// generous for control-plane JSON/proto (including a FILE/SHELL action's
	// embedded content) while still bounding the pre-auth buffer.
	const controlMaxRequestBytes = 8 << 20

	mux := http.NewServeMux()
	path, handler := pmv1connect.NewControlServiceHandler(svc, interceptors, connect.WithReadMaxBytes(controlMaxRequestBytes))
	mux.Handle(path, handler)

	// GatewayAuthService (spec 31): public, token-gated gateway self-enrollment.
	// Mounted WITHOUT the auth/authz interceptors (like InternalService) — it
	// has no JWT and self-gates on the bootstrap token + a per-IP rate limiter in
	// the handler, so a foreign-service procedure never enters ControlService's
	// PublicProcedures allow-list. Validation + logging + deadline still apply.
	gatewayAuthInterceptors := connect.WithInterceptors(
		api.NewLoggingInterceptor(logger),
		api.NewRequestDeadlineInterceptor(api.RequestDeadline),
		api.NewValidationInterceptor(),
	)
	gatewayEnrollLimiter := auth.NewRateLimiter(5, 1*time.Minute) // 5/min/IP (spec 31 AC4)
	gatewayAuthHandler := api.NewGatewayAuthHandler(st, certAuth, cfg.GatewayEnrollToken, gatewayEnrollLimiter, logger.With("component", "gateway_auth"))
	gwAuthPath, gwAuthHandler := pmv1connect.NewGatewayAuthServiceHandler(gatewayAuthHandler, gatewayAuthInterceptors, connect.WithReadMaxBytes(controlMaxRequestBytes))
	mux.Handle(gwAuthPath, gwAuthHandler)
	if cfg.GatewayEnrollToken == "" {
		logger.Warn("gateway self-enrollment disabled: PM_GATEWAY_ENROLL_TOKEN is empty — every EnrollGateway attempt will be rejected")
	}

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

	// LPS sealing keypair: event-sourced (#495) — the version-1 OCC append on
	// the lps_keypair/global stream is the cross-replica first-writer-wins,
	// and the lps_keypair row is a projection. MUST run after
	// wireSystemActions → projectors.WireAll (the #317 ordering): the
	// synchronous LpsKeypairListener materialises the projection row during
	// the append. The agent seals rotated LPS passwords to this public key so
	// the gateway relays them opaquely; control unseals at receipt (spec 18).
	// A failure here is fatal — running without it would silently disable LPS
	// rotation on every agent (fail closed).
	lpsPriv, lpsPub, err := api.EnsureLpsKeypair(ctx, st, encryptor)
	if err != nil {
		logger.Error("failed to initialize LPS sealing keypair", "error", err)
		os.Exit(1)
	}
	signedLpsPub, err := api.BuildSignedLpsPublicKey(lpsPub, actionSigner)
	if err != nil {
		logger.Error("failed to sign LPS public key for distribution", "error", err)
		os.Exit(1)
	}
	internalHandler.SetLpsKeypair(lpsPriv, signedLpsPub)

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
	// spec 31: the gateway-cert renewal path needs the CA (to re-sign) and the
	// CRL (to revoke the superseded fingerprint). The CA is always available; the
	// CRL only when Valkey is configured — renewal still works without it, just
	// skipping the best-effort superseded-cert revocation. The typed nil keeps
	// main.go free of a crl import.
	if valkey != nil {
		internalHandler.SetGatewayRenewal(certAuth, valkey.CRLStore)
	} else {
		internalHandler.SetGatewayRenewal(certAuth, nil)
	}
	internalPath, internalH := pmv1connect.NewInternalServiceHandler(
		internalHandler,
		connect.WithInterceptors(api.NewValidationInterceptor()),
		connect.WithReadMaxBytes(controlMaxRequestBytes),
	)

	// Peer-class gate: InternalService handles credential-bearing
	// proxy calls (LUKS keys, LPS passwords). A compromised agent
	// cert must NOT be usable here — only gateway replicas, which
	// present certs issued out of band by setup.sh with a spiffe://
	// peer-class URI, are admitted.
	// Revocation gate on the internal listener (WS12 #2): a revoked gateway
	// cert must not be able to call the credential-bearing proxy RPCs. With
	// Valkey the loaded CRL cache backs it; a no-Valkey dev control server has
	// no CRL, so it gets the explicit, WARN-logged NoopRevocationChecker rather
	// than a silent nil (which would fail closed and break the dev path).
	var internalRevocation mtls.RevocationChecker
	if valkey != nil && valkey.CRLCache != nil {
		internalRevocation = valkey.CRLCache
	} else {
		logger.Warn("InternalService mTLS listener running WITHOUT certificate revocation (no Valkey CRL configured) — dev only")
		internalRevocation = mtls.NoopRevocationChecker{}
	}
	internalMux := http.NewServeMux()
	// WithPeerCert (inside the class/revocation gate) injects the authenticated
	// gateway peer cert into the request context so RenewGatewayCertificate can
	// read the gateway_id from the peer cert CN (spec 31), not a request field.
	internalMux.Handle(internalPath, mtls.RequirePeerClassNotRevoked(logger, internalRevocation, mtls.PeerClassGateway)(mtls.WithPeerCert(internalH)))
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
