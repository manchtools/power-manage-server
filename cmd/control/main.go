// Package main provides the control server entry point.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
	"github.com/hibiken/asynq"
	"github.com/oklog/ulid/v2"
	"github.com/redis/go-redis/v9"
	"golang.org/x/net/http2"

	"github.com/manchtools/power-manage/sdk/gen/go/pm/v1/pmv1connect"
	"github.com/manchtools/power-manage/sdk/go/logging"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/api/template"
	"github.com/manchtools/power-manage/server/internal/asynqutil"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/config"
	"github.com/manchtools/power-manage/server/internal/control"
	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/gateway/registry"
	"github.com/manchtools/power-manage/server/internal/middleware"
	"github.com/manchtools/power-manage/server/internal/mtls"
	"github.com/manchtools/power-manage/server/internal/projectors"
	"github.com/manchtools/power-manage/server/internal/scim"
	"github.com/manchtools/power-manage/server/internal/search"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
	"github.com/manchtools/power-manage/server/internal/terminal"
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

	// Initialize secret encryptor
	//
	// rc3 note: previously read unprefixed PM_ENCRYPTION_KEY /
	// PM_ENCRYPTION_KEY_REQUIRED. Now namespaced as
	// CONTROL_ENCRYPTION_KEY / CONTROL_ENCRYPTION_KEY_REQUIRED so all
	// control-server knobs live under one prefix. Operators upgrading
	// from rc2 must rename their .env entries — the old names are no
	// longer read.
	encryptor, err := crypto.NewEncryptor(os.Getenv("CONTROL_ENCRYPTION_KEY"))
	if err != nil {
		logger.Error("failed to initialize encryptor", "error", err)
		os.Exit(1)
	}
	if encryptor == nil {
		// Fail closed: IdP client secrets, LUKS keys, and other
		// secrets-at-rest rely on this encryptor. Running without a
		// key would silently degrade security in production. Operators
		// who truly want unencrypted storage can set
		// CONTROL_ENCRYPTION_KEY_REQUIRED=false to opt in explicitly.
		if os.Getenv("CONTROL_ENCRYPTION_KEY_REQUIRED") == "false" {
			logger.Warn("CONTROL_ENCRYPTION_KEY not set and CONTROL_ENCRYPTION_KEY_REQUIRED=false - secrets will be stored unencrypted")
		} else {
			logger.Error("CONTROL_ENCRYPTION_KEY is required (set CONTROL_ENCRYPTION_KEY_REQUIRED=false to opt out)")
			os.Exit(1)
		}
	}

	// Initialize action signer (signs actions so agents can verify authenticity)
	actionSigner := ca.NewActionSigner(certAuth)

	// Setup Connect-RPC service
	svc := api.NewControlService(st, jwtManager, actionSigner, certAuth, cfg.GatewayURL, logger, encryptor, api.ControlServiceConfig{
		PasswordAuthEnabled: cfg.PasswordAuthEnabled,
		SSOCallbackBaseURL:  cfg.SSOCallbackBaseURL,
		SCIMBaseURL:         cfg.SCIMBaseURL,
	})

	// Seed SSH access for all from env var (one-time: only sets if DB value is still false)
	if v := os.Getenv("CONTROL_SSH_ACCESS_FOR_ALL"); v == "true" || v == "1" {
		settings, err := st.Queries().GetServerSettings(ctx)
		if err == nil && !settings.SshAccessForAll {
			if err := st.AppendEvent(ctx, store.Event{
				StreamType: "server_settings",
				StreamID:   "global",
				EventType:  string(eventtypes.ServerSettingUpdated),
				Data: func() payloads.ServerSettingUpdated {
					provisioning := settings.UserProvisioningEnabled
					sshAll := true
					return payloads.ServerSettingUpdated{
						UserProvisioningEnabled: &provisioning,
						SshAccessForAll:         &sshAll,
					}
				}(),
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

	// rc11 #77: derived-projection wiring for system actions.
	//
	// 1) One-shot startup sweep — guarantees idempotent convergence
	//    on every boot, deploy, or upgrade. Logged at Info because it
	//    runs once.
	// 2) Post-commit event listener — fires SyncUserSystemActions
	//    (or SyncAllUsersSystemActions for fan-out events) on every
	//    permission-shaping event, so handler tests don't need to
	//    know about system actions.
	// 3) Periodic reconciler — durability safety net for the listener,
	//    catches any event whose effect on system actions the
	//    listener doesn't yet know about. Default 1m.
	// Wire every Go-side projector listener in one place. The
	// projectors package owns the list so test fixtures (testutil)
	// and production boot stay in lockstep — adding a new ported
	// projector in #98–#106 only touches projectors.WireAll.
	//
	// Listeners fire synchronously inside Store.AppendEvent (after
	// the event commit, before AppendEvent returns), so handlers
	// see read-your-writes the same as they did under the deleted
	// PL/pgSQL triggers. See WireAll's docstring for the
	// atomicity caveat.
	projectors.WireAll(st, logger)

	if svc.SystemActions() != nil {
		// (1) Startup sweep — keeps the existing Info line so
		// operators see the one-shot convergence in boot logs.
		if err := svc.SystemActions().SyncAllUsersSystemActions(ctx); err != nil {
			logger.Error("failed to sync system actions at startup", "error", err)
		} else {
			logger.Info("system actions synced for all users (startup)")
		}

		// (2) Listener — registered post-commit on the store. Logged
		// errors are swallowed; the periodic reconciler is the
		// durability safety net. Reuse the same per-sweep timeout
		// as the reconciler so a wedged DB / signer can't leak a
		// goroutine indefinitely (#77 review round 2).
		st.RegisterEventListener(api.SystemActionListener(
			svc.SystemActions(),
			logger.With("component", "system_action_listener"),
			cfg.SystemActionReconcileTimeout,
		))

		// (3) Periodic reconciler — interval and per-sweep timeout
		// from config (defaults set in parseFlags).
		svc.SystemActions().StartReconciliation(ctx,
			cfg.SystemActionReconcileInterval,
			cfg.SystemActionReconcileTimeout)
		logger.Info("system-action reconciliation started",
			"interval", cfg.SystemActionReconcileInterval,
			"sweep_timeout", cfg.SystemActionReconcileTimeout)
	}
	// Configure trusted proxies for X-Forwarded-For header validation
	if len(cfg.TrustedProxies) > 0 {
		auth.SetTrustedProxies(cfg.TrustedProxies)
		logger.Info("trusted proxies configured", "proxies", cfg.TrustedProxies)
	}

	// terminalTokenStore is populated below in the Valkey block when
	// remote terminal sessions are configured. Hoisted to the outer
	// scope so the InternalHandler — constructed further down — can
	// share the same store and validate tokens minted by the
	// ControlService.StartTerminal handler.
	var terminalTokenStore *terminal.TokenStore

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

		// Register the store-side search listener so every event that
		// affects the search index funnels through one classifier
		// (api.AffectedSearchOps) instead of scattered handler-side
		// enqueueXxxReindex calls. The handler-side dual-writes for
		// devices and users were removed in audit N005; remaining
		// per-handler enqueues exist only for member-level operations
		// (action_set / definition members) where the source-of-truth
		// is on a relationship table the listener does not classify.
		st.RegisterEventListener(api.SearchListener(st, searchIdx, logger.With("component", "search_listener")))

		// Wire the remote terminal session token store. Tokens live in
		// Valkey under pm:terminal:session:* with a short TTL; minted
		// by ControlService.StartTerminal and consumed by the gateway
		// when the web client opens its WebSocket.
		//
		// In multi-gateway HA, the URL returned to the client must
		// point at the *specific* gateway hosting the device (any
		// other gateway has no way to bridge the WebSocket to the
		// agent). The internal/gateway/registry package looks the
		// device→gateway mapping up in Valkey: each gateway publishes
		// pm:device:gateway:<device_id> on agent connect. The
		// TerminalHandler queries the same registry at mint time.
		//
		// CONTROL_TERMINAL_GATEWAY_URL is retained as a fallback for
		// single-gateway dev deployments where the operator hasn't
		// run the registry-publishing gateway changes yet. In a real
		// multi-gateway deployment, leave it unset.
		//
		// The same TokenStore is also handed to the InternalHandler
		// further down so InternalService.ProxyValidateTerminalToken
		// can validate bearer tokens minted by this same instance.
		// Always create the token store when Valkey is available, even
		// if this node doesn't mint sessions (TerminalGatewayURL empty).
		// The gateway calls ProxyValidateTerminalToken on whichever
		// control replica it reaches, so every node that has Valkey
		// must be able to validate tokens minted by other replicas.
		terminalTokenStore = terminal.NewTokenStore(terminal.NewValkeyBackend(rdb))
		gatewayReg := registry.New(registry.NewValkeyBackend(rdb), logger.With("component", "gateway_registry"))
		termHandler := api.NewTerminalHandler(
			st,
			terminalTokenStore,
			gatewayReg,
			api.GatewayBaseURL(cfg.TerminalGatewayURL),
			logger.With("component", "terminal_handler"),
		)
		// Build an mTLS HTTP client for gateway admin fan-out. The
		// control uses its own cert as the client cert and the CA
		// cert to verify the gateway's server cert — same trust
		// model as the gateway→control direction.
		if cfg.InternalTLSCert != "" && cfg.CACertPath != "" {
			gwCert, err := tls.LoadX509KeyPair(cfg.InternalTLSCert, cfg.InternalTLSKey)
			if err != nil {
				logger.Warn("terminal admin fan-out disabled: failed to load internal TLS key pair",
					"cert", cfg.InternalTLSCert, "key", cfg.InternalTLSKey, "error", err)
			} else {
				caCert, err := os.ReadFile(cfg.CACertPath)
				if err != nil {
					logger.Warn("terminal admin fan-out disabled: failed to read CA certificate",
						"path", cfg.CACertPath, "error", err)
				} else {
					caPool := x509.NewCertPool()
					if !caPool.AppendCertsFromPEM(caCert) {
						logger.Warn("terminal admin fan-out disabled: CA certificate file contained no valid PEM certificates",
							"path", cfg.CACertPath)
					} else {
						gwTransport := &http.Transport{
							TLSClientConfig: &tls.Config{
								Certificates: []tls.Certificate{gwCert},
								RootCAs:      caPool,
								MinVersion:   tls.VersionTLS13,
							},
						}
						termHandler.SetInternalHTTPClient(&http.Client{Transport: gwTransport})
						logger.Info("terminal admin fan-out enabled (mTLS client configured)")
					}
				}
			}
		}
		svc.SetTerminalHandler(termHandler)
		if cfg.TerminalGatewayURL != "" {
			logger.Info("remote terminal sessions enabled",
				"fallback_gateway_url", cfg.TerminalGatewayURL,
				"registry_enabled", true,
			)
		} else {
			logger.Warn("CONTROL_TERMINAL_GATEWAY_URL is empty: this node can validate terminal tokens via registry but will not mint sessions with a static fallback URL")
		}

		// Index audit events on insertion — the hook fires after every AppendEvent
		// and enqueues the persisted row directly (no DB lookup in the search worker).
		// Registered via RegisterEventListener so it shares the listener-slice
		// mutex + panic-recovery wrapper with every other consumer.
		//
		// The EnqueueReindex call itself is dispatched in a goroutine so a slow
		// or unreachable Valkey cannot stall AppendEvent — fireListeners
		// dispatches synchronously, so a blocking listener body would extend
		// every state-changing RPC's tail latency by the Valkey RTT. The work
		// is best-effort (already only logs Warn on failure), so detaching is
		// safe; the goroutine has its own recover so a panic inside the
		// taskqueue client can't crash the server. Round-5 review fix.
		st.RegisterEventListener(func(ctx context.Context, ev store.PersistedEvent) {
			id := ulid.ULID(ev.ID).String()
			data := &taskqueue.SearchEntityData{
				EventType:  ev.EventType,
				StreamType: ev.StreamType,
				ActorType:  ev.ActorType,
				ActorID:    ev.ActorID,
				StreamID:   ev.StreamID,
				OccurredAt: ev.OccurredAt.Unix(),
			}
			// Detach from the AppendEvent ctx — the RPC may already have
			// returned by the time the enqueue runs; cancellation would
			// drop best-effort work that the search worker can otherwise
			// still pick up. Background ctx is correct here because the
			// taskqueue client has its own per-call timeouts.
			go func() {
				defer func() {
					if r := recover(); r != nil {
						logger.Error("audit-index listener: panicked", "id", id, "panic", r)
					}
				}()
				if err := searchIdx.EnqueueReindex(context.Background(), search.ScopeAuditEvent, id, data); err != nil {
					logger.Warn("failed to enqueue audit event reindex", "id", id, "error", err)
				}
			}()
		})

		// Ensure indexes exist (idempotent, needed for FT.SEARCH queries).
		if err := searchIdx.EnsureIndexes(ctx); err != nil {
			logger.Warn("failed to ensure search indexes", "error", err)
		}

		// Build Asynq mux with inbox worker only (search worker runs in indexer binary)
		inboxWorker := control.NewInboxWorker(st, aqClient, actionSigner, logger.With("component", "inbox_worker"))
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

		// rc7: dedicated Asynq server for terminal audit chunks.
		// Concurrency=1 so per-session chunks commit to
		// terminal_sessions.input strictly in sequence order — the
		// AppendTerminalSessionChunk query's last_sequence guard
		// prevents duplicate redeliveries but not two workers racing
		// on different sequences, which would drop the loser's bytes.
		// See taskqueue.ControlTerminalAuditQueue for the full
		// rationale.
		terminalAuditServer := asynq.NewServer(
			asynq.RedisClientOpt{
				Addr:     cfg.ValkeyAddr,
				Password: cfg.ValkeyPassword,
				DB:       cfg.ValkeyDB,
			},
			asynq.Config{
				Concurrency: 1,
				Queues: map[string]int{
					taskqueue.ControlTerminalAuditQueue: 1,
				},
				Logger: asynqutil.NewLogger(aqLogger.With("queue", "terminal_audit")),
				ErrorHandler: asynq.ErrorHandlerFunc(func(ctx context.Context, task *asynq.Task, err error) {
					retried, _ := asynq.GetRetryCount(ctx)
					maxRetry, _ := asynq.GetMaxRetry(ctx)
					aqLogger.Error("terminal audit task handler failed",
						"task_type", task.Type(),
						"error", err,
						"retry", retried,
						"max_retry", maxRetry,
					)
				}),
			},
		)
		if err := terminalAuditServer.Start(inboxWorker.NewTerminalAuditMux()); err != nil {
			logger.Error("failed to start terminal audit Asynq server", "error", err)
			os.Exit(1)
		}
		defer terminalAuditServer.Shutdown()

		logger.Info("Asynq task queue initialized",
			"valkey_addr", cfg.ValkeyAddr,
			"search_enabled", true,
			"terminal_audit_queue", taskqueue.ControlTerminalAuditQueue,
		)
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

	// Mount SCIM v2 handler. Passes svc.SystemActions() so the SCIM
	// delete path can clean up pm-tty-* / USER actions when the
	// last identity link is removed (rc11 #77).
	scimHandler := scim.NewHandler(st, logger, svc.SystemActions())
	mux.Handle("/scim/v2/", scimHandler)

	// Wrap with CORS and security headers middleware
	corsHandler := middleware.CORS(cfg.CORSOrigins, cfg.CORSAllowAll, logger)(mux)
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
			MinVersion:   tls.VersionTLS13,
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
	if terminalTokenStore != nil {
		// Shared with the ControlService.StartTerminal handler so the
		// gateway can validate tokens minted on this instance via
		// ProxyValidateTerminalToken.
		internalHandler.SetTerminalTokenStore(terminalTokenStore)
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
