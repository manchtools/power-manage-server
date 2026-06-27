// Valkey/Asynq subsystem extracted from main.go (audit F043 / #157,
// slice 4). Bundles the four interconnected pieces that are only
// constructed when CONTROL_VALKEY_ADDR is set:
//
//  1. taskqueue.Client (per-device dispatch + control-inbox enqueue)
//  2. go-redis client + RediSearch index
//  3. terminal token store + gateway registry + terminal handler
//     (with optional mTLS HTTP client for admin fan-out)
//  4. two Asynq servers (control:inbox + control:terminal_audit)
//
// As side effects, the subsystem mutates `svc` via SetTaskQueueClient,
// SetSearchIndex, and SetTerminalHandler; that matches the pre-extract
// behaviour and avoids a second round of plumbing in main(). The
// returned subsystem holds the references main() needs for shutdown
// (deferred Close) plus the terminal token store the InternalHandler
// is wired to share later.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/hibiken/asynq"
	"github.com/oklog/ulid/v2"
	"github.com/redis/go-redis/v9"

	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/asynqutil"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/control"
	"github.com/manchtools/power-manage/server/internal/crl"
	"github.com/manchtools/power-manage/server/internal/gateway/registry"
	"github.com/manchtools/power-manage/server/internal/search"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
	"github.com/manchtools/power-manage/server/internal/terminal"
)

// controlCRLRefreshInterval is how often the control server reloads the CRL
// cache that gates its InternalService mTLS listener. Matches the gateway's
// cadence; revocations propagate to the internal plane within one interval.
const controlCRLRefreshInterval = 30 * time.Second

// valkeySubsystem owns every long-lived component constructed when
// the operator configures Valkey. Close() unwinds them in reverse
// construction order; nil components are skipped so a partial-init
// failure (asynq.Start returning an error) doesn't crash the cleanup.
type valkeySubsystem struct {
	aqClient            *taskqueue.Client
	rdb                 *redis.Client
	inboxServer         *asynq.Server
	terminalAuditServer *asynq.Server

	// taskSigner is the HMAC signer threaded into the Asynq Client
	// (producer side) AND the InboxWorker / TerminalAudit mux
	// (consumer side). Both sides MUST share the same key — the
	// signer is constructed once here so a misconfiguration loud-
	// fails at boot rather than producing tasks the consumer can't
	// verify (audit F-02).
	taskSigner *taskqueue.Signer

	// TerminalTokenStore is exported because main() hands it to the
	// InternalHandler later in the boot sequence — they MUST share
	// one instance so ProxyValidateTerminalToken can validate tokens
	// minted by the same control replica.
	TerminalTokenStore *terminal.TokenStore

	// CRLStore is the Valkey-backed certificate revocation list. main() hands
	// it to the ControlService so renewal/device-deletion revoke the old cert;
	// gateways read the same Valkey key to enforce it on mTLS connections.
	CRLStore *crl.Store

	// CRLCache is a loaded, in-memory snapshot of CRLStore used to gate the
	// InternalService mTLS listener (WS12 #2: a revoked gateway cert must not
	// be able to call ProxyGetLuksKey / ProxyStoreLpsPasswords). It is loaded
	// synchronously at subsystem init — a failed initial load fails the whole
	// subsystem (fail-closed, mirroring the gateway's boot).
	CRLCache *crl.Cache

	// GatewayRegistry is the device→gateway routing registry. main() hands it to
	// the InternalHandler (SetDeviceGatewayResolver) so every device-origin
	// InternalService request is confined to the gateway the device is live on
	// (server#403). The same registry backs terminal URL lookup + fan-out.
	GatewayRegistry *registry.Registry
}

// Close stops the Asynq servers and closes the Valkey clients.
// Idempotent and nil-safe — partial init failures still call this.
func (v *valkeySubsystem) Close() {
	if v == nil {
		return
	}
	if v.terminalAuditServer != nil {
		v.terminalAuditServer.Shutdown()
	}
	if v.inboxServer != nil {
		v.inboxServer.Shutdown()
	}
	if v.rdb != nil {
		_ = v.rdb.Close()
	}
	if v.aqClient != nil {
		v.aqClient.Close()
	}
}

// newValkeySubsystem builds the entire Valkey-backed subsystem and
// wires it into svc as side effects (matches the pre-extract main()
// behaviour). Returns nil + nil when cfg.ValkeyAddr is empty so
// callers can unconditionally invoke this function and let cfg
// drive feature gating.
//
// Errors at the asynq.Start step partially-initialised components
// are unwound by deferred Close on the returned subsystem; callers
// MUST defer Close() on the returned value before checking err.
func newValkeySubsystem(ctx context.Context, cfg *Config, st *store.Store, svc *api.ControlService, actionSigner ca.ActionSigner, logger *slog.Logger) (*valkeySubsystem, error) {
	if cfg.ValkeyAddr == "" {
		return nil, nil
	}

	// Load the Asynq-payload HMAC signer (audit F-02). The hex key
	// is operator-provided via PM_TASK_SIGNING_KEY and must match
	// across every service that participates in the Asynq fan-out
	// (control, gateway, indexer). NewSigner returns (nil, nil) on
	// an empty key string for test ergonomics, but production wiring
	// rejects that here so a deployment can't accidentally turn
	// signing off.
	taskSigner, err := taskqueue.NewSigner(os.Getenv("PM_TASK_SIGNING_KEY"))
	if err != nil {
		return nil, fmt.Errorf("load task signer: %w", err)
	}
	if taskSigner == nil {
		return nil, errors.New("PM_TASK_SIGNING_KEY is required when CONTROL_VALKEY_ADDR is set (audit F-02 — task signing is mandatory)")
	}

	v := &valkeySubsystem{taskSigner: taskSigner}
	v.aqClient = taskqueue.NewClientWithSigner(cfg.ValkeyAddr, cfg.ValkeyPassword, cfg.ValkeyDB, taskSigner)
	svc.SetTaskQueueClient(v.aqClient)

	// Force RESP2 protocol: go-redis v9 auto-negotiates RESP3 with Redis 7+,
	// but RediSearch returns FT.SEARCH results in a different format under
	// RESP3 (map vs array), which breaks our result parser.
	v.rdb = redis.NewClient(&redis.Options{
		Addr:     cfg.ValkeyAddr,
		Password: cfg.ValkeyPassword,
		DB:       cfg.ValkeyDB,
		Protocol: 2,
		// 30s (vs the 3s default) so the admin-triggered RebuildSearchIndex —
		// which bulk-warms every scope — tolerates valkey-search indexing
		// latency on a modest host instead of failing with "i/o timeout".
		ReadTimeout: 30 * time.Second,
	})

	searchIdx := search.New(v.rdb, st, v.aqClient, logger.With("component", "search"))
	svc.SetSearchIndex(searchIdx)

	// Store-side search listener — see search.go for the rationale.
	st.RegisterEventListener(api.SearchListener(st, searchIdx, logger.With("component", "search_listener")))

	v.TerminalTokenStore = terminal.NewTokenStore(terminal.NewValkeyBackend(v.rdb))
	v.CRLStore = crl.NewStore(v.rdb)
	svc.SetCRLStore(v.CRLStore)
	// Load the CRL cache that gates the InternalService mTLS listener. Fail the
	// subsystem if the initial load errors — symmetry with the gateway's
	// fail-closed boot: never admit gateway certs against an unloaded CRL.
	v.CRLCache = crl.NewCache(v.CRLStore, logger.With("component", "crl"))
	if err := v.CRLCache.Refresh(ctx); err != nil {
		return nil, fmt.Errorf("initial CRL load failed (refusing to start the internal mTLS listener without a loaded revocation list): %w", err)
	}
	go v.CRLCache.Run(ctx, controlCRLRefreshInterval)
	gatewayReg := registry.New(registry.NewValkeyBackend(v.rdb), logger.With("component", "gateway_registry"))
	v.GatewayRegistry = gatewayReg
	termHandler := api.NewTerminalHandler(
		st,
		v.TerminalTokenStore,
		gatewayReg,
		api.GatewayBaseURL(cfg.TerminalGatewayURL),
		logger.With("component", "terminal_handler"),
	)
	if err := configureTerminalAdminFanout(cfg, termHandler, logger); err != nil {
		// Fan-out is best-effort — log warn (already done inside the
		// helper) but don't fail the subsystem. Single-gateway
		// deployments don't need fan-out at all.
		_ = err
	}
	svc.SetTerminalHandler(termHandler)

	// Close a user's live terminal sessions when their terminal access is
	// revoked — UserDisabled/UserDeleted (all access gone), or a UserRoleRevoked
	// that removed their last StartTerminal grant (#391) — otherwise a revoked
	// user keeps a root-capable shell until they disconnect (audit l.174). The
	// gateway fan-out (and the permission recheck) run in the background so they
	// never block the disable/delete/revoke.
	st.RegisterEventListener(api.TerminalRevocationListener(termHandler, st.Repos().User, logger.With("component", "terminal_revocation")))

	if cfg.TerminalGatewayURL != "" {
		logger.Info("remote terminal sessions enabled",
			"fallback_gateway_url", cfg.TerminalGatewayURL,
			"registry_enabled", true,
		)
	} else {
		logger.Warn("CONTROL_TERMINAL_GATEWAY_URL is empty: this node can validate terminal tokens via registry but will not mint sessions with a static fallback URL")
	}

	// Audit-event index hook — see audit_index.go for the rationale.
	st.RegisterEventListener(auditIndexListener(searchIdx, logger))

	if err := searchIdx.EnsureIndexes(ctx); err != nil {
		logger.Warn("failed to ensure search indexes", "error", err)
	}

	// Asynq mux + servers.
	inboxWorker := control.NewInboxWorker(st, v.aqClient, actionSigner, v.taskSigner, logger.With("component", "inbox_worker"), gatewayReg)
	aqLogger := logger.With("component", "asynq_server")
	v.inboxServer = newInboxAsynqServer(cfg, aqLogger)
	if err := v.inboxServer.Start(inboxWorker.NewMux()); err != nil {
		return v, fmt.Errorf("start inbox asynq server: %w", err)
	}

	v.terminalAuditServer = newTerminalAuditAsynqServer(cfg, aqLogger)
	if err := v.terminalAuditServer.Start(inboxWorker.NewTerminalAuditMux()); err != nil {
		return v, fmt.Errorf("start terminal audit asynq server: %w", err)
	}

	logger.Info("Asynq task queue initialized",
		"valkey_addr", cfg.ValkeyAddr,
		"search_enabled", true,
		"terminal_audit_queue", taskqueue.ControlTerminalAuditQueue,
	)
	return v, nil
}

// configureTerminalAdminFanout builds the mTLS HTTP client the
// TerminalHandler uses for gateway admin fan-out (cancel-session
// across replicas). The control uses its own internal cert as the
// client cert and the CA cert to verify the gateway's server cert
// — same trust model as gateway→control.
//
// Returns a non-nil error when cert / CA loading fails so callers
// can choose to bail or warn-and-continue. main() warns: a missing
// internal cert is normal in single-gateway deployments and must
// not fail boot.
func configureTerminalAdminFanout(cfg *Config, termHandler *api.TerminalHandler, logger *slog.Logger) error {
	if cfg.InternalTLSCert == "" || cfg.CACertPath == "" {
		return nil
	}
	gwCert, err := tls.LoadX509KeyPair(cfg.InternalTLSCert, cfg.InternalTLSKey)
	if err != nil {
		logger.Warn("terminal admin fan-out disabled: failed to load internal TLS key pair",
			"cert", cfg.InternalTLSCert, "key", cfg.InternalTLSKey, "error", err)
		return err
	}
	caCert, err := os.ReadFile(cfg.CACertPath)
	if err != nil {
		logger.Warn("terminal admin fan-out disabled: failed to read CA certificate",
			"path", cfg.CACertPath, "error", err)
		return err
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		logger.Warn("terminal admin fan-out disabled: CA certificate file contained no valid PEM certificates",
			"path", cfg.CACertPath)
		return errors.New("CA bundle contained no valid PEM certificates")
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{gwCert},
			RootCAs:      caPool,
			MinVersion:   tls.VersionTLS13,
		},
	}
	// A client-level Timeout backstops the per-call context deadlines on the
	// terminal admin fan-out (WS11 #8) so a half-open connection to a gateway
	// can't pin a request goroutine indefinitely.
	termHandler.SetInternalHTTPClient(&http.Client{Transport: transport, Timeout: 30 * time.Second})
	logger.Info("terminal admin fan-out enabled (mTLS client configured)")
	return nil
}

// auditIndexListener returns an event listener that enqueues every
// persisted event for indexing into the audit-event search index.
// The enqueue runs in a detached goroutine because fireListeners
// dispatches synchronously — a slow Valkey would otherwise extend
// every state-changing RPC's tail latency by the Valkey RTT. The
// listener has its own panic-recovery wrapper so a taskqueue-client
// panic can't crash the server. (Round-5 review fix.)
func auditIndexListener(idx *search.Index, logger *slog.Logger) store.EventListener {
	return func(_ context.Context, ev store.PersistedEvent) {
		id := ulid.ULID(ev.ID).String()
		data := &taskqueue.SearchEntityData{
			EventType:  ev.EventType,
			StreamType: ev.StreamType,
			ActorType:  ev.ActorType,
			ActorID:    ev.ActorID,
			StreamID:   ev.StreamID,
			OccurredAt: ev.OccurredAt.Unix(),
		}
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Error("audit-index listener: panicked", "id", id, "panic", r)
				}
			}()
			if err := idx.EnqueueReindex(context.Background(), search.ScopeAuditEvent, id, data); err != nil {
				logger.Warn("failed to enqueue audit event reindex", "id", id, "error", err)
			}
		}()
	}
}

func newInboxAsynqServer(cfg *Config, logger *slog.Logger) *asynq.Server {
	return asynq.NewServer(
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
			Logger:       asynqutil.NewLogger(logger),
			ErrorHandler: asynqErrorLogger(logger, "task handler failed"),
		},
	)
}

// newTerminalAuditAsynqServer: rc7 dedicated terminal-audit consumer.
// Concurrency=1 so per-session chunks commit to terminal_sessions.input
// strictly in sequence order — the AppendTerminalSessionChunk query's
// last_sequence guard prevents duplicate redeliveries but not two
// workers racing on different sequences (which would drop the loser's
// bytes). See taskqueue.ControlTerminalAuditQueue for full rationale.
func newTerminalAuditAsynqServer(cfg *Config, logger *slog.Logger) *asynq.Server {
	auditLog := logger.With("queue", "terminal_audit")
	return asynq.NewServer(
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
			Logger:       asynqutil.NewLogger(auditLog),
			ErrorHandler: asynqErrorLogger(auditLog, "terminal audit task handler failed"),
		},
	)
}

func asynqErrorLogger(logger *slog.Logger, msg string) asynq.ErrorHandlerFunc {
	return func(ctx context.Context, task *asynq.Task, err error) {
		retried, _ := asynq.GetRetryCount(ctx)
		maxRetry, _ := asynq.GetMaxRetry(ctx)
		logger.Error(msg,
			"task_type", task.Type(),
			"error", err,
			"retry", retried,
			"max_retry", maxRetry,
		)
	}
}
