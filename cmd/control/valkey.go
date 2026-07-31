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
	"errors"
	"fmt"
	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"log/slog"
	"os"
	"time"

	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hibiken/asynq"
	"github.com/redis/go-redis/v9"

	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/asynqutil"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/connection"
	"github.com/manchtools/power-manage/server/internal/control"
	"github.com/manchtools/power-manage/server/internal/datastore"
	"github.com/manchtools/power-manage/server/internal/devicedispatch"
	"github.com/manchtools/power-manage/server/internal/search"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
	"github.com/manchtools/power-manage/server/internal/terminal"
)

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

	// WorkerMgr runs the per-device Asynq consumer for dispatches. It lives here
	// because it needs this subsystem's Valkey options.
	//
	// The connection manager and terminal-session registry deliberately do NOT:
	// they are plain in-memory maps over live streams with no Valkey dependency,
	// and control must hold them whether or not a queue exists. Keeping them
	// here made a nil subsystem a nil-pointer panic at boot, and would have tied
	// the agent transport to a dependency that workstream B removes.
	WorkerMgr *devicedispatch.DeviceWorkerManager

	// TerminalTokenStore is exported because main() hands it to the
	// InternalHandler later in the boot sequence — they MUST share
	// one instance so ProxyValidateTerminalToken can validate tokens
	// minted by the same control replica.
	TerminalTokenStore *terminal.TokenStore
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

// newValkeySubsystem builds the entire Valkey-backed subsystem and wires it
// into svc as side effects.
//
// The nil,nil return for an empty ValkeyAddr is now unreachable in production:
// validateConfig rejects that configuration at boot, because control terminates
// agent streams through this subsystem and cannot serve anything without it.
// The branch stays as a guard for direct callers in tests.
//
// Errors at the asynq.Start step partially-initialised components
// are unwound by deferred Close on the returned subsystem; callers
// MUST defer Close() on the returned value before checking err.
func newValkeySubsystem(ctx context.Context, cfg *Config, st *store.Store, svc *api.ControlService, actionSigner ca.ActionSigner, connMgr *connection.Manager, sessions *connection.TerminalSessionRegistry, logger *slog.Logger) (*valkeySubsystem, error) {
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

	// spec 32: the client-cert TLS config every control→Valkey connection
	// presents. nil when no cert paths are configured (dev/plaintext); boot
	// enforces its presence separately when datastore mTLS is required.
	valkeyTLS, err := valkeyClientTLS(cfg)
	if err != nil {
		return nil, fmt.Errorf("configure valkey mTLS: %w", err)
	}
	if valkeyTLS == nil {
		// spec 32: no plaintext fallback. If Valkey is configured it must be over
		// mutual TLS — the ACL user's password is worthless without the client cert.
		return nil, errors.New("datastore mTLS is required when CONTROL_VALKEY_ADDR is set (spec 32): set CONTROL_VALKEY_TLS_CERT/KEY/CA")
	}

	v := &valkeySubsystem{taskSigner: taskSigner}
	v.aqClient = taskqueue.NewSecureClient(asynq.RedisClientOpt{
		Addr:      cfg.ValkeyAddr,
		Username:  cfg.ValkeyUsername,
		Password:  cfg.ValkeyPassword,
		DB:        cfg.ValkeyDB,
		TLSConfig: valkeyTLS,
	}, taskSigner)
	svc.SetTaskQueueClient(v.aqClient)

	// Force RESP2 protocol: go-redis v9 auto-negotiates RESP3 with Redis 7+,
	// but RediSearch returns FT.SEARCH results in a different format under
	// RESP3 (map vs array), which breaks our result parser.
	v.rdb = redis.NewClient(&redis.Options{
		Addr:      cfg.ValkeyAddr,
		Username:  cfg.ValkeyUsername,
		Password:  cfg.ValkeyPassword,
		DB:        cfg.ValkeyDB,
		Protocol:  2,
		TLSConfig: valkeyTLS,
		// 30s (vs the 3s default) so the admin-triggered RebuildSearchIndex —
		// which bulk-warms every scope — tolerates valkey-search indexing
		// latency on a modest host instead of failing with "i/o timeout".
		ReadTimeout: 30 * time.Second,
	})

	// Agent-stream infrastructure. The per-device worker consumes that device's
	// dispatch queue, so it needs the same Valkey connection options the client
	// above uses.
	taskFactory := devicedispatch.NewTaskHandlerFactory(connMgr, v.taskSigner, logger.With("component", "device_task"))
	v.WorkerMgr = devicedispatch.NewDeviceWorkerManager(
		asynq.RedisClientOpt{
			Addr:      cfg.ValkeyAddr,
			Username:  cfg.ValkeyUsername,
			Password:  cfg.ValkeyPassword,
			DB:        cfg.ValkeyDB,
			TLSConfig: valkeyTLS,
		},
		taskFactory.NewMux,
		logger.With("component", "device_worker"),
	)

	searchIdx := search.New(v.rdb, st, v.aqClient, logger.With("component", "search"))
	svc.SetSearchIndex(searchIdx)

	// Store-side search listener — see search.go for the rationale.
	st.RegisterEventListener(api.SearchListener(st, searchIdx, logger.With("component", "search_listener")))

	v.TerminalTokenStore = terminal.NewTokenStore(terminal.NewValkeyBackend(v.rdb))
	// Certificate revocation is no longer a Valkey-published list: control
	// terminates agent mTLS itself and queries revoked_certificates during the
	// handshake, so there is nothing to distribute and no cache to warm.
	//
	// The device→gateway registry is gone for the same reason — it answered
	// "which gateway holds this device", and control holds every stream.
	termHandler := api.NewTerminalHandler(
		st,
		v.TerminalTokenStore,
		api.TerminalBaseURL(cfg.TerminalPublicURL),
		logger.With("component", "terminal_handler"),
	)
	// Wire the transport the handler needs. Constructing TerminalHandler is not
	// enough: without this every terminal RPC returns Unavailable, because the
	// seams default to nil and the handler fails closed on them by design.
	termHandler.SetTerminalTransport(
		func(_ context.Context) ([]*pm.TerminalSessionInfo, error) {
			live := sessions.List()
			out := make([]*pm.TerminalSessionInfo, 0, len(live))
			for _, s := range live {
				out = append(out, &pm.TerminalSessionInfo{
					SessionId:      s.SessionID,
					UserId:         s.UserID,
					DeviceId:       s.DeviceID,
					TtyUser:        s.TtyUser,
					StartedAt:      timestamppb.New(s.StartedAt),
					LastActivityAt: timestamppb.New(s.LastActivity()),
				})
			}
			return out, nil
		},
		func(_ context.Context, deviceID, sessionID, reason string) (bool, error) {
			// found reports whether the session was actually here. Absent is not
			// an error — it ended with its stream — but it must be
			// distinguishable, or an operator is told a root shell closed when
			// nothing was closed.
			if sessions.Get(sessionID) == nil {
				return false, nil
			}
			err := connMgr.Send(deviceID, &pm.ServerMessage{
				Id: ulid.Make().String(),
				Payload: &pm.ServerMessage_TerminalStop{
					TerminalStop: &pm.TerminalStop{SessionId: sessionID, Reason: reason},
				},
			})
			if err != nil {
				return false, err
			}
			return true, nil
		},
		connMgr.IsConnected,
	)

	svc.SetTerminalHandler(termHandler)

	// Close a user's live terminal sessions when their terminal access is
	// revoked — UserDisabled/UserDeleted (all access gone), or a UserRoleRevoked
	// that removed their last StartTerminal grant (#391) — otherwise a revoked
	// user keeps a root-capable shell until they disconnect (audit l.174). The
	// gateway fan-out (and the permission recheck) run in the background so they
	// never block the disable/delete/revoke.
	st.RegisterEventListener(api.TerminalRevocationListener(termHandler, st.Repos().User, logger.With("component", "terminal_revocation")))

	if cfg.TerminalPublicURL != "" {
		logger.Info("remote terminal sessions enabled", "terminal_url", cfg.TerminalPublicURL)
	} else {
		logger.Warn("CONTROL_TERMINAL_URL is empty: StartTerminal will return Unavailable on this node")
	}

	// Audit-event index hook — see audit_index.go for the rationale.
	st.RegisterEventListener(auditIndexListener(searchIdx, logger))

	if err := searchIdx.EnsureIndexes(ctx); err != nil {
		logger.Warn("failed to ensure search indexes", "error", err)
	}

	// Asynq mux + servers.
	inboxWorker := control.NewInboxWorker(st, v.aqClient, actionSigner, v.taskSigner, logger.With("component", "inbox_worker"))
	aqLogger := logger.With("component", "asynq_server")
	v.inboxServer = newInboxAsynqServer(cfg, valkeyTLS, aqLogger)
	if err := v.inboxServer.Start(inboxWorker.NewMux()); err != nil {
		return v, fmt.Errorf("start inbox asynq server: %w", err)
	}

	v.terminalAuditServer = newTerminalAuditAsynqServer(cfg, valkeyTLS, aqLogger)
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

// auditIndexListener returns an event listener that enqueues every
// persisted event for indexing into the audit-event search index.
// The enqueue runs in a detached goroutine because fireListeners
// dispatches synchronously — a slow Valkey would otherwise extend
// every state-changing RPC's tail latency by the Valkey RTT. The
// listener has its own panic-recovery wrapper so a taskqueue-client
// panic can't crash the server. (Round-5 review fix.)
func auditIndexListener(idx *search.Index, logger *slog.Logger) store.EventListener {
	return func(_ context.Context, ev store.PersistedEvent) {
		id := ev.ID
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

// valkeyClientTLS builds the client-cert TLS config every control→Valkey
// connection presents (spec 32). Returns nil when no cert paths are set
// (dev/plaintext), a config when all three are set, or an error when the set is
// partial (fail closed). Control boot separately requires a non-nil result when
// datastore mTLS is mandatory.
func valkeyClientTLS(cfg *Config) (*tls.Config, error) {
	return datastore.ValkeyClientTLSFromFiles(cfg.ValkeyTLSCert, cfg.ValkeyTLSKey, cfg.ValkeyTLSCA)
}

func newInboxAsynqServer(cfg *Config, tlsCfg *tls.Config, logger *slog.Logger) *asynq.Server {
	return asynq.NewServer(
		asynq.RedisClientOpt{
			Addr:      cfg.ValkeyAddr,
			Username:  cfg.ValkeyUsername,
			Password:  cfg.ValkeyPassword,
			DB:        cfg.ValkeyDB,
			TLSConfig: tlsCfg,
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
func newTerminalAuditAsynqServer(cfg *Config, tlsCfg *tls.Config, logger *slog.Logger) *asynq.Server {
	auditLog := logger.With("queue", "terminal_audit")
	return asynq.NewServer(
		asynq.RedisClientOpt{
			Addr:      cfg.ValkeyAddr,
			Username:  cfg.ValkeyUsername,
			Password:  cfg.ValkeyPassword,
			DB:        cfg.ValkeyDB,
			TLSConfig: tlsCfg,
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
