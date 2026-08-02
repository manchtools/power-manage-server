// Package controlruntime assembles the single control process.
package controlruntime

import (
	"context"
	"crypto/ecdh"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect"

	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/agentsecrets"
	"github.com/manchtools/power-manage/server/internal/agentstream"
	"github.com/manchtools/power-manage/server/internal/agentsync"
	"github.com/manchtools/power-manage/server/internal/assignment"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/authoring"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/compliance"
	"github.com/manchtools/power-manage/server/internal/connection"
	"github.com/manchtools/power-manage/server/internal/controlrpc"
	pmcrypto "github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/delivery"
	"github.com/manchtools/power-manage/server/internal/device"
	"github.com/manchtools/power-manage/server/internal/devicegroup"
	"github.com/manchtools/power-manage/server/internal/dispatch"
	"github.com/manchtools/power-manage/server/internal/enrollment"
	"github.com/manchtools/power-manage/server/internal/execution"
	"github.com/manchtools/power-manage/server/internal/identity"
	"github.com/manchtools/power-manage/server/internal/middleware"
	"github.com/manchtools/power-manage/server/internal/registrationtoken"
	"github.com/manchtools/power-manage/server/internal/scim"
	"github.com/manchtools/power-manage/server/internal/searchrpc"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/terminal"
	"github.com/manchtools/power-manage/server/internal/terminalbridge"
)

const (
	maxControlRequestBytes     = 8 << 20
	maxAgentFrameBytes         = 64 << 20
	requestDeadline            = 30 * time.Second
	heartbeatTelemetryInterval = 2 * time.Minute
)

// Config contains the already-loaded durable dependencies and ordinary
// deployment settings for one control process.
type Config struct {
	Store                    *store.Store
	CA                       *ca.CA
	JWT                      *auth.JWTManager
	AtRest                   *pmcrypto.Encryptor
	ControlSealingPrivateKey *ecdh.PrivateKey
	Logger                   *slog.Logger
	Version                  string
	PublicBaseURL            string
	AgentURL                 string
	TerminalURL              string
	CORSOrigins              []string
	CORSAllowAll             bool
	TerminalOriginPatterns   []string
	TrustedProxies           []string
	HeartbeatInterval        time.Duration
	Now                      func() time.Time
	Readiness                func(context.Context) error
}

// Runtime owns the HTTP surfaces and bounded background dispatcher.
type Runtime struct {
	PublicHandler http.Handler
	AgentHandler  http.Handler
	Connections   *connection.Manager
	Deliveries    *delivery.Dispatcher

	store       *store.Store
	logger      *slog.Logger
	agentStream *agentstream.Handler
	scim        *scim.Handler
	limiters    []*auth.RateLimiter
	close       sync.Once
}

// New wires every retained RPC to its direct domain owner.
func New(cfg Config) *Runtime {
	if cfg.Store == nil || cfg.CA == nil || cfg.JWT == nil || cfg.AtRest == nil ||
		cfg.ControlSealingPrivateKey == nil || cfg.Readiness == nil {
		panic("controlruntime: store, CA, JWT, at-rest cipher, sealing key, and readiness check are required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	manager := connection.NewManager()
	sessions := connection.NewTerminalSessionRegistry()
	tokens := terminal.NewTokenStore(terminal.NewMemoryBackend(cfg.Now), terminal.WithClock(cfg.Now))
	deliveryState := delivery.New(delivery.Config{Store: cfg.Store, Now: cfg.Now})
	dispatcher := delivery.NewDispatcher(delivery.DispatcherConfig{
		Store: cfg.Store, State: deliveryState, Router: manager, Logger: cfg.Logger, Now: cfg.Now,
	})
	executionResults := execution.New(execution.Config{Store: cfg.Store, Now: cfg.Now})
	deviceHandlers := device.New(device.Config{
		Store: cfg.Store, Logger: cfg.Logger, Now: cfg.Now,
		CloseStream: manager.Unregister, AgentSender: manager, Decryptor: cfg.AtRest,
		TerminalTokens: tokens, TerminalSessions: sessions, TerminalURL: cfg.TerminalURL,
		IsConnected: manager.IsConnected,
	})
	secretService := agentsecrets.New(agentsecrets.Config{
		Store: cfg.Store, AtRest: cfg.AtRest, ControlSealingPrivateKey: cfg.ControlSealingPrivateKey, Now: cfg.Now,
	})
	syncService := agentsync.New(agentsync.Config{Store: cfg.Store, Manager: manager, Deliveries: deliveryState})
	agentService := agentstream.New(agentstream.Config{
		Store: cfg.Store, Manager: manager, Deliveries: deliveryState, Executions: executionResults,
		DeviceResults: deviceHandlers, Secrets: secretService, Sync: syncService, Waker: dispatcher,
		TerminalSessions: sessions, Logger: cfg.Logger, ServerVersion: cfg.Version,
		HeartbeatInterval: cfg.HeartbeatInterval, Now: cfg.Now,
	})

	limiters, ownedLimiters := defaultRateLimiters()
	bootstrap := identity.NewBootstrapper(cfg.Store, cfg.PublicBaseURL, identity.DefaultBootstrapTokenTTL, cfg.Now)
	authentication := auth.NewAuthInterceptor(cfg.Logger, cfg.JWT, limiters,
		auth.NewRejectionRecorder(cfg.Store)).WithBootstrapAuthenticator(bootstrap)
	controlOptions := []connect.HandlerOption{
		connect.WithInterceptors(
			identity.NewValidationInterceptor(),
			metadataLoggingInterceptor(cfg.Logger, cfg.Now),
			deadlineInterceptor(requestDeadline),
			authentication,
			auth.NewAuthzInterceptor(),
		),
		connect.WithReadMaxBytes(maxControlRequestBytes),
	}

	publicMux := http.NewServeMux()
	controlrpc.Handlers{
		Identity: identity.New(identity.Config{
			Store: cfg.Store, Logger: cfg.Logger, JWT: cfg.JWT, KEK: cfg.AtRest,
			PublicBaseURL: cfg.PublicBaseURL, Now: cfg.Now,
		}),
		Enrollment: enrollment.New(enrollment.Config{
			Store: cfg.Store, CA: cfg.CA, Logger: cfg.Logger, Now: cfg.Now,
			ControlURL: cfg.AgentURL, ControlSealingPublicKey: cfg.ControlSealingPrivateKey.PublicKey().Bytes(),
			CloseStream: manager.Unregister,
		}),
		Authoring:          authoring.NewHandlers(authoring.HandlersConfig{Store: cfg.Store, Logger: cfg.Logger, Now: cfg.Now}),
		Assignments:        assignment.New(assignment.Config{Store: cfg.Store, Logger: cfg.Logger, Now: cfg.Now}),
		DeviceGroups:       devicegroup.NewHandlers(devicegroup.HandlersConfig{Store: cfg.Store, Logger: cfg.Logger, Now: cfg.Now}),
		Devices:            deviceHandlers,
		RegistrationTokens: registrationtoken.New(registrationtoken.Config{Store: cfg.Store, Logger: cfg.Logger, Now: cfg.Now}),
		Compliance:         compliance.NewHandlers(compliance.HandlersConfig{Store: cfg.Store, Logger: cfg.Logger, Now: cfg.Now}),
		Dispatch:           dispatch.NewHandlers(dispatch.HandlersConfig{Store: cfg.Store, Waker: dispatcher, Logger: cfg.Logger, Now: cfg.Now}),
		Search:             searchrpc.NewHandlers(cfg.Store, cfg.Logger, cfg.Now),
	}.Mount(publicMux, controlOptions...)

	scimHandler := scim.New(scim.Config{Store: cfg.Store, Logger: cfg.Logger, KEK: cfg.AtRest, Now: cfg.Now})
	scimHandler.Mount(publicMux)
	publicMux.Handle("/terminal", terminalbridge.New(terminalbridge.Config{
		Manager: manager, Sessions: sessions, Tokens: tokens, Store: cfg.Store, Logger: cfg.Logger,
		OriginPatterns: cfg.TerminalOriginPatterns, Now: cfg.Now,
	}))
	publicMux.HandleFunc("/health", health)
	publicMux.HandleFunc("/ready", readinessHandler(cfg.Readiness))
	auth.SetTrustedProxies(cfg.TrustedProxies)
	publicHandler := middleware.RequestID(middleware.SecurityHeaders(
		middleware.CORS(cfg.CORSOrigins, cfg.CORSAllowAll, cfg.Logger)(publicMux)))

	agentPath, directAgentHandler := powermanagev1connect.NewAgentServiceHandler(
		agentService, connect.WithReadMaxBytes(maxAgentFrameBytes))
	agentMux := http.NewServeMux()
	agentMux.Handle(agentPath, agentstream.MTLSMiddleware(directAgentHandler,
		store.NewRevocationChecker(cfg.Store), cfg.Logger))
	agentMux.HandleFunc("/health", health)
	agentMux.HandleFunc("/ready", readinessHandler(cfg.Readiness))

	return &Runtime{
		PublicHandler: publicHandler, AgentHandler: agentMux, Connections: manager,
		Deliveries: dispatcher, scim: scimHandler, limiters: ownedLimiters,
		store: cfg.Store, logger: cfg.Logger, agentStream: agentService,
	}
}

// Run blocks until ctx is cancelled while the durable delivery sweep and
// coalesced heartbeat telemetry flush run.
func (r *Runtime) Run(ctx context.Context) error {
	if ctx == nil || r == nil || r.Deliveries == nil || r.store == nil || r.Connections == nil {
		return errors.New("control runtime is not initialized")
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.flushHeartbeatTelemetry(runCtx)
	}()
	err := r.Deliveries.Run(runCtx)
	cancel()
	<-done
	return err
}

func (r *Runtime) flushHeartbeatTelemetry(ctx context.Context) {
	ticker := time.NewTicker(heartbeatTelemetryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			snapshot := r.Connections.LastSeenSnapshot()
			if len(snapshot) == 0 {
				continue
			}
			if err := r.store.RecordHeartbeatTelemetry(ctx, snapshot); err != nil && !errors.Is(err, context.Canceled) {
				r.logger.Error("persist heartbeat telemetry", "devices", len(snapshot), "error", err)
			}
		}
	}
}

// Close releases process-local rate limiter and SCIM resources.
func (r *Runtime) Close() {
	if r == nil {
		return
	}
	r.close.Do(func() {
		if r.agentStream != nil {
			r.agentStream.Close()
		}
		if r.scim != nil {
			r.scim.Close()
		}
		for _, limiter := range r.limiters {
			limiter.Stop()
		}
	})
}

func health(response http.ResponseWriter, _ *http.Request) {
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write([]byte("ok"))
}

func readinessHandler(check func(context.Context) error) http.HandlerFunc {
	return func(response http.ResponseWriter, request *http.Request) {
		if err := check(request.Context()); err != nil {
			http.Error(response, "not ready", http.StatusServiceUnavailable)
			return
		}
		health(response, request)
	}
}

func defaultRateLimiters() (auth.RateLimiters, []*auth.RateLimiter) {
	newLimiter := func(requests int) *auth.RateLimiter { return auth.NewRateLimiter(requests, time.Minute) }
	limiters := auth.RateLimiters{
		SSOCallback: newLimiter(10), Refresh: newLimiter(60), Register: newLimiter(5),
		RenewCert: newLimiter(5), Logout: newLimiter(30), AuthMethods: newLimiter(30),
		SSO: newLimiter(10), Authenticated: newLimiter(600), Expensive: newLimiter(60),
		Rejected: newLimiter(20),
	}
	owned := []*auth.RateLimiter{
		limiters.SSOCallback, limiters.Refresh, limiters.Register, limiters.RenewCert,
		limiters.Logout, limiters.AuthMethods, limiters.SSO, limiters.Authenticated,
		limiters.Expensive, limiters.Rejected,
	}
	return limiters, owned
}

func deadlineInterceptor(limit time.Duration) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, request connect.AnyRequest) (connect.AnyResponse, error) {
			ctx, cancel := context.WithTimeout(ctx, limit)
			defer cancel()
			return next(ctx, request)
		}
	}
}

func metadataLoggingInterceptor(logger *slog.Logger, now func() time.Time) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, request connect.AnyRequest) (connect.AnyResponse, error) {
			started := now()
			response, err := next(ctx, request)
			attrs := []any{"procedure", request.Spec().Procedure, "duration_ms", now().Sub(started).Milliseconds()}
			if err == nil {
				logger.Debug("rpc complete", attrs...)
				return response, nil
			}
			attrs = append(attrs, "code", connect.CodeOf(err).String())
			logger.Warn("rpc rejected", attrs...)
			return response, err
		}
	}
}
