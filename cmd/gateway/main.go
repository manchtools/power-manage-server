// Gateway server handles agent connections and forwards messages via Asynq (Valkey).
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/redis/go-redis/v9"
	"golang.org/x/net/http2"

	"github.com/manchtools/power-manage/sdk/gen/go/pm/v1/pmv1connect"
	"github.com/manchtools/power-manage/sdk/go/logging"
	"github.com/manchtools/power-manage/server/internal/config"
	"github.com/manchtools/power-manage/server/internal/connection"
	"github.com/manchtools/power-manage/server/internal/gateway"
	"github.com/manchtools/power-manage/server/internal/gateway/registry"
	"github.com/manchtools/power-manage/server/internal/handler"
	"github.com/manchtools/power-manage/server/internal/middleware"
	"github.com/manchtools/power-manage/server/internal/mtls"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

// version is set at build time via -ldflags.
var version = "dev"

func main() {
	// Parse flags — TLS is always required for mTLS agent connections
	tlsCert := flag.String("tls-cert", "", "path to server certificate (required)")
	tlsKey := flag.String("tls-key", "", "path to server private key (required)")
	tlsCA := flag.String("tls-ca", "", "path to CA certificate for client validation (required)")
	flag.Parse()

	if *tlsCert == "" || *tlsKey == "" || *tlsCA == "" {
		fmt.Fprintln(os.Stderr, "FATAL: -tls-cert, -tls-key, and -tls-ca flags are required")
		os.Exit(1)
	}

	// Load config from environment
	cfg := config.FromEnv()

	// Setup logger
	logger := logging.SetupLogger(cfg.LogLevel, "json", os.Stdout)
	slog.SetDefault(logger)

	// Config-shape checks that don't fit the simple "required env
	// var empty" pattern below (TTY/MTLS host collision, etc.).
	// Failing here keeps them visible at startup rather than at the
	// first affected request.
	if err := cfg.Validate(); err != nil {
		logger.Error("invalid gateway configuration", "error", err)
		os.Exit(1)
	}

	// Validate required config
	if cfg.ValkeyAddr == "" {
		logger.Error("GATEWAY_VALKEY_ADDR is required")
		os.Exit(1)
	}
	if cfg.ControlURL == "" {
		logger.Error("GATEWAY_CONTROL_URL is required")
		os.Exit(1)
	}
	controlURL, err := url.Parse(cfg.ControlURL)
	if err != nil || controlURL.Scheme != "https" {
		logger.Error("GATEWAY_CONTROL_URL must use https for the internal mTLS control connection", "control_url", cfg.ControlURL, "error", err)
		os.Exit(1)
	}

	// Create Asynq task queue client
	aqClient := taskqueue.NewClient(cfg.ValkeyAddr, cfg.ValkeyPassword, cfg.ValkeyDB)
	defer aqClient.Close()
	logger.Info("task queue client initialized", "valkey_addr", cfg.ValkeyAddr)

	// Create control proxy (Connect-RPC client to control server's InternalService)
	// Uses mTLS to authenticate with the control server's internal listener.
	controlCert, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
	if err != nil {
		logger.Error("failed to load gateway certificate for control proxy", "error", err)
		os.Exit(1)
	}
	caCert, err := os.ReadFile(*tlsCA)
	if err != nil {
		logger.Error("failed to read CA certificate for control proxy", "error", err)
		os.Exit(1)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		logger.Error("failed to parse CA certificate for control proxy")
		os.Exit(1)
	}
	controlTransport := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{controlCert},
			RootCAs:      caPool,
			MinVersion:   tls.VersionTLS13,
		},
	}
	http2.ConfigureTransport(controlTransport)
	controlHTTPClient := &http.Client{Transport: controlTransport}
	controlProxy := handler.NewControlProxy(controlHTTPClient, cfg.ControlURL)
	logger.Info("control proxy initialized", "control_url", cfg.ControlURL)

	// Create connection manager
	manager := connection.NewManager()

	// Create task handler factory for per-device Asynq workers
	taskFactory := gateway.NewTaskHandlerFactory(manager, logger)

	// Create device worker manager
	workerMgr := gateway.NewDeviceWorkerManager(
		cfg.ValkeyAddr, cfg.ValkeyPassword, cfg.ValkeyDB,
		taskFactory.NewMux,
		logger.With("component", "device_worker"),
	)
	defer workerMgr.StopAll()

	// Resolve this gateway's stable ID. If GATEWAY_ID is set, use it
	// (static-config Traefik setups where the operator pre-declares
	// per-gateway routes). Otherwise generate a ULID at startup
	// (dynamic-config setups where Traefik picks up new routes from
	// a watcher / file provider / k8s ingress automatically).
	gatewayID := cfg.GatewayID
	if gatewayID == "" {
		gatewayID = ulid.Make().String()
		logger.Info("generated dynamic gateway ID", "gateway_id", gatewayID)
	} else {
		logger.Info("using configured gateway ID", "gateway_id", gatewayID)
	}

	// Declare the shutdown signal ctx up-front so downstream goroutines
	// (registry refresh, internal-URL refresh) can derive from it and
	// exit cleanly on SIGTERM/SIGINT rather than ticking past shutdown.
	shutdownCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Wire the multi-gateway registry lazily. The registry is shared by
	// three independent features:
	//   - terminal URL lookup for browser sessions,
	//   - internal gateway fan-out for control -> gateway RPCs,
	//   - Traefik Redis-KV self-registration.
	//
	// Keep those code paths independent. A malformed optional terminal
	// URL must not prevent agent mTLS routing or internal gateway
	// discovery from coming up.
	var (
		gatewayReg   *registry.Registry
		registryRDB  *redis.Client
		assignedHost string
	)
	ensureGatewayRegistry := func() *registry.Registry {
		if gatewayReg != nil {
			return gatewayReg
		}
		registryRDB = redis.NewClient(&redis.Options{
			Addr:     cfg.ValkeyAddr,
			Password: cfg.ValkeyPassword,
			DB:       cfg.ValkeyDB,
			Protocol: 2,
		})
		gatewayReg = registry.New(registry.NewValkeyBackend(registryRDB), logger.With("component", "registry"))
		return gatewayReg
	}
	defer func() {
		if registryRDB != nil {
			if err := registryRDB.Close(); err != nil {
				logger.Warn("failed to close gateway registry Valkey client", "error", err)
			}
		}
	}()

	// Compute the agent redirect hostname independently of the terminal
	// URL. This supports multi-gateway agent routing without requiring
	// the terminal feature to be enabled.
	//
	// A malformed template (e.g. one that references an unset env var
	// like ${TTY_DOMAIN} and expands to "https:///…" with an empty host)
	// is treated as "bootstrap redirects disabled" with a loud warning
	// rather than a fatal exit. The gateway still serves agent mTLS —
	// which is what matters for an enrolled device. Crashing on a
	// misconfigured optional feature used to kill the gateway on every
	// restart, and because the Traefik Redis KV entry expires 45 s after
	// each exit, the pm-mtls TCP router fell through to the HTTP router
	// on the shared :443 and served the Let's Encrypt cert — giving
	// agents the misleading x509 "unknown authority" error.
	// Track whether the agent URL template was *configured* separately
	// from whether it *resolved*. Without this split, a malformed
	// template (e.g. "https://${UNSET_VAR}" → "https://") leaves
	// assignedHost empty and the terminal-template block below would
	// silently paper over the misconfiguration by substituting the TTY
	// host — re-enabling bootstrap redirects to the wrong hostname.
	// Operators who explicitly set GATEWAY_PUBLIC_AGENT_URL_TEMPLATE
	// want the feature off when the template is broken, not fallen-
	// back to a different URL.
	agentURLTemplateConfigured := cfg.PublicAgentURLTemplate != ""
	if agentURLTemplateConfigured {
		agentURL := strings.ReplaceAll(cfg.PublicAgentURLTemplate, "{id}", gatewayID)
		assignedHost = hostFromURL(agentURL)
		if assignedHost == "" {
			logger.Warn("GATEWAY_PUBLIC_AGENT_URL_TEMPLATE resolved to a URL with no host — bootstrap redirects disabled; check for unset env vars in the template",
				"template", cfg.PublicAgentURLTemplate, "resolved", agentURL)
		}
	}

	if cfg.PublicTerminalURLTemplate != "" {
		// Substitute {id} in the URL template. The template is the
		// public WebSocket URL operators want clients to use; the
		// gateway never constructs hostnames from the request side.
		terminalURL := strings.ReplaceAll(cfg.PublicTerminalURLTemplate, "{id}", gatewayID)

		terminalHost := hostFromURL(terminalURL)
		if terminalHost == "" {
			// Malformed template — skip the registry work instead of
			// os.Exit(1). See the long comment above the agent-template
			// check for why this has to be non-fatal.
			logger.Warn("GATEWAY_PUBLIC_TERMINAL_URL_TEMPLATE resolved to a URL with no host — terminal session registration disabled on this gateway; check for unset env vars in the template",
				"template", cfg.PublicTerminalURLTemplate, "resolved", terminalURL)
		} else {
			// Legacy single-hostname fallback: only substitute the
			// terminal host when NO agent template was configured.
			// If the operator set the agent template and it
			// resolved to a broken URL, respect their intent to
			// disable bootstrap redirects rather than silently
			// masking the misconfiguration with the TTY host.
			if assignedHost == "" && !agentURLTemplateConfigured {
				assignedHost = terminalHost
			}

			gatewayReg = ensureGatewayRegistry()
			// Match the 5s bound used on the other Redis-touching
			// calls in this file (PublishTraefikRoute,
			// RegisterGatewayInternal). Without it, a slow or hung
			// Valkey at startup stalls gateway boot past the point
			// where SIGTERM should be respected. The refresh
			// goroutine stop() returned from RegisterGateway carries
			// its own shutdown wiring, so the bound only affects the
			// one-shot register at line 242.
			registerCtx, cancelRegister := context.WithTimeout(shutdownCtx, 5*time.Second)
			stop, err := gatewayReg.RegisterGateway(
				registerCtx,
				gatewayID,
				terminalURL,
				registry.DefaultGatewayTTL,
				registry.DefaultGatewayRefreshInterval,
			)
			cancelRegister()
			if err != nil {
				// Fail-open: the terminal feature is optional, so a
				// transient registry failure at startup must not kill
				// the gateway's agent-mTLS service. Log loudly and
				// leave terminal sessions disabled for this replica
				// until the operator restarts.
				logger.Warn("failed to register gateway in terminal registry — terminal sessions disabled on this replica",
					"error", err)
			} else {
				defer stop()
				logger.Info("multi-gateway routing enabled",
					"gateway_id", gatewayID,
					"terminal_url", terminalURL,
					"agent_redirect_host", assignedHost,
				)
			}
		}
	}

	// Traefik Redis-KV self-registration. Opt-in; when enabled, every
	// replica writes its own routing entry into the same Valkey
	// instance Traefik watches via `--providers.redis`, so scaling the
	// gateway deployment does not require hand-edited labels or per-
	// replica public DNS entries. The shared pm-mtls TCP router is
	// load-balanced across all replicas; each replica owns a unique
	// /gw/<id> path prefix on the shared tty host for TTY routing.
	if cfg.TraefikSelfRegister {
		// Need a Valkey-backed registry even when terminal URLs are
		// disabled; Traefik self-registration is the agent mTLS
		// routing layer. ensureGatewayRegistry is idempotent, so an
		// outer nil check would be noise.
		gatewayReg = ensureGatewayRegistry()

		// Auto-derive per-replica backend addresses when not set. We use
		// the replica's own routable IP on the shared Docker/k8s network
		// rather than os.Hostname(): the container's default hostname is
		// its 12-char container ID, which is NOT registered in Docker's
		// embedded DNS, so Traefik can't resolve it. The IP works on the
		// pm-internal network Traefik shares with us, and the operator
		// only has to set the public Host/EntryPoint values.
		mtlsBackend := cfg.TraefikMTLSBackend
		ttyBackend := cfg.TraefikTTYBackend
		if mtlsBackend == "" || ttyBackend == "" {
			ip, err := routableIP()
			if err != nil {
				// Fail-open: the operator can still publish a manual
				// backend via GATEWAY_TRAEFIK_{MTLS,TTY}_BACKEND, so
				// missing auto-derivation is not fatal. If nothing is
				// set we skip Traefik publication entirely below and
				// the gateway keeps serving agent mTLS on whatever
				// static route already points at it.
				logger.Warn("cannot auto-derive Traefik backends from network interfaces — set GATEWAY_TRAEFIK_{MTLS,TTY}_BACKEND explicitly if self-registration is needed",
					"error", err)
			} else {
				if mtlsBackend == "" {
					mtlsBackend = ip + portOfListenAddr(cfg.ListenAddr)
				}
				if ttyBackend == "" && cfg.WebListenAddr != "" {
					ttyBackend = "http://" + ip + portOfListenAddr(cfg.WebListenAddr)
				}
			}
		}

		// Publish only when we actually have a usable mTLS backend —
		// an empty backend in the Redis KV entry would poison the
		// pm-mtls TCP router for every replica.
		if mtlsBackend == "" {
			logger.Warn("Traefik self-registration skipped — no MTLS backend available (routable-IP auto-derive failed and GATEWAY_TRAEFIK_MTLS_BACKEND is unset)")
		} else {
			traefikCfg := registry.TraefikRouteConfig{
				RootKey:         cfg.TraefikRootKey,
				MTLSHost:        cfg.TraefikMTLSHost,
				MTLSBackend:     mtlsBackend,
				MTLSEntryPoint:  cfg.TraefikMTLSEntryPoint,
				TTYHost:         cfg.TraefikTTYHost,
				TTYBackend:      ttyBackend,
				TTYEntryPoint:   cfg.TraefikTTYEntryPoint,
				TTYCertResolver: cfg.TraefikTTYCertResolver,
			}

			// Bound the publish with shutdownCtx + a 5s timeout so a
			// slow Redis can't stall startup, and the same bound is
			// used on refresh so shutdown is prompt even during a
			// hung publish.
			publishCtx, cancelPublish := context.WithTimeout(shutdownCtx, 5*time.Second)
			err := gatewayReg.PublishTraefikRoute(
				publishCtx, gatewayID, traefikCfg, registry.DefaultGatewayTTL,
			)
			cancelPublish()
			if err != nil {
				// Fail-open: the refresh goroutine below retries on
				// the normal cadence, so a transient publish failure
				// at startup recovers within one refresh interval.
				// Killing the gateway used to be worse — the Redis
				// KV entry expired during the restart backoff and
				// Traefik fell through to the HTTP router (wrong
				// cert). Log loudly and keep serving agent mTLS.
				logger.Warn("failed to publish initial Traefik routing config — refresh goroutine will retry",
					"error", err)
			}

			// Refresh on the same cadence as the gateway terminal URL
			// so both keys share a lifecycle. Derive from shutdownCtx
			// so the goroutine exits cleanly on SIGTERM.
			traefikRefreshCtx, stopTraefikRefresh := context.WithCancel(shutdownCtx)
			defer stopTraefikRefresh()
			go func() {
				ticker := time.NewTicker(registry.DefaultGatewayRefreshInterval)
				defer ticker.Stop()
				for {
					select {
					case <-ticker.C:
						refreshCtx, cancelRefresh := context.WithTimeout(traefikRefreshCtx, 5*time.Second)
						err := gatewayReg.PublishTraefikRoute(
							refreshCtx, gatewayID, traefikCfg, registry.DefaultGatewayTTL,
						)
						cancelRefresh()
						if err != nil {
							logger.Warn("failed to refresh Traefik routing config", "error", err)
						}
					case <-traefikRefreshCtx.Done():
						return
					}
				}
			}()

			// Clean shutdown revokes only per-replica keys so other
			// replicas' routes stay up. Uses a bounded context so a
			// flaky Valkey can't stall the shutdown.
			defer func() {
				cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := gatewayReg.RevokeTraefikRoute(cleanupCtx, gatewayID, traefikCfg); err != nil {
					logger.Warn("failed to revoke Traefik routing config", "error", err)
				}
			}()

			// Surface whether the initial publish succeeded. After a
			// Valkey wobble the refresh loop will self-heal within
			// one DefaultGatewayRefreshInterval, but an operator
			// reading the log right after startup should be able to
			// tell "registered now" from "will retry in N seconds"
			// without having to cross-reference the Warn line above.
			logger.Info("traefik self-registration enabled",
				"gateway_id", gatewayID,
				"initial_publish_ok", err == nil,
				"mtls_host", cfg.TraefikMTLSHost,
				"mtls_backend", mtlsBackend,
				"tty_host", cfg.TraefikTTYHost,
				"tty_backend", ttyBackend,
				"tty_cert_resolver", cfg.TraefikTTYCertResolver,
			)
		}
	}

	// Publish the internal mTLS URL so the control server can discover
	// this gateway for admin fan-out (List/Terminate terminal sessions).
	// This is intentionally independent of terminal URL registration:
	// a bad optional public terminal URL (which may have left
	// gatewayReg unset) should not disable the internal control-plane
	// route. ensureGatewayRegistry is idempotent — if the Traefik
	// block above already created the registry, this is a no-op; if
	// terminal + Traefik are both off, this is where the registry
	// gets built so admin fan-out still works.
	gatewayReg = ensureGatewayRegistry()
	{
		internalURL := cfg.InternalURL
		if internalURL == "" {
			ip, err := routableIP()
			if err != nil {
				// Fail-open: the internal URL feeds the admin
				// fan-out path (List/Terminate terminal sessions).
				// It is strictly optional for agent mTLS service.
				// Crashing the gateway here would take the agent
				// routing layer down with it, which is exactly the
				// rc8 failure mode we're fixing. Log and move on.
				logger.Warn("cannot auto-derive GATEWAY_INTERNAL_URL — admin fan-out disabled for this replica; set GATEWAY_INTERNAL_URL explicitly to re-enable",
					"error", err)
			} else {
				internalURL = "https://" + ip + portOfListenAddr(cfg.ListenAddr)
				logger.Info("auto-derived GATEWAY_INTERNAL_URL", "internal_url", internalURL)
			}
		}
		if internalURL != "" {
			// Bound both the initial register and the periodic
			// refresh with shutdownCtx + 5s so a slow Redis can't
			// delay shutdown or pile up goroutines waiting on the
			// registry during degraded Valkey health.
			registerCtx, cancelRegister := context.WithTimeout(shutdownCtx, 5*time.Second)
			err := gatewayReg.RegisterGatewayInternal(
				registerCtx, gatewayID, internalURL, registry.DefaultGatewayTTL,
			)
			cancelRegister()
			if err != nil {
				logger.Warn("failed to register gateway internal URL", "error", err)
			}
			internalRefreshCtx, stopInternalRefresh := context.WithCancel(shutdownCtx)
			defer stopInternalRefresh()
			go func() {
				ticker := time.NewTicker(registry.DefaultGatewayRefreshInterval)
				defer ticker.Stop()
				for {
					select {
					case <-ticker.C:
						refreshCtx, cancelRefresh := context.WithTimeout(internalRefreshCtx, 5*time.Second)
						err := gatewayReg.RegisterGatewayInternal(
							refreshCtx, gatewayID, internalURL, registry.DefaultGatewayTTL,
						)
						cancelRefresh()
						if err != nil {
							logger.Warn("failed to refresh gateway internal URL", "error", err)
						}
					case <-internalRefreshCtx.Done():
						return
					}
				}
			}()
		}
	}

	// If BootstrapHost is set but no assignedHost is available
	// (because both agent + terminal URL templates were empty or
	// malformed), disable the bootstrap-redirect middleware instead
	// of crashing. Agent mTLS still works — operators just lose the
	// convenience redirect that points newly-enrolled agents at a
	// stable per-gateway hostname.
	bootstrapHost := cfg.BootstrapHost
	if bootstrapHost != "" && assignedHost == "" {
		logger.Warn("GATEWAY_BOOTSTRAP_HOST is set but no assigned host could be derived from GATEWAY_PUBLIC_AGENT_URL_TEMPLATE / GATEWAY_PUBLIC_TERMINAL_URL_TEMPLATE — bootstrap redirects disabled",
			"bootstrap_host", bootstrapHost)
		bootstrapHost = "" // disable middleware below
	}

	// Terminal session registry — shared between the agent bidi
	// stream handler (routes TerminalOutput/StateChange to the
	// matching bridge) and the WebSocket bridge handler (registers/
	// unregisters sessions and reads output). Also used by the
	// GatewayService for admin list/terminate.
	terminalSessions := connection.NewTerminalSessionRegistry()

	logger.Info("gateway started", "version", version)

	// Setup HTTP mux for agent connections (mTLS-protected)
	mux := http.NewServeMux()

	// Create agent handler (always mTLS). gatewayReg is always non-nil
	// by this point — ensureGatewayRegistry() is called unconditionally
	// in the internal-URL block above — so no guard on SetGatewayRouting.
	agentHandler := handler.NewAgentHandlerWithTLS(manager, aqClient, controlProxy, workerMgr, version, cfg.HeartbeatInterval, logger)
	agentHandler.SetGatewayRouting(gatewayReg, gatewayID)
	agentHandler.SetTerminalSessions(terminalSessions)
	path, h := pmv1connect.NewAgentServiceHandler(agentHandler)

	// Compose middlewares (innermost first):
	//   pmv1connect handler
	//     ↑ MTLSMiddleware (extracts device ID from client cert)
	//     ↑ BootstrapRedirectMiddleware (returns 307 to assignedHost
	//       when the request landed on the wildcard root via LB)
	mtlsHandler := handler.MTLSMiddleware(h, logger)
	bootstrappedHandler := handler.BootstrapRedirectMiddleware(mtlsHandler, bootstrapHost, assignedHost, logger)
	mux.Handle(path, bootstrappedHandler)

	// Mount GatewayService on the mTLS listener (internal-only,
	// called by the control server for admin list/terminate fan-
	// out). Peer-class gate: only the control server's cert (which
	// setup.sh stamps with spiffe://power-manage/control) is
	// admitted — an agent cert that happens to chain to the same
	// internal CA cannot invoke admin fan-out RPCs.
	gwSvcHandler := handler.NewGatewayServiceHandler(terminalSessions, manager, logger.With("component", "gateway_service"))
	gwSvcPath, gwSvcH := pmv1connect.NewGatewayServiceHandler(gwSvcHandler)
	mux.Handle(gwSvcPath, mtls.RequirePeerClass(logger, mtls.PeerClassControl)(gwSvcH))

	// Wrap with security headers
	securedMux := middleware.RequestID(middleware.SecurityHeaders(mux))

	// Separate mux for health checks (accessible without mTLS)
	opsMux := http.NewServeMux()
	opsMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"healthy","agents":%d}`, manager.Count())
	})
	opsMux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// Create mTLS server
	tlsConfig, err := mtls.NewTLSConfig(mtls.Config{
		CertFile: *tlsCert,
		KeyFile:  *tlsKey,
		CAFile:   *tlsCA,
	})
	if err != nil {
		logger.Error("failed to configure TLS", "error", err)
		os.Exit(1)
	}

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           securedMux,
		TLSConfig:         tlsConfig,
		ReadTimeout:       0,
		WriteTimeout:      0,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
	}

	if err := http2.ConfigureServer(server, &http2.Server{}); err != nil {
		logger.Error("failed to configure HTTP/2", "error", err)
		os.Exit(1)
	}

	// Start ops server (health checks, no TLS)
	opsServer := &http.Server{
		Addr:              ":9090",
		Handler:           opsMux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		logger.Info("ops server listening (health)", "address", ":9090")
		if err := opsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("ops server error", "error", err)
		}
	}()

	// Start mTLS server
	go func() {
		logger.Info("starting gateway server with mTLS", "address", cfg.ListenAddr)
		if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			logger.Error("server error", "error", err)
			stop()
		}
	}()

	// Start cleartext HTTP server for terminal WebSocket traffic.
	//
	// Public TLS termination happens at Traefik (Let's Encrypt via the
	// TTY router's certResolver); Traefik then forwards cleartext HTTP
	// to this listener over the internal docker/k8s network. Running a
	// second TLS handshake on the gateway side served no real purpose
	// (the cert was internally-signed and no browser client ever saw
	// it directly) and caused rc3 failures when Traefik's backend URL
	// was http:// — the listener rejected the cleartext bytes with
	// "Client sent an HTTP request to an HTTPS server". Standard
	// Traefik-behind-service pattern: terminate TLS at the edge,
	// cleartext inside the private network.
	//
	// The terminal bridge authenticates via session tokens validated
	// against the control server; no TLS client cert is needed.
	var webServer *http.Server
	if cfg.WebListenAddr != "" {
		bridgeHandler := handler.NewTerminalBridgeHandler(
			manager, terminalSessions, controlProxy, aqClient,
			logger.With("component", "terminal_bridge"),
		)
		webMux := buildWebMux(gatewayID, bridgeHandler)
		// Log the exact paths the mux will answer so operators can
		// match them against PublicTerminalURLTemplate / Traefik rules
		// without curl-probing. rc3-rc5 all stumbled on a path mismatch
		// between the minted URL and the registered handler; this line
		// makes that mismatch auditable at startup.
		terminalPaths := []string{"/terminal"}
		if gatewayID != "" {
			terminalPaths = append(terminalPaths, fmt.Sprintf("/gw/%s/terminal", gatewayID))
		}
		logger.Info("terminal mux routes registered",
			"paths", terminalPaths,
			"health_path", "/health",
		)

		webServer = &http.Server{
			Addr:              cfg.WebListenAddr,
			Handler:           middleware.RequestID(middleware.SecurityHeaders(webMux)),
			ReadTimeout:       0, // long-lived WebSocket
			WriteTimeout:      0, // long-lived WebSocket
			IdleTimeout:       120 * time.Second,
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			logger.Info("web server listening (terminal WebSocket, cleartext HTTP behind Traefik)",
				"address", cfg.WebListenAddr)
			if err := webServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("web server error", "error", err)
				stop()
			}
		}()
	}

	// Wait for shutdown signal
	<-shutdownCtx.Done()
	logger.Info("shutting down server")

	// Give connections time to drain
	drainCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := opsServer.Shutdown(drainCtx); err != nil {
		logger.Error("ops server shutdown error", "error", err)
	}
	if webServer != nil {
		if err := webServer.Shutdown(drainCtx); err != nil {
			logger.Error("web server shutdown error", "error", err)
		}
	}
	if err := server.Shutdown(drainCtx); err != nil {
		logger.Error("shutdown error", "error", err)
	}

	logger.Info("server stopped")
}

// routableIP returns the first non-loopback IPv4 address bound to an
// up-and-running network interface. In Docker Compose / k8s deployments
// this is the replica's address on the user-defined network Traefik
// shares with us — Traefik can reach it directly.
//
// We deliberately do NOT use os.Hostname() here: inside a container the
// hostname defaults to the 12-char container ID, which is not registered
// in Docker's embedded DNS. Publishing that as a Traefik backend (or as
// an internal URL for control-plane RPC) leaves Traefik unable to resolve
// it, so the service falls back to the HTTP router and serves the wrong
// cert — which is exactly how agent mTLS started failing in rc7/rc8.
func routableIP() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue
			}
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("no non-loopback IPv4 address found on any interface")
}

// portOfListenAddr returns the port portion of a Go net.Listen style
// address (":8080", "0.0.0.0:8080", "[::]:8080") formatted as
// ":port" for concatenation with a hostname. Returns "" if the input
// has no parseable port.
func portOfListenAddr(addr string) string {
	if addr == "" {
		return ""
	}
	idx := strings.LastIndex(addr, ":")
	if idx < 0 {
		return ""
	}
	return addr[idx:]
}

// hostFromURL extracts the host (including port if present) from a
// URL like "wss://gw-01.example.com:8443/terminal" so the bootstrap
// redirect middleware constructs a correct Location header that
// preserves non-default ports. Accepts http, https, ws, and wss
// schemes. Returns "" on parse failure, unsupported scheme, or
// missing host component.
func hostFromURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	switch u.Scheme {
	case "http", "https", "ws", "wss":
		// OK
	default:
		return ""
	}
	// u.Host includes the port (e.g. "gw-01.example.com:8443"), which
	// is what the caller needs for bootstrap redirects and registry
	// registration. u.Hostname() strips the port, so we return u.Host.
	//
	// But both checks matter: a template like "https://${UNSET}:8443"
	// collapses to "https://:8443" when the env var is missing.
	// u.Host = ":8443" is non-empty (would pass the first check)
	// while u.Hostname() = "" (no hostname). Require both — same
	// invariant api.ValidateGatewayURL enforces for the control
	// server's outbound URL.
	if u.Host == "" || u.Hostname() == "" {
		return ""
	}
	return u.Host
}
