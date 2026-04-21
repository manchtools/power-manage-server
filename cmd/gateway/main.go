// Gateway server handles agent connections and forwards messages via Asynq (Valkey).
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log/slog"
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

	// Validate required config
	if cfg.ValkeyAddr == "" {
		logger.Error("GATEWAY_VALKEY_ADDR is required")
		os.Exit(1)
	}
	if cfg.ControlURL == "" {
		logger.Error("GATEWAY_CONTROL_URL is required")
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

	// Wire the multi-gateway registry. Reuses the same Valkey
	// instance the Asynq queue uses, no extra connection pool. The
	// registry is enabled only when the operator has set the
	// public terminal URL template — without it the gateway can't
	// know its own public URL, so we just leave the registry off
	// (single-gateway / no-terminal mode).
	var (
		gatewayReg   *registry.Registry
		assignedHost string
	)

	// Compute the agent redirect hostname independently of the terminal
	// URL. This supports multi-gateway agent routing without requiring
	// the terminal feature to be enabled.
	if cfg.PublicAgentURLTemplate != "" {
		agentURL := strings.ReplaceAll(cfg.PublicAgentURLTemplate, "{id}", gatewayID)
		assignedHost = hostFromURL(agentURL)
		if assignedHost == "" {
			logger.Error("could not extract host from GATEWAY_PUBLIC_AGENT_URL_TEMPLATE",
				"template", cfg.PublicAgentURLTemplate, "resolved", agentURL)
			os.Exit(1)
		}
	}

	if cfg.PublicTerminalURLTemplate != "" {
		// Substitute {id} in the URL template. The template is the
		// public WebSocket URL operators want clients to use; the
		// gateway never constructs hostnames from the request side.
		terminalURL := strings.ReplaceAll(cfg.PublicTerminalURLTemplate, "{id}", gatewayID)

		// If no agent URL template was set, fall back to deriving the
		// agent redirect hostname from the terminal URL (legacy
		// single-hostname mode).
		if assignedHost == "" {
			assignedHost = hostFromURL(terminalURL)
			if assignedHost == "" {
				logger.Error("could not extract host from GATEWAY_PUBLIC_TERMINAL_URL_TEMPLATE",
					"template", cfg.PublicTerminalURLTemplate, "resolved", terminalURL)
				os.Exit(1)
			}
		}

		rdb := redis.NewClient(&redis.Options{
			Addr:     cfg.ValkeyAddr,
			Password: cfg.ValkeyPassword,
			DB:       cfg.ValkeyDB,
			Protocol: 2,
		})
		defer rdb.Close()

		gatewayReg = registry.New(registry.NewValkeyBackend(rdb), logger.With("component", "registry"))
		stop, err := gatewayReg.RegisterGateway(
			context.Background(),
			gatewayID,
			terminalURL,
			registry.DefaultGatewayTTL,
			registry.DefaultGatewayRefreshInterval,
		)
		if err != nil {
			logger.Error("failed to register gateway in registry", "error", err)
			os.Exit(1)
		}
		defer stop()

		// Also publish the internal mTLS URL so the control server
		// can discover this gateway for admin fan-out (List/Terminate
		// terminal sessions). Uses the same TTL as the terminal URL.
		//
		// rc6 note: auto-derive when GATEWAY_INTERNAL_URL is empty.
		// The GatewayService RPC is mounted on the same mTLS listener
		// that accepts agents, so the internal URL is just
		// `https://<hostname><listen-port>`. Auto-derivation keeps the
		// common case zero-config — without it, operators who don't
		// set the env silently lose the admin list/terminate feature
		// (Terminal Sessions page shows empty).
		internalURL := cfg.InternalURL
		if internalURL == "" {
			hostname, err := os.Hostname()
			if err != nil || hostname == "" {
				logger.Error("cannot auto-derive GATEWAY_INTERNAL_URL: os.Hostname failed", "error", err)
				os.Exit(1)
			}
			internalURL = "https://" + hostname + portOfListenAddr(cfg.ListenAddr)
			logger.Info("auto-derived GATEWAY_INTERNAL_URL", "internal_url", internalURL)
		}
		if internalURL != "" {
			if err := gatewayReg.RegisterGatewayInternal(
				context.Background(), gatewayID, internalURL, registry.DefaultGatewayTTL,
			); err != nil {
				logger.Warn("failed to register gateway internal URL", "error", err)
			}
			// Refresh the internal URL on the same cadence as the
			// terminal URL so it does not expire while the gateway is
			// running. Derive from shutdownCtx so the goroutine exits
			// as soon as a signal arrives.
			internalRefreshCtx, stopInternalRefresh := context.WithCancel(shutdownCtx)
			defer stopInternalRefresh()
			go func() {
				ticker := time.NewTicker(registry.DefaultGatewayRefreshInterval)
				defer ticker.Stop()
				for {
					select {
					case <-ticker.C:
						if err := gatewayReg.RegisterGatewayInternal(
							context.Background(), gatewayID, internalURL, registry.DefaultGatewayTTL,
						); err != nil {
							logger.Warn("failed to refresh gateway internal URL", "error", err)
						}
					case <-internalRefreshCtx.Done():
						return
					}
				}
			}()
		}

		logger.Info("multi-gateway routing enabled",
			"gateway_id", gatewayID,
			"terminal_url", terminalURL,
			"agent_redirect_host", assignedHost,
			"internal_url", internalURL,
		)
	}

	// Traefik Redis-KV self-registration. Opt-in; when enabled, every
	// replica writes its own routing entry into the same Valkey
	// instance Traefik watches via `--providers.redis`, so scaling the
	// gateway deployment does not require hand-edited labels or per-
	// replica public DNS entries. The shared pm-mtls TCP router is
	// load-balanced across all replicas; each replica owns a unique
	// /gw/<id> path prefix on the shared tty host for TTY routing.
	if cfg.TraefikSelfRegister {
		if gatewayReg == nil {
			// Need a Valkey-backed registry. When PublicTerminalURLTemplate
			// was empty we skipped the Valkey connection earlier; set one
			// up here so Traefik self-reg still works in deployments that
			// only want the routing layer (no terminal feature).
			rdb := redis.NewClient(&redis.Options{
				Addr:     cfg.ValkeyAddr,
				Password: cfg.ValkeyPassword,
				DB:       cfg.ValkeyDB,
				Protocol: 2,
			})
			defer rdb.Close()
			gatewayReg = registry.New(registry.NewValkeyBackend(rdb), logger.With("component", "registry"))
		}

		// Auto-derive per-replica backend addresses when not set.
		// In Compose / k8s, os.Hostname() returns the container name
		// (pm-server-gateway-1, gateway-abc123, …), which resolves to
		// that specific replica's IP inside the pm-internal network.
		// The operator only has to set the public Host/EntryPoint
		// values; replica identity is self-discovered.
		mtlsBackend := cfg.TraefikMTLSBackend
		ttyBackend := cfg.TraefikTTYBackend
		if mtlsBackend == "" || ttyBackend == "" {
			hostname, err := os.Hostname()
			if err != nil || hostname == "" {
				logger.Error("cannot auto-derive Traefik backends: os.Hostname failed", "error", err)
				os.Exit(1)
			}
			if mtlsBackend == "" {
				mtlsBackend = hostname + portOfListenAddr(cfg.ListenAddr)
			}
			if ttyBackend == "" && cfg.WebListenAddr != "" {
				ttyBackend = "http://" + hostname + portOfListenAddr(cfg.WebListenAddr)
			}
		}

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

		if err := gatewayReg.PublishTraefikRoute(
			context.Background(), gatewayID, traefikCfg, registry.DefaultGatewayTTL,
		); err != nil {
			logger.Error("failed to publish Traefik routing config", "error", err)
			os.Exit(1)
		}

		// Refresh on the same cadence as the gateway terminal URL and
		// internal URL so all three keys share a lifecycle. Derive from
		// shutdownCtx so the goroutine exits cleanly on SIGTERM.
		traefikRefreshCtx, stopTraefikRefresh := context.WithCancel(shutdownCtx)
		defer stopTraefikRefresh()
		go func() {
			ticker := time.NewTicker(registry.DefaultGatewayRefreshInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					if err := gatewayReg.PublishTraefikRoute(
						context.Background(), gatewayID, traefikCfg, registry.DefaultGatewayTTL,
					); err != nil {
						logger.Warn("failed to refresh Traefik routing config", "error", err)
					}
				case <-traefikRefreshCtx.Done():
					return
				}
			}
		}()

		// Clean shutdown revokes only per-replica keys so other
		// replicas' routes stay up. Uses a bounded context so a flaky
		// Valkey can't stall the shutdown.
		defer func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := gatewayReg.RevokeTraefikRoute(cleanupCtx, gatewayID, traefikCfg); err != nil {
				logger.Warn("failed to revoke Traefik routing config", "error", err)
			}
		}()

		logger.Info("traefik self-registration enabled",
			"gateway_id", gatewayID,
			"mtls_host", cfg.TraefikMTLSHost,
			"mtls_backend", cfg.TraefikMTLSBackend,
			"tty_host", cfg.TraefikTTYHost,
			"tty_backend", cfg.TraefikTTYBackend,
			"tty_cert_resolver", cfg.TraefikTTYCertResolver,
		)
	}
	// Fail fast if BootstrapHost is set but we have no assignedHost
	// (because PublicTerminalURLTemplate was empty). Without this
	// guard, BootstrapRedirectMiddleware would panic on an empty
	// assignedHost further down.
	if cfg.BootstrapHost != "" && assignedHost == "" {
		logger.Error("GATEWAY_BOOTSTRAP_HOST is set but neither GATEWAY_PUBLIC_AGENT_URL_TEMPLATE nor GATEWAY_PUBLIC_TERMINAL_URL_TEMPLATE is set; cannot derive the per-gateway hostname for bootstrap redirects",
			"bootstrap_host", cfg.BootstrapHost)
		os.Exit(1)
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

	// Create agent handler (always mTLS)
	agentHandler := handler.NewAgentHandlerWithTLS(manager, aqClient, controlProxy, workerMgr, version, cfg.HeartbeatInterval, logger)
	if gatewayReg != nil {
		agentHandler.SetGatewayRouting(gatewayReg, gatewayID)
	}
	agentHandler.SetTerminalSessions(terminalSessions)
	path, h := pmv1connect.NewAgentServiceHandler(agentHandler)

	// Compose middlewares (innermost first):
	//   pmv1connect handler
	//     ↑ MTLSMiddleware (extracts device ID from client cert)
	//     ↑ BootstrapRedirectMiddleware (returns 307 to assignedHost
	//       when the request landed on the wildcard root via LB)
	mtlsHandler := handler.MTLSMiddleware(h, logger)
	bootstrappedHandler := handler.BootstrapRedirectMiddleware(mtlsHandler, cfg.BootstrapHost, assignedHost, logger)
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
	// u.Host includes the port (e.g. "gw-01.example.com:8443").
	// u.Hostname() strips it, which would break redirects on
	// non-default ports.
	if u.Host == "" {
		return ""
	}
	return u.Host
}
