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
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/manchtools/power-manage/sdk/gen/go/pm/v1/pmv1connect"
	"github.com/manchtools/power-manage/server/internal/config"
	"github.com/manchtools/power-manage/server/internal/connection"
	"github.com/manchtools/power-manage/server/internal/gateway"
	"github.com/manchtools/power-manage/server/internal/handler"
	"github.com/manchtools/power-manage/server/internal/mtls"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

// version is set at build time via -ldflags.
var version = "dev"

func main() {
	// Parse flags (TLS only — other config from env)
	tlsEnabled := flag.Bool("tls", false, "enable mTLS")
	tlsCert := flag.String("tls-cert", "", "path to server certificate")
	tlsKey := flag.String("tls-key", "", "path to server private key")
	tlsCA := flag.String("tls-ca", "", "path to CA certificate for client validation")
	flag.Parse()

	// Load config from environment
	cfg := config.FromEnv()

	// Setup logger
	var level slog.Level
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))
	slog.SetDefault(logger)

	// Validate TLS flags
	if *tlsEnabled {
		if *tlsCert == "" || *tlsKey == "" || *tlsCA == "" {
			logger.Error("TLS enabled but missing required flags: -tls-cert, -tls-key, -tls-ca")
			os.Exit(1)
		}
	}

	// Validate required config
	if cfg.ValkeyAddr == "" {
		logger.Error("VALKEY_ADDR is required")
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
	// When TLS is enabled, use mTLS to authenticate with the control server's internal listener.
	var controlHTTPClient *http.Client
	if *tlsEnabled {
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
		controlHTTPClient = &http.Client{Transport: controlTransport}
	} else {
		controlHTTPClient = http.DefaultClient
	}
	controlProxy := handler.NewControlProxy(controlHTTPClient, cfg.ControlURL)
	logger.Info("control proxy initialized", "control_url", cfg.ControlURL, "mtls", *tlsEnabled)

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

	logger.Info("gateway started", "version", version)

	// Setup HTTP mux
	mux := http.NewServeMux()

	// Create handler based on TLS mode
	if *tlsEnabled {
		agentHandler := handler.NewAgentHandlerWithTLS(manager, aqClient, controlProxy, workerMgr, logger)
		path, h := pmv1connect.NewAgentServiceHandler(agentHandler)
		mux.Handle(path, handler.MTLSMiddleware(h, logger))
	} else {
		agentHandler := handler.NewAgentHandler(manager, aqClient, controlProxy, workerMgr, logger)
		path, h := pmv1connect.NewAgentServiceHandler(agentHandler)
		mux.Handle(path, h)
	}

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"healthy","agents":%d}`, manager.Count())
	})

	// Ready check endpoint
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// Wrap with security headers
	securedMux := securityHeadersMiddleware(mux)

	// Create server
	var server *http.Server

	if *tlsEnabled {
		tlsConfig, err := mtls.NewTLSConfig(mtls.Config{
			CertFile: *tlsCert,
			KeyFile:  *tlsKey,
			CAFile:   *tlsCA,
		})
		if err != nil {
			logger.Error("failed to configure TLS", "error", err)
			os.Exit(1)
		}

		server = &http.Server{
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
	} else {
		server = &http.Server{
			Addr:              cfg.ListenAddr,
			Handler:           h2c.NewHandler(securedMux, &http2.Server{}),
			ReadTimeout:       0,
			WriteTimeout:      0,
			IdleTimeout:       120 * time.Second,
			ReadHeaderTimeout: 10 * time.Second,
		}
	}

	// Graceful shutdown
	shutdownCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Start server
	go func() {
		if *tlsEnabled {
			logger.Info("starting gateway server with mTLS", "address", cfg.ListenAddr)
			if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				logger.Error("server error", "error", err)
				os.Exit(1)
			}
		} else {
			logger.Info("starting gateway server (insecure h2c mode)", "address", cfg.ListenAddr)
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("server error", "error", err)
				os.Exit(1)
			}
		}
	}()

	// Wait for shutdown signal
	<-shutdownCtx.Done()
	logger.Info("shutting down server")

	// Give connections time to drain
	drainCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(drainCtx); err != nil {
		logger.Error("shutdown error", "error", err)
	}

	logger.Info("server stopped")
}

// securityHeadersMiddleware adds standard security headers to all responses.
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("X-XSS-Protection", "0")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}
