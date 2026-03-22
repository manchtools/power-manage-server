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

	"github.com/manchtools/power-manage/sdk/gen/go/pm/v1/pmv1connect"
	"github.com/manchtools/power-manage/sdk/go/logging"
	"github.com/manchtools/power-manage/server/internal/config"
	"github.com/manchtools/power-manage/server/internal/connection"
	"github.com/manchtools/power-manage/server/internal/gateway"
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

	logger.Info("gateway started", "version", version)

	// Setup HTTP mux for agent connections (mTLS-protected)
	mux := http.NewServeMux()

	// Create agent handler (always mTLS)
	agentHandler := handler.NewAgentHandlerWithTLS(manager, aqClient, controlProxy, workerMgr, logger)
	path, h := pmv1connect.NewAgentServiceHandler(agentHandler)
	mux.Handle(path, handler.MTLSMiddleware(h, logger))

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

	// Graceful shutdown
	shutdownCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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
			os.Exit(1)
		}
	}()

	// Wait for shutdown signal
	<-shutdownCtx.Done()
	logger.Info("shutting down server")

	// Give connections time to drain
	drainCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := opsServer.Shutdown(drainCtx); err != nil {
		logger.Error("ops server shutdown error", "error", err)
	}
	if err := server.Shutdown(drainCtx); err != nil {
		logger.Error("shutdown error", "error", err)
	}

	logger.Info("server stopped")
}
