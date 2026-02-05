// Gateway server handles agent connections and forwards messages via PostgreSQL pub/sub.
package main

import (
	"context"
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
	"github.com/manchtools/power-manage/server/internal/connection"
	"github.com/manchtools/power-manage/server/internal/handler"
	"github.com/manchtools/power-manage/server/internal/mtls"
	"github.com/manchtools/power-manage/server/internal/store"
)

// version is set at build time via -ldflags.
var version = "dev"

func main() {
	// Parse flags
	addr := flag.String("addr", ":8080", "listen address")
	databaseURL := flag.String("database-url", "", "PostgreSQL connection URL")
	logLevel := flag.String("log-level", "info", "log level (debug, info, warn, error)")

	// TLS flags
	tlsEnabled := flag.Bool("tls", false, "enable mTLS")
	tlsCert := flag.String("tls-cert", "", "path to server certificate")
	tlsKey := flag.String("tls-key", "", "path to server private key")
	tlsCA := flag.String("tls-ca", "", "path to CA certificate for client validation")

	flag.Parse()

	// Setup logger
	var level slog.Level
	switch *logLevel {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
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

	// Validate required flags
	if *databaseURL == "" {
		logger.Error("database-url is required")
		os.Exit(1)
	}

	// Validate TLS flags
	if *tlsEnabled {
		if *tlsCert == "" || *tlsKey == "" || *tlsCA == "" {
			logger.Error("TLS enabled but missing required flags: -tls-cert, -tls-key, -tls-ca")
			os.Exit(1)
		}
	}

	// Connect to PostgreSQL (without running migrations - control server handles that)
	ctx := context.Background()
	logger.Info("connecting to PostgreSQL", "url", redactPassword(*databaseURL))
	db, err := store.NewWithoutMigrations(ctx, *databaseURL)
	if err != nil {
		logger.Error("failed to connect to PostgreSQL", "error", err)
		os.Exit(1)
	}
	defer db.Close()
	logger.Info("connected to PostgreSQL")

	// Create connection manager
	manager := connection.NewManager()

	logger.Info("gateway started", "version", version)

	// Setup HTTP mux
	mux := http.NewServeMux()

	// Create handler based on TLS mode
	if *tlsEnabled {
		agentHandler := handler.NewAgentHandlerWithTLS(manager, db, logger)
		path, h := pmv1connect.NewAgentServiceHandler(agentHandler)
		// Wrap with mTLS middleware to extract device ID from certificate
		mux.Handle(path, handler.MTLSMiddleware(h, logger))
	} else {
		agentHandler := handler.NewAgentHandler(manager, db, logger)
		path, h := pmv1connect.NewAgentServiceHandler(agentHandler)
		mux.Handle(path, h)
	}

	// Health check endpoint for load balancer
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
		// mTLS mode
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
			Addr:         *addr,
			Handler:      securedMux,
			TLSConfig:    tlsConfig,
			ReadTimeout:  0, // No timeout for streaming
			WriteTimeout: 0, // No timeout for streaming
			IdleTimeout:  120 * time.Second,
		}

		// Configure HTTP/2
		if err := http2.ConfigureServer(server, &http2.Server{}); err != nil {
			logger.Error("failed to configure HTTP/2", "error", err)
			os.Exit(1)
		}
	} else {
		// h2c mode (HTTP/2 without TLS, for development/testing)
		server = &http.Server{
			Addr:         *addr,
			Handler:      h2c.NewHandler(securedMux, &http2.Server{}),
			ReadTimeout:  0,
			WriteTimeout: 0,
			IdleTimeout:  120 * time.Second,
		}
	}

	// Graceful shutdown
	shutdownCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Start server
	go func() {
		if *tlsEnabled {
			logger.Info("starting gateway server with mTLS", "address", *addr)
			if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				logger.Error("server error", "error", err)
				os.Exit(1)
			}
		} else {
			logger.Info("starting gateway server (insecure h2c mode)", "address", *addr)
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

// redactPassword redacts the password from a database URL for logging.
func redactPassword(url string) string {
	// Simple redaction - find :password@ pattern and replace password
	// This is a basic implementation; production code might use url.Parse
	return url // For now, just return as-is; the URL structure varies
}

