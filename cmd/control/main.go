// Package main provides the control server entry point.
package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/manchtools/power-manage/sdk/gen/go/pm/v1/pmv1connect"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/control"
	"github.com/manchtools/power-manage/server/internal/store"
)

// version is set at build time via -ldflags.
var version = "dev"

type Config struct {
	ListenAddr    string
	DatabaseURL   string
	JWTSecret     string
	CACertPath    string
	CAKeyPath     string
	CertValidity  time.Duration
	LogLevel      string
	LogFormat     string
	AdminEmail    string
	AdminPassword string
	CORSOrigins   []string
	GatewayURL    string
}

func main() {
	cfg := parseFlags()

	logger := setupLogger(cfg.LogLevel, cfg.LogFormat)
	logger.Info("starting control server", "version", version, "listen_addr", cfg.ListenAddr, "gateway_url", cfg.GatewayURL)
	if cfg.GatewayURL == "" {
		logger.Warn("CONTROL_GATEWAY_URL is not set - agents will not receive a gateway URL during registration")
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
	logger.Info("CA initialized", "validity", cfg.CertValidity)

	// Initialize JWT manager
	jwtManager := auth.NewJWTManager(auth.JWTConfig{
		Secret: []byte(cfg.JWTSecret),
	})

	// Initialize authorizer
	authorizer, err := auth.NewAuthorizer()
	if err != nil {
		logger.Error("failed to initialize authorizer", "error", err)
		os.Exit(1)
	}

	// Start control handler (PostgreSQL LISTEN notification processor)
	controlHandler := control.NewHandler(st, logger)
	go func() {
		if err := controlHandler.Run(ctx); err != nil && ctx.Err() == nil {
			logger.Error("control handler error", "error", err)
		}
	}()

	// Start periodic cleanup of expired revoked tokens
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := st.Queries().CleanupExpiredRevocations(ctx); err != nil {
					logger.Error("failed to cleanup expired token revocations", "error", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Initialize action signer (signs actions so agents can verify authenticity)
	actionSigner := ca.NewActionSigner(certAuth)

	// Setup Connect-RPC service
	svc := api.NewControlService(st, jwtManager, actionSigner, certAuth, cfg.GatewayURL, logger)
	loginLimiter := auth.NewRateLimiter(10, 15*time.Minute)
	refreshLimiter := auth.NewRateLimiter(30, 15*time.Minute)
	registerLimiter := auth.NewRateLimiter(10, 15*time.Minute)

	interceptors := connect.WithInterceptors(
		auth.NewAuthInterceptor(jwtManager, loginLimiter, refreshLimiter, registerLimiter),
		auth.NewAuthzInterceptor(authorizer),
		auth.NewSessionInterceptor(st),
	)

	mux := http.NewServeMux()
	path, handler := pmv1connect.NewControlServiceHandler(svc, interceptors)
	mux.Handle(path, handler)

	// Add health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// Wrap with CORS and security headers middleware
	corsHandler := corsMiddleware(cfg.CORSOrigins, logger)(mux)
	securedHandler := securityHeadersMiddleware(corsHandler)

	server := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: h2c.NewHandler(securedHandler, &http2.Server{}),
	}

	// Start server
	go func() {
		logger.Info("control server listening", "addr", cfg.ListenAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server error", "error", err)
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

	flag.Parse()

	// Environment variable overrides
	if v := os.Getenv("CONTROL_LISTEN_ADDR"); v != "" {
		cfg.ListenAddr = v
	}
	if v := os.Getenv("CONTROL_DATABASE_URL"); v != "" {
		cfg.DatabaseURL = v
	}
	if v := os.Getenv("CONTROL_JWT_SECRET"); v != "" {
		cfg.JWTSecret = v
	}
	if v := os.Getenv("CONTROL_CA_CERT"); v != "" {
		cfg.CACertPath = v
	}
	if v := os.Getenv("CONTROL_CA_KEY"); v != "" {
		cfg.CAKeyPath = v
	}
	if v := os.Getenv("CONTROL_ADMIN_EMAIL"); v != "" {
		cfg.AdminEmail = v
	}
	if v := os.Getenv("CONTROL_ADMIN_PASSWORD"); v != "" {
		cfg.AdminPassword = v
	}
	if v := os.Getenv("CONTROL_LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}
	if v := os.Getenv("CONTROL_GATEWAY_URL"); v != "" {
		cfg.GatewayURL = v
	}
	if v := os.Getenv("CONTROL_CORS_ORIGINS"); v != "" {
		origins := strings.Split(v, ",")
		for i := range origins {
			origins[i] = strings.TrimSpace(origins[i])
		}
		cfg.CORSOrigins = origins
	}

	// Generate JWT secret if not provided
	if cfg.JWTSecret == "" {
		secret := make([]byte, 32)
		rand.Read(secret)
		cfg.JWTSecret = fmt.Sprintf("%x", secret)
	}

	return cfg
}

func setupLogger(level, format string) *slog.Logger {
	var logLevel slog.Level
	switch level {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: logLevel}

	var handler slog.Handler
	if format == "json" {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}

	return slog.New(handler)
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

	entropy := ulid.Monotonic(rand.Reader, 0)
	id := ulid.MustNew(ulid.Timestamp(time.Now()), entropy).String()

	// Append UserCreated event - the trigger will handle projection
	err = st.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   id,
		EventType:  "UserCreated",
		Data: map[string]any{
			"email":         email,
			"password_hash": passwordHash,
			"role":          "admin",
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

// corsMiddleware returns a middleware that adds CORS headers for cross-origin requests.
// If allowedOrigins is empty, all origins are allowed (development mode) with a warning.
// Set CONTROL_CORS_ORIGINS=https://app.example.com,https://other.example.com for production.
func corsMiddleware(allowedOrigins []string, logger *slog.Logger) func(http.Handler) http.Handler {
	originSet := make(map[string]bool, len(allowedOrigins))
	for _, o := range allowedOrigins {
		originSet[o] = true
	}

	allowAll := len(allowedOrigins) == 0
	if allowAll {
		logger.Warn("CORS: no origins configured (CONTROL_CORS_ORIGINS), allowing all origins -- set this in production")
	} else {
		logger.Info("CORS: allowed origins configured", "origins", allowedOrigins)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			if origin != "" {
				if allowAll || originSet[origin] {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				} else {
					// Origin not allowed - do not set CORS headers
					if r.Method == http.MethodOptions {
						w.WriteHeader(http.StatusForbidden)
						return
					}
					next.ServeHTTP(w, r)
					return
				}
			}

			// Handle preflight requests
			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type, Connect-Protocol-Version, Connect-Timeout-Ms, Cookie")
				w.Header().Set("Access-Control-Expose-Headers", "Connect-Content-Encoding, Connect-Protocol-Version")
				w.Header().Set("Access-Control-Max-Age", "86400")
				w.WriteHeader(http.StatusNoContent)
				return
			}

			// Set headers for actual requests
			w.Header().Set("Access-Control-Expose-Headers", "Connect-Content-Encoding, Connect-Protocol-Version")

			next.ServeHTTP(w, r)
		})
	}
}

// maskDatabaseURL masks the password in a database URL for logging.
func maskDatabaseURL(url string) string {
	// Simple masking - replace password portion
	// postgres://user:password@host:port/db -> postgres://user:***@host:port/db
	for i := 0; i < len(url); i++ {
		if url[i] == ':' && i > 10 { // Skip the postgres:// part
			for j := i + 1; j < len(url); j++ {
				if url[j] == '@' {
					return url[:i+1] + "***" + url[j:]
				}
			}
		}
	}
	return url
}
