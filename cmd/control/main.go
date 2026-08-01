// Command control runs the single Power Manage control process.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/manchtools/power-manage-sdk/logging"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/controlruntime"
	pmcrypto "github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/datastore"
	"github.com/manchtools/power-manage/server/internal/store"
)

// version is set at build time.
var version = "dev"

func main() {
	command, args := "serve", os.Args[1:]
	if len(args) > 0 && args[0] == "bootstrap-admin" {
		command, args = "bootstrap-admin", args[1:]
	}
	cfg, err := loadConfig(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "control: invalid configuration:", err)
		os.Exit(2)
	}
	if command == "bootstrap-admin" {
		os.Exit(runBootstrapAdmin(context.Background(), cfg))
	}

	logger := logging.SetupLogger(cfg.LogLevel, cfg.LogFormat, os.Stderr)
	slog.SetDefault(logger)
	if err := run(cfg, logger); err != nil {
		logger.Error("control stopped", "error", err)
		os.Exit(1)
	}
}

func run(cfg *Config, logger *slog.Logger) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := datastore.RequirePostgresTLS(cfg.DatabaseURL); err != nil {
		return fmt.Errorf("database TLS: %w", err)
	}
	st, err := store.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer st.Close()
	st.SetLogger(logger)

	certificateAuthority, err := ca.New(cfg.CACertFile, cfg.CAKeyFile, cfg.CertificateValidity)
	if err != nil {
		return fmt.Errorf("load certificate authority: %w", err)
	}
	jwt, err := auth.NewJWTManager(auth.JWTConfig{PrivateKey: cfg.SessionSigningKey})
	if err != nil {
		return fmt.Errorf("load session signer: %w", err)
	}
	atRest, err := pmcrypto.NewEncryptor(cfg.EncryptionKey)
	if err != nil {
		return fmt.Errorf("load at-rest encryption key: %w", err)
	}
	if atRest == nil {
		return errors.New("load at-rest encryption key: key is required")
	}
	if err := auth.ReconcileSystemRoles(ctx, st, time.Now(), logger); err != nil {
		return fmt.Errorf("reconcile system roles: %w", err)
	}

	runtime := controlruntime.New(controlruntime.Config{
		Store: st, CA: certificateAuthority, JWT: jwt, AtRest: atRest,
		ControlSealingPrivateKey: cfg.SealingKey, Logger: logger, Version: version,
		PublicBaseURL: cfg.PublicBaseURL, AgentURL: cfg.AgentURL, TerminalURL: cfg.TerminalURL,
		CORSOrigins: cfg.CORSOrigins, CORSAllowAll: cfg.CORSAllowAll,
		TerminalOriginPatterns: cfg.TerminalOrigins, TrustedProxies: cfg.TrustedProxies,
		HeartbeatInterval: cfg.HeartbeatInterval,
	})
	defer runtime.Close()
	publicServer, err := buildPublicServer(cfg, runtime.PublicHandler)
	if err != nil {
		return err
	}
	agentServer, err := buildAgentServer(cfg, certificateAuthority, runtime.AgentHandler)
	if err != nil {
		return err
	}

	errorsCh := make(chan error, 3)
	go func() {
		if err := runtime.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			errorsCh <- fmt.Errorf("delivery dispatcher: %w", err)
		}
	}()
	go func() {
		logger.Info("public listener ready", "address", cfg.PublicListen)
		var err error
		if publicServer.TLSConfig == nil {
			err = publicServer.ListenAndServe()
		} else {
			err = publicServer.ListenAndServeTLS("", "")
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errorsCh <- fmt.Errorf("public listener: %w", err)
		}
	}()
	go func() {
		logger.Info("agent mTLS listener ready", "address", cfg.AgentListen)
		if err := agentServer.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errorsCh <- fmt.Errorf("agent listener: %w", err)
		}
	}()

	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errorsCh:
		cancel()
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	publicErr := publicServer.Shutdown(shutdownCtx)
	agentErr := agentServer.Shutdown(shutdownCtx)
	if serveErr != nil {
		return serveErr
	}
	if publicErr != nil {
		return fmt.Errorf("shut down public listener: %w", publicErr)
	}
	if agentErr != nil {
		return fmt.Errorf("shut down agent listener: %w", agentErr)
	}
	return nil
}
