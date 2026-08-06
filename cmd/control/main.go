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
	"strings"
	"syscall"
	"time"

	"github.com/manchtools/power-manage-sdk/logging"
	"github.com/manchtools/power-manage/server/internal/archive"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/controlruntime"
	pmcrypto "github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/jobs"
	"github.com/manchtools/power-manage/server/internal/maintenance"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/webhook"
)

// version is set at build time.
var version = "dev"

func main() {
	command, err := parseCommand(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "control:", err)
		os.Exit(2)
	}
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "control: invalid configuration:", err)
		os.Exit(2)
	}
	if command == "bootstrap-admin" {
		os.Exit(runBootstrapAdmin(context.Background(), cfg))
	}
	if command == "backup-status" {
		os.Exit(runBackupStatus(os.Stdout, os.Stderr, cfg, time.Now))
	}

	logger := logging.SetupLogger(cfg.LogLevel, cfg.LogFormat, os.Stderr)
	slog.SetDefault(logger)
	if err := run(cfg, logger); err != nil {
		logger.Error("control stopped", "error", err)
		os.Exit(1)
	}
}

// parseCommand selects the subcommand to run. Configuration comes entirely
// from the environment, so control accepts no flags and no other arguments.
func parseCommand(args []string) (string, error) {
	if len(args) > 0 {
		switch args[0] {
		case "bootstrap-admin", "backup-status":
			if len(args) > 1 {
				return "", fmt.Errorf("unexpected arguments: %s", strings.Join(args[1:], " "))
			}
			return args[0], nil
		default:
			return "", fmt.Errorf("unexpected arguments: %s (accepted commands: bootstrap-admin, backup-status)",
				strings.Join(args, " "))
		}
	}
	return "serve", nil
}

func run(cfg *Config, logger *slog.Logger) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	st, err := store.New(ctx, cfg.DatabasePath)
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
	auditArchive, err := archive.New(archive.Config{
		Backend: archive.BackendFilesystem, FilesystemPath: cfg.BackupPath,
	})
	if err != nil {
		return fmt.Errorf("open audit archive: %w", err)
	}
	notifier, err := webhook.New(cfg.WebhookURL)
	if err != nil {
		return fmt.Errorf("open webhook: %w", err)
	}
	maintenanceService := maintenance.New(maintenance.Config{
		Store: st, Archive: auditArchive, Retention: cfg.AuditRetention,
		Notifier: notifier, BackupPath: cfg.BackupPath, BackupMaxLag: cfg.BackupMaxLag,
	})
	if err := maintenanceService.EnsureScheduled(ctx); err != nil {
		return fmt.Errorf("schedule maintenance: %w", err)
	}
	jobState := jobs.New(jobs.Config{
		Store: st, LeaseDuration: 2 * time.Minute, RetryDelay: 30 * time.Second,
	})
	jobRunner := jobs.NewRunner(jobs.RunnerConfig{
		Store: st, State: jobState, Handlers: maintenanceService.Handlers(),
		Recurring: maintenanceService.Recurring(), Logger: logger,
	})
	revocations := store.NewRevocationChecker(st)

	runtime := controlruntime.New(controlruntime.Config{
		Store: st, CA: certificateAuthority, JWT: jwt, AtRest: atRest,
		ControlSealingPrivateKey: cfg.SealingKey, Logger: logger, Version: version,
		PublicBaseURL: cfg.PublicBaseURL, AgentURL: cfg.AgentURL, TerminalURL: cfg.TerminalURL,
		CORSOrigins: cfg.CORSOrigins, CORSAllowAll: cfg.CORSAllowAll,
		TerminalOriginPatterns: cfg.TerminalOrigins, TrustedProxies: cfg.TrustedProxies,
		HeartbeatInterval: cfg.HeartbeatInterval,
		Readiness: func(ctx context.Context) error {
			return checkReadiness(ctx, st, revocations, cfg.ArtifactPath)
		},
	})
	defer runtime.Close()
	// wrapDevAuth is a no-op unless this binary was compiled with the
	// `devauth` build tag and run with PM_DEV_AUTH=1; only then
	// does it mount the local development sign-in endpoint (target design
	// §5.2). Production builds compile the stub, so the wrap returns the
	// handler unchanged.
	publicHandler := wrapDevAuth(runtime.PublicHandler, st, jwt, atRest, logger)
	publicServer, err := buildPublicServer(cfg, publicHandler)
	if err != nil {
		return err
	}
	agentServer, err := buildAgentServer(cfg, certificateAuthority, runtime.AgentHandler)
	if err != nil {
		return err
	}

	errorsCh := make(chan error, 4)
	go func() {
		if err := runtime.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			errorsCh <- fmt.Errorf("delivery dispatcher: %w", err)
		}
	}()
	go func() {
		if err := jobRunner.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			errorsCh <- fmt.Errorf("job runner: %w", err)
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
		if err := serveAgent(agentServer, cfg.AgentProxySources); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
