package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/manchtools/power-manage/server/internal/archive"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/doctor"
	"github.com/manchtools/power-manage/server/internal/pii"
	"github.com/manchtools/power-manage/server/internal/projectors"
	"github.com/manchtools/power-manage/server/internal/retention"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/postgres"
)

// runRebuildProjections implements `control rebuild-projections [target…]`
// (spec 21 / F-01 #505): the production entry point for the emergency
// projection replay that ADR 0029's recovery guarantee rests on. With no
// arguments it replays every store.AllRebuildTargets entry; with names it
// replays those targets plus whatever cascade safety pulls in (F-03 #506
// — a TRUNCATE ... CASCADE must never wipe a table that is not replayed).
//
// Deliberately CLI-only: a destructive TRUNCATE-and-replay is an
// operator-console operation gated by host/shell access to the control
// container — there is NO remote RPC exposing RebuildAll (spec 21 AC 3).
//
// Exit codes: 0 success · 1 rebuild failed (rolled back) · 2 could not
// run (bad flags, unknown target, no database).
func runRebuildProjections(args []string) int {
	fs := flag.NewFlagSet("rebuild-projections", flag.ContinueOnError)
	envFile := fs.String("env-file", ".env", "deploy .env file to read CONTROL_DATABASE_URL from (skipped if absent)")
	archiveDir := fs.String("archive-dir", "", "retention archive directory (filesystem backend); restores pruned history via the EventLogPruned marker chain, then replays live events (spec 19 AC 21)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	// A restore is always a FULL rebuild: the archived history spans every
	// stream, and partial-target semantics would reintroduce the cascade
	// data-loss class the restore exists to prevent.
	if *archiveDir != "" && len(fs.Args()) > 0 {
		fmt.Fprintln(os.Stderr, "rebuild-projections: --archive-dir restores every projection; target selection is not supported with it")
		return 2
	}

	// Same env resolution as doctor: process env merged with the deploy
	// .env file (the file wins — it is the operator's stored config).
	vars := doctor.ProcessEnv()
	if dotenv, err := doctor.LoadEnvFile(*envFile); err != nil {
		fmt.Fprintf(os.Stderr, "rebuild-projections: could not read %s: %v\n", *envFile, err)
		return 2
	} else if dotenv != nil {
		vars = doctor.MergeVars(vars, dotenv)
	}
	dsn := vars["CONTROL_DATABASE_URL"]
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "rebuild-projections: CONTROL_DATABASE_URL is not set (env or --env-file)")
		return 2
	}

	// CLI lifecycle context (spec 21 AC 3), not a request context. Ctrl-C
	// cancels mid-replay; the single rebuild transaction rolls back to
	// the pre-rebuild state rather than leaving projections half-built.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	st, err := store.New(ctx, dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rebuild-projections: connect to database: %v\n", err)
		return 2
	}
	defer st.Close()
	st.SetLogger(logger)
	st.SetRepos(postgres.NewRepos(st.Queries()))
	projectors.WireAll(st, logger)

	// Spec 19 / ADR 0033: the users projection (and any PII-bearing stream)
	// replays sealed `pii:v1:` fields, so the rebuild MUST wire the same PII
	// opener that boot wires — WireAll does NOT. Without it, openSealedPII
	// refuses to project ciphertext and the entire rebuild rolls back, so the
	// emergency-recovery command fails on any real deployment (all of which
	// have users with PII). The KEK is mandatory (same posture as control
	// boot); a rebuild cannot decrypt PII without it. Resolved from the same
	// merged env as the DSN, so a key kept only in `.env` is honoured.
	encKey := vars["CONTROL_ENCRYPTION_KEY"]
	if encKey == "" {
		fmt.Fprintln(os.Stderr, "rebuild-projections: CONTROL_ENCRYPTION_KEY is not set (env or --env-file) — required to decrypt sealed PII during replay")
		return 2
	}
	encryptor, err := crypto.NewEncryptor(encKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rebuild-projections: initialize encryptor: %v\n", err)
		return 2
	}
	piiOpener, err := pii.NewOpener(encryptor, st.Repos().UserEncryptionKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rebuild-projections: initialize PII opener: %v\n", err)
		return 2
	}
	projectors.SetPIIOpener(piiOpener)

	var res store.RebuildResult
	if *archiveDir != "" {
		// Restore path (spec 19 AC 21): chain-load the pruned history from
		// the retention archives (integrity-checked against the marker
		// hashes), then replay it + the live events > N in one transaction.
		arch, aerr := archive.New(archive.Config{Backend: archive.BackendFilesystem, FilesystemPath: *archiveDir})
		if aerr != nil {
			fmt.Fprintf(os.Stderr, "rebuild-projections: open archive: %v\n", aerr)
			return 2
		}
		hist, herr := retention.LoadArchivedHistory(ctx, st, arch)
		if herr != nil {
			fmt.Fprintf(os.Stderr, "rebuild-projections: load archived history: %v\n", herr)
			return 2
		}
		fmt.Printf("restoring every projection from %d archived event(s) + the live log\n", len(hist))
		res, err = st.RebuildAllFromArchive(ctx, hist)
		if err != nil {
			fmt.Fprintf(os.Stderr, "rebuild-projections: restore FAILED, all changes rolled back: %v\n", err)
			return 1
		}
	} else {
		targets := fs.Args()
		plan, perr := st.ResolveTargets(ctx, targets...)
		if perr != nil {
			if errors.Is(perr, store.ErrUnknownTarget) {
				valid := make([]string, len(store.AllRebuildTargets))
				for i, tgt := range store.AllRebuildTargets {
					valid[i] = tgt.Name
				}
				fmt.Fprintf(os.Stderr, "rebuild-projections: %v\nvalid targets: %s\n", perr, strings.Join(valid, ", "))
				return 2
			}
			fmt.Fprintf(os.Stderr, "rebuild-projections: %v\n", perr)
			return 2
		}

		// Print the plan BEFORE any destructive statement runs, including
		// what cascade safety widened the selection to.
		fmt.Printf("rebuilding %d projection target(s): %s\n", len(plan), strings.Join(plan, ", "))
		if len(targets) > 0 && len(plan) > len(targets) {
			fmt.Println("selection widened for cascade safety: a partial rebuild must replay every table its TRUNCATE ... CASCADE wipes")
		}

		res, err = st.RebuildAll(ctx, targets...)
		if err != nil {
			if errors.Is(err, store.ErrHistoryPruned) {
				// Not a failed rebuild — the rebuild refused to run because
				// it would destroy pruned state (spec 19 AC 21). Actionable:
				// re-run with --archive-dir pointing at the retention
				// archives. Exit 2 = could-not-run, doctor convention.
				fmt.Fprintf(os.Stderr, "rebuild-projections: %v\n", err)
				return 2
			}
			fmt.Fprintf(os.Stderr, "rebuild-projections: FAILED, all changes rolled back: %v\n", err)
			return 1
		}
	}
	for _, tr := range res.Targets {
		fmt.Printf("  %-24s applied=%-8d skipped=%-6d %s\n",
			tr.Name, tr.EventsApplied, tr.Skipped, tr.Duration.Round(time.Millisecond))
	}

	// System-role permissions are reconciler-owned (the Go registry is
	// the single source of truth; migration 009 blanked the SQL
	// literals), so a rebuild re-seeds the Admin/User rows with empty
	// arrays. Boot reconciles them too, but re-running it here makes
	// the rebuilt DB immediately correct without a control restart.
	if err := auth.ReconcileSystemRoles(ctx, st.Queries(), logger); err != nil {
		fmt.Fprintf(os.Stderr, "rebuild-projections: rebuild succeeded but reconciling system-role permissions failed: %v\nrestart the control server (its boot reconciler is fatal-on-failure) before relying on RBAC\n", err)
		return 1
	}

	fmt.Printf("done in %s\n", res.TotalDuration.Round(time.Millisecond))
	return 0
}
