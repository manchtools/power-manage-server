package doctor

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/retention"
)

// DEKInvariantCheck verifies the per-user encryption-key invariants that
// crypto-shred erasure depends on (spec 19 AC 30 / AC 31):
//
//   - AC 30: every LIVE user's DEK must be present AND unwrappable under
//     the KEK. A missing row OR a present-but-unwrappable one (KEK changed,
//     bit rot) leaves a non-deleted user effectively erased — Critical.
//     The check PROACTIVELY unwraps each key rather than only checking row
//     presence, so a corrupt key is caught here, not when it later aborts a
//     projection.
//   - AC 31: no user with a UserDeleted event may still hold a DEK row. A
//     resurrected shredded key (e.g. a backup restore) is Critical, and the
//     remediation names the re-shred reconcile.
//
// Read-only: the check reports, it never deletes a key.
type DEKInvariantCheck struct{}

func (DEKInvariantCheck) ID() string { return "dek_invariants" }

func (c DEKInvariantCheck) Run(ctx context.Context, env *Env) ([]Finding, error) {
	if skip, proceed := dbReady(ctx, c, env); !proceed {
		return skip, nil
	}

	// The KEK is required to probe unwraps. Its absence is EncryptionKeyCheck's
	// Critical; here it means we cannot run the AC 30 probe — an exec error so
	// the operator fixes config first, not a false pass. NewEncryptor returns
	// (nil, nil) for an empty key, so guard the nil explicitly.
	kek, err := crypto.NewEncryptor(env.Get("CONTROL_ENCRYPTION_KEY"))
	if err != nil {
		return nil, fmt.Errorf("cannot build KEK to probe DEK unwraps: %w", err)
	}
	if kek == nil {
		return nil, fmt.Errorf("CONTROL_ENCRYPTION_KEY is not set — cannot probe DEK unwraps (see the encryption_key check)")
	}

	deks, err := env.DB.LiveUserWrappedDEKs(ctx)
	if err != nil {
		return nil, fmt.Errorf("list live user DEKs: %w", err)
	}
	var missing, corrupt []string
	for _, d := range deks {
		if d.Wrapped == "" {
			missing = append(missing, d.UserID)
			continue
		}
		if _, err := crypto.UnwrapDEK(kek, d.UserID, d.Wrapped); err != nil {
			corrupt = append(corrupt, d.UserID)
		}
	}

	resurrected, err := env.DB.DeletedUsersWithDEK(ctx)
	if err != nil {
		return nil, fmt.Errorf("list deleted users with a DEK: %w", err)
	}

	var out []Finding
	if len(missing) > 0 {
		out = append(out, crit(c.ID(),
			fmt.Sprintf("%d live user(s) have NO encryption key — their PII is effectively erased (accidental key loss): %s", len(missing), sample(missing)),
			"restore user_encryption_keys from a backup taken WITH the event log (they are jointly authoritative); a live user without a DEK cannot decrypt their PII"))
	}
	if len(corrupt) > 0 {
		out = append(out, crit(c.ID(),
			fmt.Sprintf("%d live user(s) have an encryption key that does not unwrap under CONTROL_ENCRYPTION_KEY (KEK mismatch or corruption): %s", len(corrupt), sample(corrupt)),
			"verify CONTROL_ENCRYPTION_KEY matches the key the DEKs were wrapped under; a KEK fault must NOT be mistaken for erasure — do not delete these keys"))
	}
	if len(resurrected) > 0 {
		out = append(out, crit(c.ID(),
			fmt.Sprintf("%d deleted user(s) still hold an encryption key — a shredded DEK was resurrected (e.g. a backup restore): %s", len(resurrected), sample(resurrected)),
			"re-shred: delete the user_encryption_keys row for each listed erased user so their PII returns to unreadable (their projections are already redacted)"))
	}
	if len(out) == 0 {
		return []Finding{ok(c.ID(),
			fmt.Sprintf("every live user's DEK unwraps and no erased user retains one (%d live keys checked)", len(deks)))}, nil
	}
	return out, nil
}

// ProjectionDriftCheck reports projections that have stopped applying
// events they should (spec 19 AC 31a, absorbs audit F-02). Drift must be
// caught BEFORE retention prunes the events that would re-derive it —
// there is no post-prune reconstruction of pruned history. Read-only.
type ProjectionDriftCheck struct{}

func (ProjectionDriftCheck) ID() string { return "projection_drift" }

func (c ProjectionDriftCheck) Run(ctx context.Context, env *Env) ([]Finding, error) {
	if skip, proceed := dbReady(ctx, c, env); !proceed {
		return skip, nil
	}

	drifts, err := env.DB.ProjectionDrift(ctx)
	if err != nil {
		return nil, fmt.Errorf("compute projection drift: %w", err)
	}
	var behind []string
	for _, d := range drifts {
		if d.Drifted() {
			// Name the LAGGING table and ITS high-water — the target-wide
			// max can be a fresh sibling's and would obscure the culprit.
			behind = append(behind, fmt.Sprintf("%s (table %s applied ≤ %d, event log at %d)", d.Target, d.LaggingTable, d.LaggingMax, d.StreamMax))
		}
	}
	if len(behind) > 0 {
		return []Finding{crit(c.ID(),
			fmt.Sprintf("%d projection(s) have fallen behind the event log — a projection write was silently dropped: %s", len(behind), strings.Join(behind, "; ")),
			"rebuild the affected projections (control rebuild-projections <target…>) and investigate the dropped write BEFORE the next retention prune removes the source events")}, nil
	}
	return []Finding{ok(c.ID(),
		fmt.Sprintf("every projection is current with the event log (%d targets checked)", len(drifts)))}, nil
}

// RetentionPostureCheck reports the audit-log retention posture (spec 19
// AC 29): oldest live event age, event row count, the configured window,
// and the last successful prune (checkpoint + time + archive ref). It
// never mutates or prunes anything.
//
// Config-shape violations (enabled but invalid window/backend/path) are
// Critical: the control server refuses to BOOT on them, so seeing one
// here means the running server was started before the variable changed —
// the next restart will fail.
type RetentionPostureCheck struct{}

func (RetentionPostureCheck) ID() string { return "retention" }

func (c RetentionPostureCheck) Run(ctx context.Context, env *Env) ([]Finding, error) {
	cfg, malformed := retentionEnvConfig(env)
	if cfg.Enabled && len(malformed) > 0 {
		// An unparseable duration would otherwise surface as a misleading
		// "window too small (got 0s)" — name the actual broken value (CR).
		return []Finding{crit(c.ID(),
			fmt.Sprintf("retention is enabled but %s — the value is not a valid Go duration (e.g. \"2160h\" for 90 days)", strings.Join(malformed, "; ")),
			"fix the variable(s) named above; at boot the server falls back to the flag default and may refuse to start")}, nil
	}
	if err := cfg.Validate(); err != nil {
		return []Finding{crit(c.ID(),
			fmt.Sprintf("retention is enabled but misconfigured: %v", err),
			"fix the CONTROL_RETENTION_* variable named above; the control server will refuse to boot with this configuration")}, nil
	}

	if skip, proceed := dbReady(ctx, c, env); !proceed {
		return skip, nil
	}
	p, err := env.DB.RetentionPosture(ctx)
	if err != nil {
		return nil, fmt.Errorf("read retention posture: %w", err)
	}

	oldest := "empty log"
	if !p.OldestEventAt.IsZero() {
		oldest = fmt.Sprintf("oldest event %s old", env.Now().Sub(p.OldestEventAt).Round(time.Hour))
	}
	lastPrune := "never pruned"
	if !p.LastPruneAt.IsZero() {
		lastPrune = fmt.Sprintf("last prune at %s (checkpoint %d, archive %s)",
			p.LastPruneAt.Format(time.RFC3339), p.LastPruneCheckpoint, p.LastPruneRef)
	}

	if !cfg.Enabled {
		return []Finding{info(c.ID(),
			fmt.Sprintf("retention is disabled — the event log grows unbounded (%d events, %s; %s)", p.EventCount, oldest, lastPrune))}, nil
	}
	return []Finding{ok(c.ID(),
		fmt.Sprintf("retention enabled (window %s): %d events, %s; %s", cfg.Window, p.EventCount, oldest, lastPrune))}, nil
}

// retentionEnvConfig mirrors cmd/control's flag/env mapping for the
// doctor's standalone read (doctor runs without booting the server).
// malformed lists human-readable descriptions of duration variables that
// are set but do not parse — the caller reports them explicitly instead
// of letting the zero fallback masquerade as a too-small value.
func retentionEnvConfig(env *Env) (cfg retention.EnvConfig, malformed []string) {
	enabled := env.Get("CONTROL_RETENTION_ENABLED")
	backend := env.Get("CONTROL_RETENTION_ARCHIVE_BACKEND")
	if backend == "" {
		backend = "filesystem" // the boot-side flag default
	}
	parse := func(key string, def time.Duration) time.Duration {
		raw := env.Get(key)
		if raw == "" {
			return def
		}
		d, err := time.ParseDuration(raw)
		if err != nil {
			malformed = append(malformed, fmt.Sprintf("%s=%q", key, raw))
			return def
		}
		return d
	}
	return retention.EnvConfig{
		Enabled:     enabled == "true" || enabled == "1",
		Window:      parse("CONTROL_RETENTION_WINDOW", 0),
		Backend:     backend,
		ArchivePath: env.Get("CONTROL_RETENTION_ARCHIVE_PATH"),
		Interval:    parse("CONTROL_RETENTION_INTERVAL", time.Hour), // the boot-side flag default
	}, malformed
}

// sample renders up to three ids for a finding message; user ids are ULIDs
// (not secrets), so naming a few is safe and actionable without dumping all.
func sample(ids []string) string {
	if len(ids) <= 3 {
		return strings.Join(ids, ", ")
	}
	return fmt.Sprintf("%s, … (+%d more)", strings.Join(ids[:3], ", "), len(ids)-3)
}
