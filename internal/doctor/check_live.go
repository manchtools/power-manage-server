package doctor

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/manchtools/power-manage/server/internal/search"
)

// defaultAdminEmail is the bootstrap sentinel an operator is expected to replace.
const defaultAdminEmail = "admin@example.com"

// DatastoresCheck — Postgres + Valkey reachability (spec 15, criterion 11). An
// unreachable (or unconfigured) datastore is a Critical finding, never an exec
// error, so the rest of the suite still runs.
type DatastoresCheck struct{}

func (DatastoresCheck) ID() string { return "datastores" }

func (c DatastoresCheck) Run(ctx context.Context, env *Env) ([]Finding, error) {
	var findings []Finding
	if env.DB == nil {
		findings = append(findings, crit(c.ID(), "Postgres is not configured/connectable", "set CONTROL_DATABASE_URL to a reachable database"))
	} else if err := env.DB.Ping(ctx); err != nil {
		findings = append(findings, critDetail(c.ID(), "Postgres is unreachable", "check CONTROL_DATABASE_URL and that the database is up", err.Error()))
	} else {
		findings = append(findings, ok(c.ID(), "Postgres reachable"))
	}
	if env.Cache == nil {
		findings = append(findings, crit(c.ID(), "Valkey is not configured/connectable", "set CONTROL_VALKEY_ADDR to a reachable instance"))
	} else if err := env.Cache.Ping(ctx); err != nil {
		findings = append(findings, critDetail(c.ID(), "Valkey is unreachable", "check CONTROL_VALKEY_ADDR/password and that Valkey is up", err.Error()))
	} else {
		findings = append(findings, ok(c.ID(), "Valkey reachable"))
	}
	return findings, nil
}

// QueuesCheck — Asynq dead-letter (archived) depth (spec 15, criterion 12).
type QueuesCheck struct{}

func (QueuesCheck) ID() string { return "queues" }

func (c QueuesCheck) Run(ctx context.Context, env *Env) ([]Finding, error) {
	if env.Cache == nil {
		return []Finding{info(c.ID(), "skipped — Valkey unavailable")}, nil
	}
	byQueue, err := env.Cache.ArchivedByQueue(ctx)
	if err != nil {
		return []Finding{info(c.ID(), "could not read queue depths: "+err.Error())}, nil
	}
	var findings []Finding
	names := make([]string, 0, len(byQueue))
	for q := range byQueue {
		names = append(names, q)
	}
	sort.Strings(names)
	for _, q := range names {
		if n := byQueue[q]; n > 0 {
			findings = append(findings, warn(c.ID(),
				fmt.Sprintf("queue %q has %d archived (dead-letter) task(s)", q, n),
				"inspect and retry/delete archived tasks; investigate the repeated failures"))
		}
	}
	if len(findings) == 0 {
		return []Finding{ok(c.ID(), "no archived (dead-letter) tasks")}, nil
	}
	return findings, nil
}

// defaultReconcileInterval mirrors the indexer's own default
// (cmd/indexer -reconcile-interval) so the freshness horizon self-calibrates
// even when INDEXER_RECONCILE_INTERVAL is not in the inspected env.
const defaultReconcileInterval = time.Hour

// SearchCheck — expected indexes present (criterion 13, critical) + indexer
// liveness via the reconcile heartbeat (warning past 2× the reconcile interval)
// + schema fingerprint drift (warning). The freshness horizon is derived from
// the configured interval, not a fixed wall-clock.
type SearchCheck struct{}

func (SearchCheck) ID() string { return "search" }

func (c SearchCheck) Run(ctx context.Context, env *Env) ([]Finding, error) {
	if env.Cache == nil {
		return []Finding{info(c.ID(), "skipped — Valkey unavailable")}, nil
	}
	missing, err := env.Cache.MissingIndexes(ctx, expectedIndexNames())
	if err != nil {
		return []Finding{info(c.ID(), "could not query search indexes: "+err.Error())}, nil
	}
	var findings []Finding
	for _, name := range missing {
		findings = append(findings, crit(c.ID(),
			fmt.Sprintf("search index %s is missing", name),
			"run the indexer / RebuildSearchIndex to (re)create it"))
	}

	// Indexer liveness: a heartbeat older than 2× the reconcile interval means
	// the indexer process is dead/stuck — the index drifts silently even though
	// the fingerprint may still match. Absent heartbeat ⇒ never stamped (fresh
	// deploy / pre-heartbeat indexer); not a "stale" signal, so no warning.
	interval := reconcileInterval(env)
	if ts, present, err := env.Cache.LastReconcile(ctx); err == nil && present {
		if age := env.now().Sub(ts); age > 2*interval {
			f := warn(c.ID(),
				fmt.Sprintf("the search indexer has not reconciled in %s (> 2× the %s interval) — it may be dead or stuck", age.Round(time.Second), interval),
				"check the indexer container/logs and restart it")
			f.Detail = "last reconcile " + ts.UTC().Format(time.RFC3339)
			findings = append(findings, f)
		}
	}

	if current, err := env.Cache.SchemaCurrent(ctx); err == nil && !current {
		findings = append(findings, warn(c.ID(),
			"the indexed schema is stale (fingerprint mismatch)",
			"the indexer will rebuild on next boot; trigger a rebuild if it has not"))
	}
	if len(findings) == 0 {
		return []Finding{ok(c.ID(), "all expected search indexes present, schema current, indexer reconciling")}, nil
	}
	return findings, nil
}

// reconcileInterval reads INDEXER_RECONCILE_INTERVAL (a Go duration) from the
// inspected env, falling back to the indexer's own default. A non-positive value
// (reconciliation disabled) also falls back, so the freshness check still has a
// sane horizon.
func reconcileInterval(env *Env) time.Duration {
	if d, err := time.ParseDuration(env.Get("INDEXER_RECONCILE_INTERVAL")); err == nil && d > 0 {
		return d
	}
	return defaultReconcileInterval
}

// AdminCheck — bootstrap admin still on the default email (spec 15, criterion 14).
type AdminCheck struct{}

func (AdminCheck) ID() string { return "admin" }

func (c AdminCheck) Run(ctx context.Context, env *Env) ([]Finding, error) {
	flag := func() []Finding {
		return []Finding{warn(c.ID(),
			fmt.Sprintf("the bootstrap admin still uses the default address %q", defaultAdminEmail),
			"create a real admin account and remove/disable the default")}
	}
	// The configured-email signal is definitive and needs no DB.
	if env.Get("CONTROL_ADMIN_EMAIL") == defaultAdminEmail {
		return flag(), nil
	}
	// The DB signal: does a live admin row still sit on the default email? If we
	// cannot consult the DB, say so — never report a green we did not verify.
	if env.DB == nil {
		return []Finding{info(c.ID(), "default-email admin DB lookup skipped — Postgres unavailable; CONTROL_ADMIN_EMAIL is not the default")}, nil
	}
	exists, err := env.DB.AdminUserExists(ctx, defaultAdminEmail)
	if err != nil {
		return []Finding{info(c.ID(), "could not query for a default-email admin: "+err.Error())}, nil
	}
	if exists {
		return flag(), nil
	}
	return []Finding{ok(c.ID(), "no default-email admin in use")}, nil
}

// expectedIndexNames lists the FT search indexes the deployment should have.
func expectedIndexNames() []string {
	names := make([]string, 0, len(search.IndexSchemas))
	for _, ix := range search.IndexSchemas {
		names = append(names, ix.Name)
	}
	return names
}

// critDetail is crit() with a Detail attached.
func critDetail(id, msg, remediation, detail string) Finding {
	f := crit(id, msg, remediation)
	f.Detail = detail
	return f
}
