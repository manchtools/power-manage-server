package doctor

import (
	"bufio"
	"context"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/manchtools/power-manage/server/internal/store"
)

// Env is the read-only view the checks run against: a merged config map (process
// env overlaid with a deploy `.env` file when one is found), the cert/key files
// to inspect, optional live probes, and a clock seam. Built by the subcommand;
// constructed directly with fakes in tests.
type Env struct {
	vars map[string]string

	// CertFiles / KeyFiles are absolute paths the cert checks inspect (resolved
	// from CONTROL_CA_CERT/KEY, CONTROL_INTERNAL_TLS_CERT/KEY, plus any siblings
	// in the certs directory).
	CertFiles []string
	KeyFiles  []string

	// DB / Cache are nil when they could not be constructed (no DSN/addr) or in
	// pure-config tests; live checks treat nil as "datastore unavailable".
	DB    DBProbe
	Cache CacheProbe

	// FromEnvFile records whether a .env file was loaded (so the .env-only checks
	// can report "no .env file found" rather than a false pass).
	FromEnvFile bool

	Now func() time.Time
}

// timeNow is the package clock seam (WS0): runtime code never calls time.Now()
// directly. Tests override Env.Now; this is the production default.
var timeNow = time.Now

// NewEnv builds an Env from an already-merged vars map.
func NewEnv(vars map[string]string) *Env {
	if vars == nil {
		vars = map[string]string{}
	}
	return &Env{vars: vars, Now: timeNow}
}

// Get returns the merged value for key ("" if unset).
func (e *Env) Get(key string) string { return e.vars[key] }

// Has reports whether key is present (even if empty).
func (e *Env) Has(key string) bool { _, ok := e.vars[key]; return ok }

// now returns the clock (defaulting to the package seam if unset).
func (e *Env) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return timeNow()
}

// ProcessEnv snapshots os.Environ into a map.
func ProcessEnv() map[string]string {
	out := map[string]string{}
	for _, kv := range os.Environ() {
		if i := strings.IndexByte(kv, '='); i >= 0 {
			out[kv[:i]] = kv[i+1:]
		}
	}
	return out
}

// LoadEnvFile parses a minimal KEY=VALUE `.env` file (no shell expansion). Lines
// that are blank, comments (`#`), or lack `=` are skipped; surrounding quotes and
// an optional leading `export ` are stripped. Returns (nil, nil) if the file does
// not exist — a missing .env is not an error (the doctor may run in-container).
func LoadEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		i := strings.IndexByte(line, '=')
		if i < 0 {
			continue
		}
		k := strings.TrimSpace(line[:i])
		v := strings.TrimSpace(line[i+1:])
		v = strings.Trim(v, `"'`)
		if k != "" {
			out[k] = v
		}
	}
	return out, sc.Err()
}

// MergeVars overlays b onto a copy of a (b wins) — used to overlay a deploy .env
// file on top of the process environment so the operator's stored config is the
// source of truth for what they configured.
func MergeVars(a, b map[string]string) map[string]string {
	out := make(map[string]string, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// dsnPassword extracts the password from a postgres DSN, or "" if none/unparsable.
// Used to judge the DB password embedded in CONTROL_DATABASE_URL without ever
// echoing it.
func dsnPassword(dsn string) string {
	if dsn == "" {
		return ""
	}
	u, err := url.Parse(dsn)
	if err != nil || u.User == nil {
		return ""
	}
	pw, _ := u.User.Password()
	return pw
}

// DBProbe is the narrow live-Postgres surface the DB checks need.
type DBProbe interface {
	Ping(ctx context.Context) error
	// AdminUserExists reports whether an enabled admin user with the given email
	// exists (used to flag the bootstrap default).
	AdminUserExists(ctx context.Context, email string) (bool, error)
	// LiveUserWrappedDEKs returns every non-deleted user with its wrapped DEK
	// (empty when absent) — the DEK invariant check unwraps each (spec 19 AC 30).
	LiveUserWrappedDEKs(ctx context.Context) ([]store.UserDEK, error)
	// DeletedUsersWithDEK returns erased users that still hold a DEK row — the
	// resurrected-shredded-key anomaly (spec 19 AC 31).
	DeletedUsersWithDEK(ctx context.Context) ([]string, error)
	// ProjectionDrift compares each rebuild target's projection high-water
	// against the events it should have applied (spec 19 AC 31a).
	ProjectionDrift(ctx context.Context) ([]store.TargetDrift, error)
	// RetentionPosture reports event-log size/age and the last prune
	// (spec 19 AC 29).
	RetentionPosture(ctx context.Context) (store.RetentionPosture, error)
}

// CacheProbe is the narrow live-Valkey surface the cache/search/queue checks need.
type CacheProbe interface {
	Ping(ctx context.Context) error
	// MissingIndexes returns which of names have no FT.INFO (i.e. are absent).
	MissingIndexes(ctx context.Context, names []string) ([]string, error)
	// SchemaCurrent reports whether the indexed schema fingerprint matches the
	// running code (false ⇒ the indexer needs to rebuild).
	SchemaCurrent(ctx context.Context) (bool, error)
	// ArchivedByQueue returns the archived (dead-letter) task count per queue.
	ArchivedByQueue(ctx context.Context) (map[string]int, error)
	// LastReconcile returns when the indexer last completed a reconcile and
	// whether that heartbeat is present (absent ⇒ never stamped / pre-heartbeat
	// indexer). Used to detect a dead/stuck indexer.
	LastReconcile(ctx context.Context) (time.Time, bool, error)
	// SearchQueryRejections runs each named index's real match-all query and
	// returns the indexes whose query the engine REJECTED, mapped to the error
	// (e.g. a valkey-search version that doesn't accept the query syntax). This
	// is the FUNCTIONAL probe — index-presence/freshness checks miss a search
	// that is present but cannot answer. Missing indexes are skipped (covered by
	// MissingIndexes).
	SearchQueryRejections(ctx context.Context, indexNames []string) (map[string]string, error)
	// KeyspaceNotifications returns Valkey's notify-keyspace-events config value
	// (empty = off, the Redis default). Traefik's Redis provider WATCHES the
	// gateway's self-registered routes via keyspace notifications, so an empty
	// value silently breaks dynamic gateway routing (incl. the terminal route).
	KeyspaceNotifications(ctx context.Context) (string, error)
}
