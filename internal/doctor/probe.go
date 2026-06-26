package doctor

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/manchtools/power-manage/server/internal/search"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

// PGProbe is the live-Postgres DBProbe. The pool connects lazily, so
// construction succeeds even when the database is down — the reachability verdict
// comes from Ping (a Critical finding), not from construction.
type PGProbe struct{ pool *pgxpool.Pool }

// NewPGProbe builds a Postgres probe from a DSN. Returns an error only when the
// DSN is empty/unparseable (a configuration problem, not "unreachable").
func NewPGProbe(ctx context.Context, dsn string) (*PGProbe, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("CONTROL_DATABASE_URL is empty")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	return &PGProbe{pool: pool}, nil
}

func (p *PGProbe) Ping(ctx context.Context) error { return p.pool.Ping(ctx) }

func (p *PGProbe) AdminUserExists(ctx context.Context, email string) (bool, error) {
	var exists bool
	err := p.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM users_projection WHERE email = $1 AND role = 'admin' AND NOT disabled AND NOT is_deleted)`,
		email).Scan(&exists)
	return exists, err
}

// Close releases the pool.
func (p *PGProbe) Close() {
	if p.pool != nil {
		p.pool.Close()
	}
}

// ValkeyProbe is the live-Valkey CacheProbe (RediSearch + Asynq inspector).
type ValkeyProbe struct {
	rdb       *redis.Client
	inspector *asynq.Inspector
	queues    []string
}

// NewValkeyProbe builds a Valkey probe. RESP2 is forced to match the indexer
// (RediSearch is RESP3-incompatible).
func NewValkeyProbe(addr, password string, db int) (*ValkeyProbe, error) {
	if strings.TrimSpace(addr) == "" {
		return nil, errors.New("CONTROL_VALKEY_ADDR is empty")
	}
	opt := asynq.RedisClientOpt{Addr: addr, Password: password, DB: db}
	return &ValkeyProbe{
		rdb:       redis.NewClient(&redis.Options{Addr: addr, Password: password, DB: db, Protocol: 2}),
		inspector: asynq.NewInspector(opt),
		queues:    []string{taskqueue.ControlInboxQueue, taskqueue.ControlTerminalAuditQueue, taskqueue.SearchQueue},
	}, nil
}

func (v *ValkeyProbe) Ping(ctx context.Context) error { return v.rdb.Ping(ctx).Err() }

func (v *ValkeyProbe) MissingIndexes(ctx context.Context, names []string) ([]string, error) {
	var missing []string
	for _, n := range names {
		if err := v.rdb.Do(ctx, "FT.INFO", n).Err(); err != nil {
			if indexNotFound(err) {
				missing = append(missing, n)
				continue
			}
			return nil, err
		}
	}
	return missing, nil
}

func (v *ValkeyProbe) SchemaCurrent(ctx context.Context) (bool, error) {
	stored, err := v.rdb.Get(ctx, search.SchemaFingerprintKey).Result()
	if errors.Is(err, redis.Nil) {
		return false, nil // never indexed
	}
	if err != nil {
		return false, err
	}
	return stored == search.SchemaFingerprint(), nil
}

func (v *ValkeyProbe) ArchivedByQueue(_ context.Context) (map[string]int, error) {
	out := map[string]int{}
	for _, q := range v.queues {
		info, err := v.inspector.GetQueueInfo(q)
		if err != nil {
			if queueNotFound(err) {
				continue // queue not created yet — nothing archived
			}
			return nil, err
		}
		out[q] = info.Archived
	}
	return out, nil
}

// LastReconcile reads the indexer heartbeat (search.LastReconcileKey, RFC3339).
func (v *ValkeyProbe) LastReconcile(ctx context.Context) (time.Time, bool, error) {
	raw, err := v.rdb.Get(ctx, search.LastReconcileKey).Result()
	if errors.Is(err, redis.Nil) {
		return time.Time{}, false, nil // never stamped
	}
	if err != nil {
		return time.Time{}, false, err
	}
	ts, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, false, err
	}
	return ts, true, nil
}

// Close releases the client + inspector.
func (v *ValkeyProbe) Close() {
	if v.rdb != nil {
		_ = v.rdb.Close()
	}
	if v.inspector != nil {
		_ = v.inspector.Close()
	}
}

// indexNotFound reports whether a RediSearch error means "no such index" (vs a
// real failure). valkey-search phrases it a few ways across versions.
func indexNotFound(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "unknown index") ||
		strings.Contains(s, "no such index") ||
		strings.Contains(s, "not found")
}

// queueNotFound reports whether an asynq inspector error means "queue not
// created yet" (a fresh deploy has none) rather than a real failure. The
// sentinel is matched first, but the inspector also returns a raw
// `NOT_FOUND: queue "x" does not exist` that errors.Is does NOT catch, so the
// string form is matched too (dead-branch error-sentinel guard).
func queueNotFound(err error) bool {
	if errors.Is(err, asynq.ErrQueueNotFound) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "does not exist") || strings.Contains(s, "queue not found")
}
