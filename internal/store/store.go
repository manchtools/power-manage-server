// Package store provides database access for the control server.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // pgx database/sql driver
	"github.com/pressly/goose/v3"

	"github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/store/migrations"
)

// Re-export generated types for convenience
type Queries = generated.Queries

// Event represents a domain event.
type Event struct {
	StreamType string
	StreamID   string
	EventType  string
	Data       map[string]any
	Metadata   map[string]any
	ActorType  string
	ActorID    string
}

// Notification represents a PostgreSQL NOTIFY payload.
type Notification struct {
	Channel string
	Payload string
}

// NotificationHandler handles incoming notifications.
type NotificationHandler func(channel, payload string)

// listenCommand represents a LISTEN or UNLISTEN command to be executed.
type listenCommand struct {
	channel  string
	unlisten bool
	done     chan error
}

// Store wraps the database connection and provides access to queries.
type Store struct {
	pool    *pgxpool.Pool
	queries *Queries

	// Listener management
	listenerMu    sync.Mutex
	listenerConn  *pgx.Conn
	handlers      map[string][]NotificationHandler
	listening     bool
	listenCmdChan chan listenCommand // Channel for sending LISTEN/UNLISTEN commands
}

// New creates a new Store and runs migrations.
// This should only be called by the control server which is responsible for database schema management.
func New(ctx context.Context, connString string) (*Store, error) {
	// Create connection pool
	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return nil, fmt.Errorf("create connection pool: %w", err)
	}

	// Verify connection
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	// Run migrations using a standard database/sql connection
	// Goose doesn't support pgx directly, so we use the stdlib adapter
	sqlDB, err := sql.Open("pgx", connString)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("open database for migrations: %w", err)
	}
	defer sqlDB.Close()

	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		pool.Close()
		return nil, fmt.Errorf("set goose dialect: %w", err)
	}
	if err := goose.Up(sqlDB, "."); err != nil {
		pool.Close()
		return nil, fmt.Errorf("run migrations: %w", err)
	}

	return &Store{
		pool:     pool,
		queries:  generated.New(pool),
		handlers: make(map[string][]NotificationHandler),
	}, nil
}

// NewWithoutMigrations creates a new Store without running migrations.
// This should be used by services that only consume the database (e.g., gateway)
// and don't manage the schema.
func NewWithoutMigrations(ctx context.Context, connString string) (*Store, error) {
	// Create connection pool
	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return nil, fmt.Errorf("create connection pool: %w", err)
	}

	// Verify connection
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return &Store{
		pool:     pool,
		queries:  generated.New(pool),
		handlers: make(map[string][]NotificationHandler),
	}, nil
}

// Queries returns the SQLC queries interface.
// For RLS-aware queries, use QueriesFromContext instead.
func (s *Store) Queries() *Queries {
	return s.queries
}

type queriesContextKey struct{}

// ContextWithQueries stores RLS-scoped queries in the context.
func ContextWithQueries(ctx context.Context, q *Queries) context.Context {
	return context.WithValue(ctx, queriesContextKey{}, q)
}

// QueriesFromContext returns RLS-scoped queries from context if set,
// otherwise falls back to the store's default (pool-backed) queries.
func (s *Store) QueriesFromContext(ctx context.Context) *Queries {
	if q, ok := ctx.Value(queriesContextKey{}).(*Queries); ok && q != nil {
		return q
	}
	return s.queries
}

// Pool returns the underlying connection pool.
func (s *Store) Pool() *pgxpool.Pool {
	return s.pool
}

// Close closes the database connection.
func (s *Store) Close() {
	s.listenerMu.Lock()
	if s.listenerConn != nil {
		s.listenerConn.Close(context.Background())
		s.listenerConn = nil
	}
	s.listening = false
	s.listenerMu.Unlock()

	s.pool.Close()
}

// WithTx runs a function within a transaction.
func (s *Store) WithTx(ctx context.Context, fn func(*Queries) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	if err := fn(s.queries.WithTx(tx)); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

// AppendEvent appends a new event to the event store.
// It handles optimistic locking by checking the expected version.
// Retries automatically on version conflicts (up to 5 times).
func (s *Store) AppendEvent(ctx context.Context, event Event) error {
	if event.ActorType == "" || event.ActorID == "" {
		return fmt.Errorf("event actor_type and actor_id are required")
	}

	// Marshal event data once (doesn't change on retry)
	data, err := json.Marshal(event.Data)
	if err != nil {
		return fmt.Errorf("marshal event data: %w", err)
	}

	metadata := []byte("{}")
	if event.Metadata != nil {
		metadata, err = json.Marshal(event.Metadata)
		if err != nil {
			return fmt.Errorf("marshal event metadata: %w", err)
		}
	}

	// Retry loop for handling version conflicts
	// NOTE: Intentionally uses s.queries (pool-backed, no RLS session) rather
	// than QueriesFromContext. The events table has FORCE ROW LEVEL SECURITY and
	// the events_select policy restricts non-admin users to only their own events.
	// Using the session connection would return a stale version (missing other
	// actors' events), causing perpetual version conflicts.
	const maxRetries = 5
	for attempt := 0; attempt < maxRetries; attempt++ {
		// Get current version
		version, err := s.queries.GetStreamVersion(ctx, generated.GetStreamVersionParams{
			StreamType: event.StreamType,
			StreamID:   event.StreamID,
		})
		if err != nil {
			return fmt.Errorf("get stream version: %w", err)
		}

		// Append event with next version
		_, err = s.queries.AppendEvent(ctx, generated.AppendEventParams{
			StreamType:    event.StreamType,
			StreamID:      event.StreamID,
			StreamVersion: version + 1,
			EventType:     event.EventType,
			Data:          data,
			Metadata:      metadata,
			ActorType:     event.ActorType,
			ActorID:       event.ActorID,
		})
		if err == nil {
			return nil
		}

		// Check for version conflict (unique constraint violation)
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			// Retry on version conflict
			if attempt < maxRetries-1 {
				continue
			}
			return fmt.Errorf("version conflict after %d retries: stream was modified concurrently", maxRetries)
		}
		return fmt.Errorf("append event: %w", err)
	}

	return nil
}

// AppendEventWithVersion appends an event with an expected version for optimistic locking.
func (s *Store) AppendEventWithVersion(ctx context.Context, event Event, expectedVersion int32) error {
	// Marshal event data
	data, err := json.Marshal(event.Data)
	if err != nil {
		return fmt.Errorf("marshal event data: %w", err)
	}

	metadata := []byte("{}")
	if event.Metadata != nil {
		metadata, err = json.Marshal(event.Metadata)
		if err != nil {
			return fmt.Errorf("marshal event metadata: %w", err)
		}
	}

	// Append event with specified version
	_, err = s.queries.AppendEvent(ctx, generated.AppendEventParams{
		StreamType:    event.StreamType,
		StreamID:      event.StreamID,
		StreamVersion: expectedVersion,
		EventType:     event.EventType,
		Data:          data,
		Metadata:      metadata,
		ActorType:     event.ActorType,
		ActorID:       event.ActorID,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("version conflict: expected version %d but stream was modified", expectedVersion)
		}
		return fmt.Errorf("append event: %w", err)
	}

	return nil
}

// Listen registers a handler for PostgreSQL NOTIFY on the given channel pattern.
// Channel patterns can use '*' as a wildcard suffix (e.g., "agent_*").
func (s *Store) Listen(ctx context.Context, channelPattern string, handler NotificationHandler) error {
	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()

	// Register handler
	s.handlers[channelPattern] = append(s.handlers[channelPattern], handler)

	// Start listener if not already running
	if !s.listening {
		if err := s.startListener(ctx); err != nil {
			return err
		}
	}

	return nil
}

// startListener starts the background notification listener.
func (s *Store) startListener(ctx context.Context) error {
	// Create a dedicated connection for listening
	conn, err := pgx.Connect(ctx, s.pool.Config().ConnString())
	if err != nil {
		return fmt.Errorf("create listener connection: %w", err)
	}
	s.listenerConn = conn
	s.listening = true
	s.listenCmdChan = make(chan listenCommand, 100)

	// Subscribe to all channels we're interested in
	for pattern := range s.handlers {
		channel := pattern
		// For wildcard patterns, we need to listen to a base channel
		// PostgreSQL doesn't support wildcards in LISTEN, so we'll filter in the handler
		if strings.HasSuffix(pattern, "*") {
			// We'll listen to a generic channel and filter
			// For now, listen to individual channels as they come
			continue
		}
		if _, err := conn.Exec(ctx, fmt.Sprintf("LISTEN %s", pgx.Identifier{channel}.Sanitize())); err != nil {
			conn.Close(ctx)
			s.listenerConn = nil
			s.listening = false
			return fmt.Errorf("listen to channel %s: %w", channel, err)
		}
	}

	// Start notification processing goroutine
	go s.processNotifications(ctx)

	return nil
}

// processNotifications processes incoming notifications and LISTEN/UNLISTEN commands.
func (s *Store) processNotifications(ctx context.Context) {
	for {
		s.listenerMu.Lock()
		conn := s.listenerConn
		cmdChan := s.listenCmdChan
		s.listenerMu.Unlock()

		if conn == nil {
			return
		}

		// Process any pending LISTEN/UNLISTEN commands first
		// This is done in a non-blocking way to avoid missing notifications
	drainCommands:
		for {
			select {
			case cmd := <-cmdChan:
				var err error
				if cmd.unlisten {
					_, err = conn.Exec(ctx, fmt.Sprintf("UNLISTEN %s", pgx.Identifier{cmd.channel}.Sanitize()))
				} else {
					_, err = conn.Exec(ctx, fmt.Sprintf("LISTEN %s", pgx.Identifier{cmd.channel}.Sanitize()))
				}
				if cmd.done != nil {
					cmd.done <- err
					close(cmd.done)
				}
			default:
				break drainCommands
			}
		}

		// Wait for notification with a short timeout so we can check for commands
		waitCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		notification, err := conn.WaitForNotification(waitCtx)
		cancel()

		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// Timeout is expected - just loop again to check for commands
			if waitCtx.Err() == context.DeadlineExceeded {
				continue
			}
			// Connection lost, try to reconnect
			s.listenerMu.Lock()
			if s.listenerConn != nil {
				s.listenerConn.Close(context.Background())
				s.listenerConn = nil
			}
			s.listening = false
			s.listenerMu.Unlock()
			return
		}

		// Dispatch to handlers
		s.listenerMu.Lock()
		for pattern, handlers := range s.handlers {
			if s.matchChannel(pattern, notification.Channel) {
				for _, handler := range handlers {
					go handler(notification.Channel, notification.Payload)
				}
			}
		}
		s.listenerMu.Unlock()
	}
}

// matchChannel checks if a channel matches a pattern.
func (s *Store) matchChannel(pattern, channel string) bool {
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(channel, prefix)
	}
	return pattern == channel
}

// ListenChannel subscribes to a specific channel and starts listening.
func (s *Store) ListenChannel(ctx context.Context, channel string) error {
	s.listenerMu.Lock()
	cmdChan := s.listenCmdChan
	listening := s.listening
	s.listenerMu.Unlock()

	if !listening || cmdChan == nil {
		return fmt.Errorf("listener not started")
	}

	// Send command to the notification goroutine
	done := make(chan error, 1)
	select {
	case cmdChan <- listenCommand{channel: channel, unlisten: false, done: done}:
	case <-ctx.Done():
		return ctx.Err()
	}

	// Wait for completion
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("listen to channel %s: %w", channel, err)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// UnlistenChannel unsubscribes from a specific channel.
func (s *Store) UnlistenChannel(ctx context.Context, channel string) error {
	s.listenerMu.Lock()
	cmdChan := s.listenCmdChan
	listening := s.listening
	s.listenerMu.Unlock()

	if !listening || cmdChan == nil {
		return nil
	}

	// Send command to the notification goroutine
	done := make(chan error, 1)
	select {
	case cmdChan <- listenCommand{channel: channel, unlisten: true, done: done}:
	case <-ctx.Done():
		return ctx.Err()
	}

	// Wait for completion
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("unlisten channel %s: %w", channel, err)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// StartListener starts the notification listener for the given channels.
func (s *Store) StartListener(ctx context.Context, channels []string, handler NotificationHandler) error {
	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()

	// Create a dedicated connection for listening
	conn, err := pgx.Connect(ctx, s.pool.Config().ConnString())
	if err != nil {
		return fmt.Errorf("create listener connection: %w", err)
	}
	s.listenerConn = conn
	s.listening = true

	// Subscribe to all channels
	for _, channel := range channels {
		if _, err := conn.Exec(ctx, fmt.Sprintf("LISTEN %s", pgx.Identifier{channel}.Sanitize())); err != nil {
			conn.Close(ctx)
			s.listenerConn = nil
			s.listening = false
			return fmt.Errorf("listen to channel %s: %w", channel, err)
		}
		s.handlers[channel] = append(s.handlers[channel], handler)
	}

	// Start notification processing goroutine
	go s.processNotifications(ctx)

	return nil
}

// ============================================================================
// SESSION CONTEXT FOR ROW-LEVEL SECURITY
// ============================================================================

// SessionContext holds the current user's identity for RLS policies.
type SessionContext struct {
	UserID string
	Role   string
}

// SetSessionContext sets the session context for RLS policies.
// This must be called at the start of each request to enable proper row filtering.
func (s *Store) SetSessionContext(ctx context.Context, sc SessionContext) error {
	_, err := s.pool.Exec(ctx, "SELECT set_session_context($1, $2)", sc.UserID, sc.Role)
	if err != nil {
		return fmt.Errorf("set session context: %w", err)
	}
	return nil
}

// WithSessionContext runs a function with the session context set for RLS.
// This is the preferred way to execute queries that need RLS filtering.
func (s *Store) WithSessionContext(ctx context.Context, sc SessionContext, fn func() error) error {
	// Acquire a connection from the pool
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire connection: %w", err)
	}
	defer conn.Release()

	// Set session context on this connection
	_, err = conn.Exec(ctx, "SELECT set_session_context($1, $2)", sc.UserID, sc.Role)
	if err != nil {
		return fmt.Errorf("set session context: %w", err)
	}

	// Run the function
	return fn()
}

// QueriesWithContext returns queries that will use the session context.
// Note: The caller must ensure SetSessionContext was called on the same connection.
func (s *Store) QueriesWithContext(ctx context.Context, sc SessionContext) (*Queries, error) {
	// For proper RLS, we need to use a dedicated connection
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire connection: %w", err)
	}

	// Set session context
	_, err = conn.Exec(ctx, "SELECT set_session_context($1, $2)", sc.UserID, sc.Role)
	if err != nil {
		conn.Release()
		return nil, fmt.Errorf("set session context: %w", err)
	}

	// Return queries using this connection
	// Note: caller is responsible for releasing the connection
	return generated.New(conn), nil
}

// ConnWithSession acquires a connection and sets session context.
// The caller must call release() when done.
type ConnWithSession struct {
	conn    *pgxpool.Conn
	queries *Queries
}

// AcquireWithSession acquires a connection with session context set for RLS.
func (s *Store) AcquireWithSession(ctx context.Context, sc SessionContext) (*ConnWithSession, error) {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire connection: %w", err)
	}

	// Set session context
	_, err = conn.Exec(ctx, "SELECT set_session_context($1, $2)", sc.UserID, sc.Role)
	if err != nil {
		conn.Release()
		return nil, fmt.Errorf("set session context: %w", err)
	}

	return &ConnWithSession{
		conn:    conn,
		queries: generated.New(conn),
	}, nil
}

// Queries returns the SQLC queries for this connection.
func (c *ConnWithSession) Queries() *Queries {
	return c.queries
}

// Release clears the session context and releases the connection back to the pool.
func (c *ConnWithSession) Release() {
	// Reset session context before returning to pool to prevent stale
	// role/user_id leaking into subsequent requests that reuse this connection.
	_, _ = c.conn.Exec(context.Background(), "SELECT set_session_context('', '')")
	c.conn.Release()
}

// SystemSessionContext returns a session context for system operations
// that bypass RLS (used for triggers, migrations, etc.)
func SystemSessionContext() SessionContext {
	return SessionContext{
		UserID: "system",
		Role:   "system",
	}
}

// AdminSessionContext returns a session context for admin operations.
func AdminSessionContext(userID string) SessionContext {
	return SessionContext{
		UserID: userID,
		Role:   "admin",
	}
}

// UserSessionContext returns a session context for regular user operations.
func UserSessionContext(userID string) SessionContext {
	return SessionContext{
		UserID: userID,
		Role:   "user",
	}
}

// DeviceSessionContext returns a session context for device operations.
func DeviceSessionContext(deviceID string) SessionContext {
	return SessionContext{
		UserID: deviceID,
		Role:   "device",
	}
}

// Notify sends a notification to a PostgreSQL channel.
func (s *Store) Notify(ctx context.Context, channel, payload string) error {
	_, err := s.pool.Exec(ctx, "SELECT pg_notify($1, $2)", channel, payload)
	if err != nil {
		return fmt.Errorf("pg_notify: %w", err)
	}
	return nil
}
