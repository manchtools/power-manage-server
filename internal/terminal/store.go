// Package terminal provides the control-server side of the remote
// terminal feature: a session token store keyed in Valkey, the metadata
// schema for active sessions, and the helpers used by the
// ControlService RPC handlers (manchtools/power-manage-sdk#16,
// manchtools/power-manage-server#6).
//
// The token store is intentionally a thin wrapper over a small
// SessionBackend interface so handler tests can fake it without
// pulling in miniredis. The production wiring uses Valkey via the
// existing *redis.Client that the control server already maintains
// for RediSearch.
package terminal

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"
)

// DefaultTokenTTL is the lifetime of a freshly-minted session token.
// The web client must connect to the gateway WebSocket endpoint
// before this expires; the token is single-use after that and the
// session lives until StopTerminal/TerminateTerminalSession or the
// idle sweeper closes it.
const DefaultTokenTTL = 60 * time.Second

// keyPrefix is the Valkey key namespace for terminal session tokens.
// One key per session: pm:terminal:session:<session_id>.
const keyPrefix = "pm:terminal:session:"

// Errors returned by the store. Wrap with %w in callers; check with
// errors.Is.
var (
	// ErrTokenNotFound is returned when the supplied session_id has no
	// matching token (expired, never minted, or already revoked).
	ErrTokenNotFound = errors.New("terminal: session token not found")
	// ErrTokenMismatch is returned when the supplied bearer token does
	// not match the one stored under the session_id. Treated the same
	// as ErrTokenNotFound by callers — both surface as Unauthenticated
	// — but distinguished here so the audit log can record forgery
	// attempts separately from expired sessions.
	ErrTokenMismatch = errors.New("terminal: session token mismatch")
)

// Session is the persisted form of an active terminal session, stored
// in Valkey under pm:terminal:session:<session_id>. The bearer Token is
// hashed at rest, NOT stored verbatim, so a Valkey dump cannot be used
// to forge connections.
type Session struct {
	// SessionID is the ULID identifying the session for its full
	// lifetime (mint, validate, stop, audit).
	SessionID string `json:"session_id"`
	// UserID is the ID of the Power Manage user that opened the
	// session. Used for ownership checks (StopTerminal must be called
	// by the same user) and audit attribution.
	UserID string `json:"user_id"`
	// DeviceID is the target device the session will run on.
	DeviceID string `json:"device_id"`
	// TtyUser is the resolved dedicated TTY user
	// (e.g. "pm-tty-pdotterer") that the agent will spawn the shell
	// as. Carried in the session record so the gateway can pass it
	// through to the agent without re-resolving.
	TtyUser string `json:"tty_user"`
	// Cols and Rows are the initial window size requested by the web
	// client. Stored alongside the session so the gateway can include
	// them in the TerminalStart it sends to the agent without an
	// extra round-trip.
	Cols uint32 `json:"cols"`
	Rows uint32 `json:"rows"`
	// CreatedAt is the mint time. Used for diagnostics and audit; the
	// real expiry is enforced by Valkey TTL on the key.
	CreatedAt time.Time `json:"created_at"`
	// ExpiresAt is the absolute deadline for connecting. Mirrors the
	// Valkey TTL but is convenient to surface in StartTerminal's
	// response so the web client can decide when to retry.
	ExpiresAt time.Time `json:"expires_at"`
	// TokenHash is the SHA-256 hash of the bearer token. The plaintext
	// token is returned to the web client exactly once (in the
	// StartTerminal response) and never persisted.
	TokenHash string `json:"token_hash"`
}

// SessionBackend is the storage interface the token store depends on.
// Implementations must be safe for concurrent use. Two implementations
// ship with this package: ValkeyBackend (production) and FakeBackend
// (tests).
type SessionBackend interface {
	// Set stores the session with the given TTL. Implementations must
	// support TTL eviction so expired entries do not accumulate.
	Set(ctx context.Context, sessionID string, payload []byte, ttl time.Duration) error
	// Get returns the raw payload for the given session_id, or
	// ErrTokenNotFound if it has expired or was never set.
	Get(ctx context.Context, sessionID string) ([]byte, error)
	// Delete removes the session_id. Idempotent: returns nil whether
	// or not the key existed.
	Delete(ctx context.Context, sessionID string) error
	// GetAndDelete atomically returns the payload and removes the
	// session_id in one operation. Used by Validate to enforce
	// single-use tokens: two concurrent connect attempts with the
	// same bearer can only succeed once — the loser sees
	// ErrTokenNotFound. Implementations must use a primitive that
	// cannot race (Valkey GETDEL, an in-process mutex on the fake,
	// etc.). A naïve Get-then-Delete pair does NOT satisfy this
	// contract; returning a nil payload and nil error MUST be
	// translated to ErrTokenNotFound.
	GetAndDelete(ctx context.Context, sessionID string) ([]byte, error)
}

// TokenStore is the high-level façade used by the API handlers. It
// owns the SessionBackend, mints opaque bearer tokens, hashes them
// before storage, and serializes the Session metadata.
type TokenStore struct {
	backend SessionBackend
	ttl     time.Duration
	now     func() time.Time
}

// TokenStoreOption configures a TokenStore at construction time.
type TokenStoreOption func(*TokenStore)

// WithTTL overrides the default token lifetime. A non-positive value
// is treated as DefaultTokenTTL.
func WithTTL(ttl time.Duration) TokenStoreOption {
	return func(s *TokenStore) {
		if ttl > 0 {
			s.ttl = ttl
		}
	}
}

// WithClock overrides time.Now for tests.
func WithClock(now func() time.Time) TokenStoreOption {
	return func(s *TokenStore) {
		if now != nil {
			s.now = now
		}
	}
}

// NewTokenStore constructs a TokenStore over the given backend.
// Panics if backend is nil so misconfiguration is caught at startup
// rather than on the first Mint/Validate call.
func NewTokenStore(backend SessionBackend, opts ...TokenStoreOption) *TokenStore {
	if backend == nil {
		panic("terminal: NewTokenStore requires a non-nil SessionBackend")
	}
	s := &TokenStore{
		backend: backend,
		ttl:     DefaultTokenTTL,
		now:     time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// MintParams holds the per-session metadata captured at StartTerminal
// time. The TokenStore generates the SessionID and bearer token; the
// caller supplies everything else.
type MintParams struct {
	UserID   string
	DeviceID string
	TtyUser  string
	Cols     uint32
	Rows     uint32
}

// MintResult is what the StartTerminal handler hands back to the web
// client: the freshly-generated session_id and the plaintext bearer
// token (which the client appends to the gateway URL as ?token=).
type MintResult struct {
	SessionID string
	Token     string
	ExpiresAt time.Time
}

// Mint creates a new session with an auto-generated session ID,
// stores its hashed token + metadata, and returns the plaintext
// token to the caller. Use MintWithID when the caller needs to
// control the session ID (e.g. to write a CQRS event before
// minting the derived Valkey state).
func (s *TokenStore) Mint(ctx context.Context, params MintParams) (*MintResult, error) {
	return s.MintWithID(ctx, ulid.Make().String(), params)
}

// MintWithID is like Mint but uses the caller-supplied session ID
// instead of generating one. This supports the CQRS pattern where
// the event (source of truth) is written first with a known ID,
// and the Valkey token (derived state) is minted afterwards.
func (s *TokenStore) MintWithID(ctx context.Context, sessionID string, params MintParams) (*MintResult, error) {
	if sessionID == "" {
		return nil, errors.New("terminal: session_id is required")
	}
	if params.UserID == "" || params.DeviceID == "" || params.TtyUser == "" {
		return nil, errors.New("terminal: mint requires user_id, device_id, and tty_user")
	}

	token, err := generateOpaqueToken(32)
	if err != nil {
		return nil, fmt.Errorf("terminal: generate token: %w", err)
	}

	now := s.now()
	expiresAt := now.Add(s.ttl)
	session := Session{
		SessionID: sessionID,
		UserID:    params.UserID,
		DeviceID:  params.DeviceID,
		TtyUser:   params.TtyUser,
		Cols:      params.Cols,
		Rows:      params.Rows,
		CreatedAt: now,
		ExpiresAt: expiresAt,
		TokenHash: hashToken(token),
	}
	payload, err := json.Marshal(session)
	if err != nil {
		return nil, fmt.Errorf("terminal: marshal session: %w", err)
	}
	if err := s.backend.Set(ctx, sessionID, payload, s.ttl); err != nil {
		return nil, fmt.Errorf("terminal: persist session: %w", err)
	}
	return &MintResult{
		SessionID: sessionID,
		Token:     token,
		ExpiresAt: expiresAt,
	}, nil
}

// Lookup returns the stored Session for the given session_id, without
// validating the bearer token. Used by StopTerminal (where the caller
// is authenticated via JWT and ownership is checked against UserID),
// admin paths, and tests.
func (s *TokenStore) Lookup(ctx context.Context, sessionID string) (*Session, error) {
	payload, err := s.backend.Get(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	var session Session
	if err := json.Unmarshal(payload, &session); err != nil {
		return nil, fmt.Errorf("terminal: decode session %s: %w", sessionID, err)
	}
	return &session, nil
}

// Validate verifies that the supplied bearer token matches the one
// stored for the given session_id, atomically consumes the token on
// success, and returns the Session. Single-use: a second call with
// the same bearer returns ErrTokenNotFound even within the TTL.
//
// Distinguishes ErrTokenNotFound (expired, never minted, or already
// consumed) from ErrTokenMismatch (bearer forgery attempt) so the
// audit log can record forgeries separately. Used by the
// gateway-side InternalService.ValidateTerminalToken path.
//
// On mismatch the session entry is re-persisted with the same
// remaining TTL so a forged bearer cannot DoS a legitimate session
// that has not yet been claimed. (GETDEL has already removed it; if
// we did not re-set, the real client's subsequent Validate would
// hit ErrTokenNotFound.)
func (s *TokenStore) Validate(ctx context.Context, sessionID, bearerToken string) (*Session, error) {
	payload, err := s.backend.GetAndDelete(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	var session Session
	if err := json.Unmarshal(payload, &session); err != nil {
		return nil, fmt.Errorf("terminal: decode session %s: %w", sessionID, err)
	}
	if subtle.ConstantTimeCompare([]byte(session.TokenHash), []byte(hashToken(bearerToken))) != 1 {
		// Forgery attempt — restore the real session so the
		// legitimate client isn't locked out. Compute the remaining
		// TTL from ExpiresAt; if already expired we just drop it.
		remaining := session.ExpiresAt.Sub(s.now())
		if remaining > 0 {
			if restoreErr := s.backend.Set(ctx, sessionID, payload, remaining); restoreErr != nil {
				// Log via caller — we don't have a logger here. Returning
				// mismatch is the priority; the caller surfaces it as
				// Unauthenticated and the audit pipeline flags it.
				return nil, ErrTokenMismatch
			}
		}
		return nil, ErrTokenMismatch
	}
	return &session, nil
}

// Revoke removes the session entry, making subsequent Validate /
// Lookup calls return ErrTokenNotFound. Idempotent — revoking an
// unknown session returns nil.
func (s *TokenStore) Revoke(ctx context.Context, sessionID string) error {
	return s.backend.Delete(ctx, sessionID)
}

// generateOpaqueToken returns a base64url-encoded random byte string.
// 32 bytes of entropy is well above the 128-bit threshold for
// unguessable session tokens.
func generateOpaqueToken(numBytes int) (string, error) {
	buf := make([]byte, numBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
