package terminal

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestTokenStore_MintLookupRoundTrip(t *testing.T) {
	store := NewTokenStore(NewFakeBackend(nil))
	ctx := context.Background()

	res, err := store.Mint(ctx, MintParams{
		UserID:   "user-1",
		DeviceID: "device-1",
		TtyUser:  "pm-tty-alice",
		Cols:     80,
		Rows:     24,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if res.SessionID == "" {
		t.Error("session_id should be populated")
	}
	if res.Token == "" {
		t.Error("token should be populated")
	}

	got, err := store.Lookup(ctx, res.SessionID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if got.UserID != "user-1" || got.DeviceID != "device-1" || got.TtyUser != "pm-tty-alice" {
		t.Errorf("session metadata mismatch: %+v", got)
	}
	if got.Cols != 80 || got.Rows != 24 {
		t.Errorf("size = %dx%d, want 80x24", got.Cols, got.Rows)
	}
}

func TestTokenStore_TokenIsHashedNotPlaintext(t *testing.T) {
	backend := NewFakeBackend(nil)
	store := NewTokenStore(backend)
	ctx := context.Background()

	res, err := store.Mint(ctx, MintParams{
		UserID:   "user-1",
		DeviceID: "device-1",
		TtyUser:  "pm-tty-alice",
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	// The persisted payload must NOT contain the plaintext token.
	raw, err := backend.Get(ctx, res.SessionID)
	if err != nil {
		t.Fatalf("backend get: %v", err)
	}
	if string(raw) == "" {
		t.Fatal("backend payload empty")
	}
	if strings.Contains(string(raw), res.Token) {
		t.Error("plaintext token must not appear in persisted payload")
	}
}

func TestTokenStore_Validate_RoundTrip(t *testing.T) {
	store := NewTokenStore(NewFakeBackend(nil))
	ctx := context.Background()

	res, err := store.Mint(ctx, MintParams{
		UserID:   "user-1",
		DeviceID: "device-1",
		TtyUser:  "pm-tty-alice",
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	session, err := store.Validate(ctx, res.SessionID, res.Token)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if session.UserID != "user-1" {
		t.Errorf("validated session = %+v", session)
	}
}

func TestTokenStore_Validate_MismatchedToken(t *testing.T) {
	store := NewTokenStore(NewFakeBackend(nil))
	ctx := context.Background()

	res, err := store.Mint(ctx, MintParams{
		UserID:   "user-1",
		DeviceID: "device-1",
		TtyUser:  "pm-tty-alice",
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	_, err = store.Validate(ctx, res.SessionID, "wrong-token")
	if !errors.Is(err, ErrTokenMismatch) {
		t.Errorf("expected ErrTokenMismatch, got %v", err)
	}
}

func TestTokenStore_Validate_UnknownSession(t *testing.T) {
	store := NewTokenStore(NewFakeBackend(nil))
	_, err := store.Validate(context.Background(), "no-such-session", "anything")
	if !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("expected ErrTokenNotFound, got %v", err)
	}
}

func TestTokenStore_Revoke_IsIdempotent(t *testing.T) {
	store := NewTokenStore(NewFakeBackend(nil))
	ctx := context.Background()

	res, err := store.Mint(ctx, MintParams{
		UserID:   "user-1",
		DeviceID: "device-1",
		TtyUser:  "pm-tty-alice",
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	if err := store.Revoke(ctx, res.SessionID); err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	// Second revoke must succeed too.
	if err := store.Revoke(ctx, res.SessionID); err != nil {
		t.Errorf("second revoke (idempotent) returned %v", err)
	}
	// And subsequent lookup must report not found.
	if _, err := store.Lookup(ctx, res.SessionID); !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("after revoke, expected ErrTokenNotFound, got %v", err)
	}
}

func TestTokenStore_TTLExpiry(t *testing.T) {
	// Frozen clock so we can advance it deterministically.
	now := time.Unix(0, 0)
	clock := func() time.Time { return now }
	backend := NewFakeBackend(clock)
	store := NewTokenStore(backend, WithClock(clock), WithTTL(10*time.Second))
	ctx := context.Background()

	res, err := store.Mint(ctx, MintParams{
		UserID:   "user-1",
		DeviceID: "device-1",
		TtyUser:  "pm-tty-alice",
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	// Still valid at t+5s.
	now = now.Add(5 * time.Second)
	if _, err := store.Lookup(ctx, res.SessionID); err != nil {
		t.Errorf("lookup at t+5s: %v", err)
	}

	// Expired at t+11s.
	now = now.Add(6 * time.Second)
	if _, err := store.Lookup(ctx, res.SessionID); !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("lookup at t+11s: expected ErrTokenNotFound, got %v", err)
	}
}

func TestTokenStore_Mint_RequiresFields(t *testing.T) {
	store := NewTokenStore(NewFakeBackend(nil))
	ctx := context.Background()
	cases := []MintParams{
		{DeviceID: "d", TtyUser: "u"},          // no UserID
		{UserID: "u", TtyUser: "u"},            // no DeviceID
		{UserID: "u", DeviceID: "d"},           // no TtyUser
	}
	for i, p := range cases {
		if _, err := store.Mint(ctx, p); err == nil {
			t.Errorf("case %d: expected error for %+v", i, p)
		}
	}
}

func TestTokenStore_MintGeneratesUniqueIDs(t *testing.T) {
	store := NewTokenStore(NewFakeBackend(nil))
	ctx := context.Background()
	seen := make(map[string]struct{})
	for i := 0; i < 100; i++ {
		res, err := store.Mint(ctx, MintParams{
			UserID:   "user-1",
			DeviceID: "device-1",
			TtyUser:  "pm-tty-alice",
		})
		if err != nil {
			t.Fatalf("mint %d: %v", i, err)
		}
		if _, dup := seen[res.SessionID]; dup {
			t.Fatalf("duplicate session_id %s on iter %d", res.SessionID, i)
		}
		seen[res.SessionID] = struct{}{}
	}
}

