// Bootstrap admin-user creation. Extracted from main.go (audit F043 /
// #157, slice 5). This is the one-shot seed that runs when
// CONTROL_ADMIN_EMAIL + CONTROL_ADMIN_PASSWORD are set on a fresh
// deploy; subsequent boots short-circuit on GetUserByEmail.
package main

import (
	"context"
	"fmt"
	"log/slog"
	urlpkg "net/url"

	"github.com/oklog/ulid/v2"

	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
)

func ensureAdminUser(ctx context.Context, st *store.Store, email, password string, logger *slog.Logger) error {
	// Check if user exists via the projection
	_, err := st.Repos().User.GetByEmail(ctx, email)
	if err == nil {
		logger.Info("admin user already exists", "email", email)
		return nil
	}

	// Create admin user via event sourcing
	passwordHash, err := auth.HashPassword(password)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	id := ulid.Make().String()

	// Mint the user's DEK BEFORE the creation event: the event carries
	// PII (email) the sealer needs the key for (spec 19 AC 1/6).
	if err := st.MintUserDEK(ctx, id); err != nil {
		return fmt.Errorf("mint encryption key for bootstrap admin: %w", err)
	}

	// Look up Admin role BEFORE emitting the user-creation event so
	// the user INSERT and the role assignment land atomically inside
	// one projector tx (issue #135). If the role lookup fails (no
	// Admin role seeded yet?), log and proceed with no roles - the
	// Go projector treats a missing role_ids key the same as an
	// empty slice and skips the per-role INSERT loop.
	var roleIDs []string
	if adminRole, err := st.Repos().Role.GetByName(ctx, "Admin"); err == nil {
		roleIDs = []string{adminRole.ID}
	} else {
		logger.Warn("failed to look up Admin role for bootstrap user; user will be created with no roles",
			"user_id", id, "error", err)
	}

	// Append UserCreatedWithRoles compound event - the projector
	// inserts the user row AND the per-role assignment row in one tx.
	emailCopy := email
	passwordHashCopy := passwordHash
	role := "admin"
	err = st.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   id,
		EventType:  string(eventtypes.UserCreatedWithRoles),
		Data: payloads.UserCreatedWithRoles{
			Email:        &emailCopy,
			PasswordHash: &passwordHashCopy,
			Role:         &role,
			RoleIDs:      roleIDs,
		},
		ActorType: "system",
		ActorID:   "bootstrap",
	})
	if err != nil {
		return fmt.Errorf("create user event: %w", err)
	}

	logger.Info("admin user created", "email", email, "id", id)
	return nil
}

// maskDatabaseURL masks the password in a database URL for logging.
// Uses net/url parsing so URL-encoded credentials (e.g. passwords that
// contain ':' or '@') are handled correctly; the hand-rolled scan we
// had before could mangle those edge cases.
func maskDatabaseURL(raw string) string {
	u, err := urlpkg.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	if _, hasPassword := u.User.Password(); !hasPassword {
		return raw
	}
	u.User = urlpkg.UserPassword(u.User.Username(), "***")
	return u.String()
}
