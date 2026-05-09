package projectors_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/projectors"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// ============================================================================
// Pure decoder tests — pin the field defaults that match the deleted
// PL/pgSQL project_user_event() COALESCE / NULL semantics.
// ============================================================================

// TestUserCreatedFromEvent_Pure pins the decoder defaults: missing
// password_hash → "" (drives has_password=false), missing role → "user"
// (matches PL/pgSQL `COALESCE(role, "user")`), profile fields each
// default to "", linux_uid → 0.
func TestUserCreatedFromEvent_Pure(t *testing.T) {
	t.Run("happy path with all fields", func(t *testing.T) {
		got, err := projectors.UserCreatedFromEvent(store.PersistedEvent{
			StreamType: "user", StreamID: "u-1", EventType: "UserCreated", ActorID: "actor",
			Data: jsonOrFail(t, map[string]any{
				"email":              "a@b.com",
				"password_hash":      "hash-1",
				"role":               "admin",
				"display_name":       "Alice",
				"given_name":         "Al",
				"family_name":        "Ice",
				"preferred_username": "alice",
				"picture":            "http://x/pic.jpg",
				"locale":             "en-US",
				"linux_username":     "alice",
				"linux_uid":          1001,
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, "u-1", got.ID)
		assert.Equal(t, "a@b.com", got.Email)
		assert.Equal(t, "hash-1", got.PasswordHash)
		assert.Equal(t, "admin", got.Role)
		assert.Equal(t, "Alice", got.DisplayName)
		assert.Equal(t, "alice", got.PreferredUsername)
		assert.Equal(t, "alice", got.LinuxUsername)
		assert.Equal(t, int32(1001), got.LinuxUID)
	})

	t.Run("defaults: missing password_hash → '', role → 'user', profile → '', linux_uid → 0", func(t *testing.T) {
		got, err := projectors.UserCreatedFromEvent(store.PersistedEvent{
			StreamType: "user", StreamID: "u-2", EventType: "UserCreated",
			Data: jsonOrFail(t, map[string]any{"email": "x@y.com"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "", got.PasswordHash)
		assert.Equal(t, "user", got.Role, "missing role must default to 'user'")
		assert.Equal(t, "", got.DisplayName)
		assert.Equal(t, "", got.LinuxUsername)
		assert.Equal(t, int32(0), got.LinuxUID)
	})

	t.Run("missing email fails", func(t *testing.T) {
		_, err := projectors.UserCreatedFromEvent(store.PersistedEvent{
			StreamType: "user", StreamID: "u-3", EventType: "UserCreated",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
		assert.Contains(t, err.Error(), "email")
	})

	t.Run("explicit empty email + role round-trip verbatim (PL/pgSQL parity)", func(t *testing.T) {
		// PL/pgSQL `event.data->>'role'` returns "" for an explicit
		// empty string — COALESCE doesn't kick in (which only handles
		// SQL NULL i.e. missing keys). Reject explicit "" would
		// silently rewrite historical replay events. Same for email
		// (which would have been INSERTed as ""). CR catch on PR #183.
		got, err := projectors.UserCreatedFromEvent(store.PersistedEvent{
			StreamType: "user", StreamID: "u-empty", EventType: "UserCreated",
			Data: jsonOrFail(t, map[string]any{"email": "", "role": ""}),
		})
		require.NoError(t, err)
		assert.Equal(t, "", got.Email, "explicit empty email must round-trip as \"\"")
		assert.Equal(t, "", got.Role, "explicit empty role must round-trip as \"\" (default 'user' only kicks in for missing key)")
	})

	t.Run("wrong stream/event type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.UserCreatedFromEvent(store.PersistedEvent{
			StreamType: "device", EventType: "UserCreated",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
		_, err = projectors.UserCreatedFromEvent(store.PersistedEvent{
			StreamType: "user", EventType: "UserDisabled",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})

	t.Run("malformed payload bytes is a validation error", func(t *testing.T) {
		_, err := projectors.UserCreatedFromEvent(store.PersistedEvent{
			StreamType: "user", EventType: "UserCreated",
			Data: []byte("not json"),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestUserProfileUpdatedFromEvent_Pure — every profile field defaults
// to "" when missing (matches PL/pgSQL COALESCE-to-"").
func TestUserProfileUpdatedFromEvent_Pure(t *testing.T) {
	t.Run("happy path with all fields", func(t *testing.T) {
		got, err := projectors.UserProfileUpdatedFromEvent(store.PersistedEvent{
			StreamType: "user", StreamID: "u-1", EventType: "UserProfileUpdated",
			Data: jsonOrFail(t, map[string]any{
				"display_name":       "Bob",
				"given_name":         "Bob",
				"family_name":        "Smith",
				"preferred_username": "bobby",
				"picture":            "p",
				"locale":             "de",
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, "Bob", got.DisplayName)
		assert.Equal(t, "Smith", got.FamilyName)
		assert.Equal(t, "de", got.Locale)
	})

	t.Run("missing keys default to ''", func(t *testing.T) {
		got, err := projectors.UserProfileUpdatedFromEvent(store.PersistedEvent{
			StreamType: "user", StreamID: "u-1", EventType: "UserProfileUpdated",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.NoError(t, err)
		assert.Equal(t, "", got.DisplayName)
		assert.Equal(t, "", got.Locale)
	})

	t.Run("wrong event type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.UserProfileUpdatedFromEvent(store.PersistedEvent{
			StreamType: "user", EventType: "UserCreated",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestUserEmailChangedFromEvent_Pure — email is required.
func TestUserEmailChangedFromEvent_Pure(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		got, err := projectors.UserEmailChangedFromEvent(store.PersistedEvent{
			StreamType: "user", StreamID: "u-1", EventType: "UserEmailChanged",
			Data: jsonOrFail(t, map[string]any{"email": "new@e.com"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "new@e.com", got.Email)
	})

	t.Run("missing email fails", func(t *testing.T) {
		_, err := projectors.UserEmailChangedFromEvent(store.PersistedEvent{
			StreamType: "user", StreamID: "u-1", EventType: "UserEmailChanged",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "email")
	})

	t.Run("explicit empty email round-trips (PL/pgSQL parity)", func(t *testing.T) {
		got, err := projectors.UserEmailChangedFromEvent(store.PersistedEvent{
			StreamType: "user", StreamID: "u-1", EventType: "UserEmailChanged",
			Data: jsonOrFail(t, map[string]any{"email": ""}),
		})
		require.NoError(t, err)
		assert.Equal(t, "", got.Email, "explicit empty email must round-trip — PL/pgSQL would have written it through")
	})
}

// TestUserPasswordChangedFromEvent_Pure — password_hash required.
func TestUserPasswordChangedFromEvent_Pure(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		got, err := projectors.UserPasswordChangedFromEvent(store.PersistedEvent{
			StreamType: "user", StreamID: "u-1", EventType: "UserPasswordChanged",
			Data: jsonOrFail(t, map[string]any{"password_hash": "h"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "h", got.PasswordHash)
	})

	t.Run("missing password_hash fails", func(t *testing.T) {
		_, err := projectors.UserPasswordChangedFromEvent(store.PersistedEvent{
			StreamType: "user", StreamID: "u-1", EventType: "UserPasswordChanged",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "password_hash")
	})
}

// TestUserRoleChangedFromEvent_Pure — role is required.
func TestUserRoleChangedFromEvent_Pure(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		got, err := projectors.UserRoleChangedFromEvent(store.PersistedEvent{
			StreamType: "user", StreamID: "u-1", EventType: "UserRoleChanged",
			Data: jsonOrFail(t, map[string]any{"role": "admin"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "admin", got.Role)
	})

	t.Run("missing role fails", func(t *testing.T) {
		_, err := projectors.UserRoleChangedFromEvent(store.PersistedEvent{
			StreamType: "user", StreamID: "u-1", EventType: "UserRoleChanged",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "role")
	})

	t.Run("explicit empty role round-trips (PL/pgSQL parity)", func(t *testing.T) {
		got, err := projectors.UserRoleChangedFromEvent(store.PersistedEvent{
			StreamType: "user", StreamID: "u-1", EventType: "UserRoleChanged",
			Data: jsonOrFail(t, map[string]any{"role": ""}),
		})
		require.NoError(t, err)
		assert.Equal(t, "", got.Role, "explicit empty role must round-trip")
	})
}

// TestUserSshKeyAddedFromEvent_Pure — key_id required.
func TestUserSshKeyAddedFromEvent_Pure(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		got, err := projectors.UserSshKeyAddedFromEvent(store.PersistedEvent{
			StreamType: "user", StreamID: "u-1", EventType: "UserSshKeyAdded",
			Data: jsonOrFail(t, map[string]any{
				"key_id":     "k-1",
				"public_key": "ssh-rsa AAA",
				"comment":    "laptop",
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, "k-1", got.KeyID)
		require.NotNil(t, got.PublicKey)
		assert.Equal(t, "ssh-rsa AAA", *got.PublicKey)
		require.NotNil(t, got.Comment)
		assert.Equal(t, "laptop", *got.Comment)
	})

	t.Run("missing public_key + comment stay nil", func(t *testing.T) {
		got, err := projectors.UserSshKeyAddedFromEvent(store.PersistedEvent{
			StreamType: "user", StreamID: "u-1", EventType: "UserSshKeyAdded",
			Data: jsonOrFail(t, map[string]any{"key_id": "k-only"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "k-only", got.KeyID)
		assert.Nil(t, got.PublicKey, "missing public_key must stay nil so JSONB element gets a JSON null (PL/pgSQL parity)")
		assert.Nil(t, got.Comment, "missing comment must stay nil so JSONB element gets a JSON null (PL/pgSQL parity)")
	})

	t.Run("missing key_id fails", func(t *testing.T) {
		_, err := projectors.UserSshKeyAddedFromEvent(store.PersistedEvent{
			StreamType: "user", StreamID: "u-1", EventType: "UserSshKeyAdded",
			Data: jsonOrFail(t, map[string]any{"public_key": "p"}),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key_id")
	})
}

// TestUserSshKeyRemovedFromEvent_Pure — key_id required.
func TestUserSshKeyRemovedFromEvent_Pure(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		got, err := projectors.UserSshKeyRemovedFromEvent(store.PersistedEvent{
			StreamType: "user", StreamID: "u-1", EventType: "UserSshKeyRemoved",
			Data: jsonOrFail(t, map[string]any{"key_id": "k-1"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "k-1", got.KeyID)
	})

	t.Run("missing key_id fails", func(t *testing.T) {
		_, err := projectors.UserSshKeyRemovedFromEvent(store.PersistedEvent{
			StreamType: "user", StreamID: "u-1", EventType: "UserSshKeyRemoved",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key_id")
	})
}

// TestUserSshSettingsUpdatedFromEvent_Pure — every boolean is
// COALESCE-preserved (nil pointer = "preserve existing"; non-nil =
// "set"). Empty payload is valid.
func TestUserSshSettingsUpdatedFromEvent_Pure(t *testing.T) {
	t.Run("explicit values present", func(t *testing.T) {
		got, err := projectors.UserSshSettingsUpdatedFromEvent(store.PersistedEvent{
			StreamType: "user", StreamID: "u-1", EventType: "UserSshSettingsUpdated",
			Data: jsonOrFail(t, map[string]any{
				"ssh_access_enabled": true,
				"ssh_allow_pubkey":   false,
				"ssh_allow_password": true,
			}),
		})
		require.NoError(t, err)
		require.NotNil(t, got.SshAccessEnabled)
		assert.True(t, *got.SshAccessEnabled)
		require.NotNil(t, got.SshAllowPubkey)
		assert.False(t, *got.SshAllowPubkey)
		require.NotNil(t, got.SshAllowPassword)
		assert.True(t, *got.SshAllowPassword)
	})

	t.Run("missing keys stay nil for SQL COALESCE preserve", func(t *testing.T) {
		got, err := projectors.UserSshSettingsUpdatedFromEvent(store.PersistedEvent{
			StreamType: "user", StreamID: "u-1", EventType: "UserSshSettingsUpdated",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.NoError(t, err)
		assert.Nil(t, got.SshAccessEnabled, "missing key must stay nil so SQL COALESCE preserves the existing column")
		assert.Nil(t, got.SshAllowPubkey)
		assert.Nil(t, got.SshAllowPassword)
	})
}

// TestUserLinuxUsernameChangedFromEvent_Pure — linux_username
// required (NOT NULL column in the projection schema).
func TestUserLinuxUsernameChangedFromEvent_Pure(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		got, err := projectors.UserLinuxUsernameChangedFromEvent(store.PersistedEvent{
			StreamType: "user", StreamID: "u-1", EventType: "UserLinuxUsernameChanged",
			Data: jsonOrFail(t, map[string]any{"linux_username": "newname"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "newname", got.LinuxUsername)
	})

	t.Run("missing key fails", func(t *testing.T) {
		_, err := projectors.UserLinuxUsernameChangedFromEvent(store.PersistedEvent{
			StreamType: "user", StreamID: "u-1", EventType: "UserLinuxUsernameChanged",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "linux_username")
	})
}

// TestUserSystemActionLinkedFromEvent_Pure — field required;
// action_id defaults to "".
func TestUserSystemActionLinkedFromEvent_Pure(t *testing.T) {
	t.Run("happy path with action_id", func(t *testing.T) {
		got, err := projectors.UserSystemActionLinkedFromEvent(store.PersistedEvent{
			StreamType: "user", StreamID: "u-1", EventType: "UserSystemActionLinked",
			Data: jsonOrFail(t, map[string]any{
				"field":     projectors.SystemActionFieldTTY,
				"action_id": "act-tty-1",
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, projectors.SystemActionFieldTTY, got.Field)
		assert.Equal(t, "act-tty-1", got.ActionID)
	})

	t.Run("missing field fails", func(t *testing.T) {
		_, err := projectors.UserSystemActionLinkedFromEvent(store.PersistedEvent{
			StreamType: "user", StreamID: "u-1", EventType: "UserSystemActionLinked",
			Data: jsonOrFail(t, map[string]any{"action_id": "x"}),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "field")
	})

	t.Run("explicit unlink: empty action_id ok", func(t *testing.T) {
		got, err := projectors.UserSystemActionLinkedFromEvent(store.PersistedEvent{
			StreamType: "user", StreamID: "u-1", EventType: "UserSystemActionLinked",
			Data: jsonOrFail(t, map[string]any{
				"field": projectors.SystemActionFieldUser,
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, "", got.ActionID, "missing action_id must default to '' (matches PL/pgSQL COALESCE)")
	})
}

// TestUserProvisioningSettingsUpdatedFromEvent_Pure — same
// COALESCE-preserve shape as SSH settings.
func TestUserProvisioningSettingsUpdatedFromEvent_Pure(t *testing.T) {
	t.Run("explicit value", func(t *testing.T) {
		got, err := projectors.UserProvisioningSettingsUpdatedFromEvent(store.PersistedEvent{
			StreamType: "user", StreamID: "u-1", EventType: "UserProvisioningSettingsUpdated",
			Data: jsonOrFail(t, map[string]any{"user_provisioning_enabled": true}),
		})
		require.NoError(t, err)
		require.NotNil(t, got.UserProvisioningEnabled)
		assert.True(t, *got.UserProvisioningEnabled)
	})

	t.Run("missing key stays nil for COALESCE preserve", func(t *testing.T) {
		got, err := projectors.UserProvisioningSettingsUpdatedFromEvent(store.PersistedEvent{
			StreamType: "user", StreamID: "u-1", EventType: "UserProvisioningSettingsUpdated",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.NoError(t, err)
		assert.Nil(t, got.UserProvisioningEnabled)
	})
}

// ============================================================================
// Integration tests — drive the listener via st.AppendEvent and verify
// the projection lands as expected. Use testutil.SetupPostgres which
// wires projectors.WireAll.
// ============================================================================

// createUserViaEvent emits a UserCreated event for the given user id
// and returns nothing — the seed for every lifecycle test below.
func createUserViaEvent(t *testing.T, st *store.Store, ctx context.Context, userID, email string) {
	t.Helper()
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user", StreamID: userID, EventType: "UserCreated",
		Data: map[string]any{
			"email":         email,
			"password_hash": "hash-seed",
			"role":          "user",
		},
		ActorType: "system", ActorID: "test",
	}))
}

// TestUserListener_FullLifecycle drives every event type in sequence
// against a single user and asserts the projection lands in the right
// state at every step.
func TestUserListener_FullLifecycle(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	userID := testutil.NewID()

	// 1. Created.
	createUserViaEvent(t, st, ctx, userID, "alice@e.com")
	got, err := st.Queries().GetUserByID(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, "alice@e.com", got.Email)
	assert.True(t, got.HasPassword, "non-empty password_hash must set has_password=true")
	assert.Equal(t, "user", got.Role)
	assert.False(t, got.Disabled)
	assert.Equal(t, int32(0), got.SessionVersion)
	originalSessionVersion := got.SessionVersion

	// 2. ProfileUpdated — REPLACES the six profile fields.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user", StreamID: userID, EventType: "UserProfileUpdated",
		Data: map[string]any{
			"display_name":       "Alice",
			"given_name":         "Al",
			"family_name":        "Ice",
			"preferred_username": "alice",
			"picture":            "p",
			"locale":             "en-US",
		},
		ActorType: "user", ActorID: "u",
	}))
	got, err = st.Queries().GetUserByID(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, "Alice", got.DisplayName)
	assert.Equal(t, "alice", got.PreferredUsername)
	assert.Equal(t, "en-US", got.Locale)

	// 3. EmailChanged.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user", StreamID: userID, EventType: "UserEmailChanged",
		Data:      map[string]any{"email": "alice2@e.com"},
		ActorType: "user", ActorID: "u",
	}))
	got, err = st.Queries().GetUserByID(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, "alice2@e.com", got.Email)

	// 4. PasswordChanged — must bump session_version.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user", StreamID: userID, EventType: "UserPasswordChanged",
		Data:      map[string]any{"password_hash": "newhash"},
		ActorType: "user", ActorID: "u",
	}))
	got, err = st.Queries().GetUserByID(ctx, userID)
	require.NoError(t, err)
	require.NotNil(t, got.PasswordHash)
	assert.Equal(t, "newhash", *got.PasswordHash)
	assert.Greater(t, got.SessionVersion, originalSessionVersion,
		"UserPasswordChanged must bump session_version monotonically")
	afterPasswordSessionVersion := got.SessionVersion

	// 5. RoleChanged.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user", StreamID: userID, EventType: "UserRoleChanged",
		Data:      map[string]any{"role": "admin"},
		ActorType: "user", ActorID: "u",
	}))
	got, err = st.Queries().GetUserByID(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, "admin", got.Role)

	// 6. Disabled — must bump session_version and flip disabled=true.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user", StreamID: userID, EventType: "UserDisabled",
		Data:      map[string]any{},
		ActorType: "user", ActorID: "u",
	}))
	got, err = st.Queries().GetUserByID(ctx, userID)
	require.NoError(t, err)
	assert.True(t, got.Disabled)
	assert.Greater(t, got.SessionVersion, afterPasswordSessionVersion,
		"UserDisabled must bump session_version monotonically")

	// 7. Enabled — flip disabled=false (no session_version bump).
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user", StreamID: userID, EventType: "UserEnabled",
		Data:      map[string]any{},
		ActorType: "user", ActorID: "u",
	}))
	got, err = st.Queries().GetUserByID(ctx, userID)
	require.NoError(t, err)
	assert.False(t, got.Disabled)

	// 8. SshKeyAdded.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user", StreamID: userID, EventType: "UserSshKeyAdded",
		Data: map[string]any{
			"key_id":     "k-1",
			"public_key": "ssh-rsa AAA",
			"comment":    "laptop",
		},
		ActorType: "user", ActorID: "u",
	}))
	got, err = st.Queries().GetUserByID(ctx, userID)
	require.NoError(t, err)
	assert.Contains(t, string(got.SshPublicKeys), "k-1")
	assert.Contains(t, string(got.SshPublicKeys), "ssh-rsa AAA")

	// 9. SshKeyRemoved — drops the matching element.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user", StreamID: userID, EventType: "UserSshKeyRemoved",
		Data:      map[string]any{"key_id": "k-1"},
		ActorType: "user", ActorID: "u",
	}))
	got, err = st.Queries().GetUserByID(ctx, userID)
	require.NoError(t, err)
	assert.NotContains(t, string(got.SshPublicKeys), "k-1")

	// 10. SshSettingsUpdated — explicit values.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user", StreamID: userID, EventType: "UserSshSettingsUpdated",
		Data: map[string]any{
			"ssh_access_enabled": true,
			"ssh_allow_pubkey":   true,
			"ssh_allow_password": false,
		},
		ActorType: "user", ActorID: "u",
	}))
	got, err = st.Queries().GetUserByID(ctx, userID)
	require.NoError(t, err)
	assert.True(t, got.SshAccessEnabled)
	assert.True(t, got.SshAllowPubkey)
	assert.False(t, got.SshAllowPassword)

	// 11. LinuxUsernameChanged.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user", StreamID: userID, EventType: "UserLinuxUsernameChanged",
		Data:      map[string]any{"linux_username": "alice2"},
		ActorType: "user", ActorID: "u",
	}))
	got, err = st.Queries().GetUserByID(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, "alice2", got.LinuxUsername)

	// 12. SystemActionLinked — TTY arm only.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user", StreamID: userID, EventType: "UserSystemActionLinked",
		Data: map[string]any{
			"field":     projectors.SystemActionFieldTTY,
			"action_id": "act-tty-1",
		},
		ActorType: "user", ActorID: "u",
	}))
	got, err = st.Queries().GetUserByID(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, "act-tty-1", got.SystemTtyActionID)
	assert.Equal(t, "", got.SystemUserActionID, "non-targeted column must be preserved as ''")
	assert.Equal(t, "", got.SystemSshActionID, "non-targeted column must be preserved as ''")

	// 13. SessionInvalidated — bumps session_version.
	priorSV := got.SessionVersion
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user", StreamID: userID, EventType: "UserSessionInvalidated",
		Data:      map[string]any{},
		ActorType: "user", ActorID: "u",
	}))
	got, err = st.Queries().GetUserByID(ctx, userID)
	require.NoError(t, err)
	assert.Greater(t, got.SessionVersion, priorSV,
		"UserSessionInvalidated must bump session_version monotonically")

	// 14. LoggedIn — stamps last_login_at.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user", StreamID: userID, EventType: "UserLoggedIn",
		Data:      map[string]any{},
		ActorType: "user", ActorID: "u",
	}))
	got, err = st.Queries().GetUserByID(ctx, userID)
	require.NoError(t, err)
	require.NotNil(t, got.LastLoginAt)

	// 15. ProvisioningSettingsUpdated.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user", StreamID: userID, EventType: "UserProvisioningSettingsUpdated",
		Data:      map[string]any{"user_provisioning_enabled": true},
		ActorType: "user", ActorID: "u",
	}))
	got, err = st.Queries().GetUserByID(ctx, userID)
	require.NoError(t, err)
	assert.True(t, got.UserProvisioningEnabled)

	// 16. Deleted — soft-delete (GetUserByID filters is_deleted=FALSE
	// so the row vanishes from this query).
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user", StreamID: userID, EventType: "UserDeleted",
		Data:      map[string]any{},
		ActorType: "user", ActorID: "u",
	}))
	_, err = st.Queries().GetUserByID(ctx, userID)
	require.Error(t, err, "GetUserByID filters is_deleted=FALSE; deleted user is gone from this query")
}

// TestUserListener_SshKeyFilterIsolatesByID locks the JSONB filter
// semantics: add A → add B → remove A — only B remains.
func TestUserListener_SshKeyFilterIsolatesByID(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	userID := testutil.NewID()
	createUserViaEvent(t, st, ctx, userID, "ssh@e.com")

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user", StreamID: userID, EventType: "UserSshKeyAdded",
		Data: map[string]any{
			"key_id": "key-A", "public_key": "AAA", "comment": "a",
		},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user", StreamID: userID, EventType: "UserSshKeyAdded",
		Data: map[string]any{
			"key_id": "key-B", "public_key": "BBB", "comment": "b",
		},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user", StreamID: userID, EventType: "UserSshKeyRemoved",
		Data:      map[string]any{"key_id": "key-A"},
		ActorType: "user", ActorID: "u",
	}))

	got, err := st.Queries().GetUserByID(ctx, userID)
	require.NoError(t, err)
	assert.NotContains(t, string(got.SshPublicKeys), "key-A",
		"UserSshKeyRemoved must drop the matching element")
	assert.Contains(t, string(got.SshPublicKeys), "key-B",
		"UserSshKeyRemoved must NOT touch other elements")
}

// TestUserListener_StaleDeleteReplayDoesNotNukeIdentityLinks locks
// the asymmetric-guard discipline for the cascade-heavy UserDeleted:
// when the version-guarded SoftDelete affects zero rows, the cascade
// (identity_links wipe) MUST be skipped. Otherwise an old UserDeleted
// re-applied later would silently nuke a freshly-restored user's
// identity links.
func TestUserListener_StaleDeleteReplayDoesNotNukeIdentityLinks(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	userID := testutil.NewID()

	// Need an IdP to satisfy identity_links_projection.provider_id FK.
	idpID := testutil.NewID()
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider", StreamID: idpID,
		EventType: "IdentityProviderCreated",
		Data: map[string]any{
			"name": "test", "slug": "test-" + testutil.NewID(),
			"client_id": "c", "issuer_url": "https://x.example.com",
		},
		ActorType: "user", ActorID: "u",
	}))

	createUserViaEvent(t, st, ctx, userID, "stale-del@e.com")
	// Bump projection_version with a profile update so the row's
	// projection_version is non-zero — gives us room to send an older
	// stale event.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user", StreamID: userID, EventType: "UserProfileUpdated",
		Data:      map[string]any{"display_name": "Stale"},
		ActorType: "user", ActorID: "u",
	}))

	live, err := st.Queries().GetUserByID(ctx, userID)
	require.NoError(t, err)

	// Plant an identity_link that a stale replay would wrongly nuke.
	_, err = st.Pool().Exec(ctx,
		"INSERT INTO identity_links_projection (id, user_id, provider_id, external_id) VALUES ($1, $2, $3, $4)",
		"link-"+testutil.NewID(), userID, idpID, "ext-stale",
	)
	require.NoError(t, err)

	// Drive the listener with a stale UserDeleted.
	older := live.ProjectionVersion - 5
	staleAt := *live.CreatedAt
	listener := projectors.UserListener(st, slog.Default())
	listener(ctx, store.PersistedEvent{
		ID:          uuid.New(),
		SequenceNum: &older,
		StreamType:  "user",
		StreamID:    userID,
		EventType:   "UserDeleted",
		Data:        []byte("{}"),
		ActorType:   "user",
		ActorID:     "u",
		OccurredAt:  staleAt,
	})

	// User still alive.
	stillAlive, err := st.Queries().GetUserByID(ctx, userID)
	require.NoError(t, err)
	assert.False(t, stillAlive.IsDeleted, "stale UserDeleted must NOT flip is_deleted")

	// Identity link still there — cascade was short-circuited by the
	// SoftDelete returning n == 0.
	count := 0
	require.NoError(t, st.Pool().QueryRow(ctx,
		"SELECT count(*) FROM identity_links_projection WHERE user_id = $1", userID,
	).Scan(&count))
	assert.Equal(t, 1, count, "stale UserDeleted must NOT cascade-delete identity_links")
}

// TestUserListener_StaleDisableAfterReEnableKeepsSessionMonotonic
// locks the session_version monotonic property: a stale UserDisabled
// replayed AFTER a re-Enable must NOT regress session_version. The
// guarded UPDATE rejects the stale event outright (n == 0), so
// neither disabled NOR session_version change.
func TestUserListener_StaleDisableAfterReEnableKeepsSessionMonotonic(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	userID := testutil.NewID()
	createUserViaEvent(t, st, ctx, userID, "stale-disable@e.com")

	// First Disable — bumps session_version. Capture what we see right
	// after that so we know the projection_version that the would-be
	// stale event carries.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user", StreamID: userID, EventType: "UserDisabled",
		Data: map[string]any{}, ActorType: "user", ActorID: "u",
	}))
	afterFirstDisable, err := st.Queries().GetUserByID(ctx, userID)
	require.NoError(t, err)
	staleVer := afterFirstDisable.ProjectionVersion

	// Real Enable + re-Disable + re-Enable to push session_version up
	// and the projection_version past the staleVer mark.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user", StreamID: userID, EventType: "UserEnabled",
		Data: map[string]any{}, ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user", StreamID: userID, EventType: "UserDisabled",
		Data: map[string]any{}, ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user", StreamID: userID, EventType: "UserEnabled",
		Data: map[string]any{}, ActorType: "user", ActorID: "u",
	}))

	live, err := st.Queries().GetUserByID(ctx, userID)
	require.NoError(t, err)
	require.False(t, live.Disabled, "user must be re-enabled before stale-replay test")
	liveSV := live.SessionVersion
	liveDisabled := live.Disabled

	// Now drive the listener with a STALE UserDisabled whose
	// projection_version sits below the live row's. The guarded
	// UPDATE must reject it: neither disabled nor session_version
	// changes.
	listener := projectors.UserListener(st, slog.Default())
	listener(ctx, store.PersistedEvent{
		ID:          uuid.New(),
		SequenceNum: &staleVer,
		StreamType:  "user",
		StreamID:    userID,
		EventType:   "UserDisabled",
		Data:        []byte("{}"),
		ActorType:   "user",
		ActorID:     "u",
		OccurredAt:  *afterFirstDisable.CreatedAt,
	})

	after, err := st.Queries().GetUserByID(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, liveDisabled, after.Disabled,
		"stale UserDisabled must NOT regress disabled flag")
	assert.Equal(t, liveSV, after.SessionVersion,
		"stale UserDisabled must NOT regress session_version (monotonic)")
}

// TestUserListener_IgnoresWrongStreamType — defensive: a non-user
// event must not crash the listener.
func TestUserListener_IgnoresWrongStreamType(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	listener := projectors.UserListener(st, slog.Default())
	// Should be a no-op (no panic, no DB call).
	listener(ctx, store.PersistedEvent{
		StreamType: "device", StreamID: "d-1", EventType: "DeviceRegistered",
	})
}
