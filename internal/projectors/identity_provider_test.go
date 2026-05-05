package projectors_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/projectors"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// TestIdentityProviderCreatedFromEvent_Pure exercises the decoder
// for IdentityProviderCreated. PL/pgSQL defaulted: provider_type='oidc',
// scopes='{}', auto_create_users=FALSE, auto_link_by_email=FALSE,
// default_role_id='', etc. Pointer fields on the encrypted secret
// preserve the empty-vs-omitted distinction.
func TestIdentityProviderCreatedFromEvent_Pure(t *testing.T) {
	t.Run("happy path with all fields", func(t *testing.T) {
		got, err := projectors.IdentityProviderCreatedFromEvent(store.PersistedEvent{
			StreamType: "identity_provider", StreamID: "idp-1",
			EventType: "IdentityProviderCreated", ActorID: "actor-1",
			Data: jsonOrFail(t, map[string]any{
				"name":                        "Google",
				"slug":                        "google",
				"provider_type":               "oidc",
				"client_id":                   "client-abc",
				"client_secret_encrypted":     "ENC:secret",
				"issuer_url":                  "https://accounts.google.com",
				"authorization_url":           "https://oauth/auth",
				"token_url":                   "https://oauth/token",
				"userinfo_url":                "https://oauth/userinfo",
				"scopes":                      []string{"openid", "email", "profile"},
				"auto_create_users":           true,
				"auto_link_by_email":          true,
				"default_role_id":             "role-default",
				"disable_password_for_linked": true,
				"group_claim":                 "groups",
				"group_mapping":               map[string]string{"engineering": "group-eng"},
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, "idp-1", got.ID)
		assert.Equal(t, "Google", got.Name)
		assert.Equal(t, "google", got.Slug)
		assert.Equal(t, "oidc", got.ProviderType)
		assert.Equal(t, "client-abc", got.ClientID)
		assert.Equal(t, "ENC:secret", got.ClientSecretEncrypted)
		assert.Equal(t, "https://accounts.google.com", got.IssuerURL)
		assert.Equal(t, []string{"openid", "email", "profile"}, got.Scopes)
		assert.True(t, got.AutoCreateUsers)
		assert.True(t, got.AutoLinkByEmail)
		assert.Equal(t, "role-default", got.DefaultRoleID)
		assert.True(t, got.DisablePasswordForLinked)
		assert.Equal(t, "groups", got.GroupClaim)
		assert.NotEmpty(t, got.GroupMapping, "group_mapping JSONB round-trips")
		assert.Equal(t, "actor-1", got.CreatedBy)
	})

	t.Run("defaults: provider_type='oidc', scopes empty, bools false, strings empty", func(t *testing.T) {
		got, err := projectors.IdentityProviderCreatedFromEvent(store.PersistedEvent{
			StreamType: "identity_provider", StreamID: "idp-2",
			EventType: "IdentityProviderCreated", ActorID: "u",
			Data: jsonOrFail(t, map[string]any{
				"name":       "Bare",
				"slug":       "bare",
				"client_id":  "c",
				"issuer_url": "https://example.com",
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, "oidc", got.ProviderType, "provider_type defaults to 'oidc'")
		assert.Equal(t, "", got.ClientSecretEncrypted)
		assert.Equal(t, []string{}, got.Scopes)
		assert.False(t, got.AutoCreateUsers)
		assert.False(t, got.AutoLinkByEmail)
		assert.Equal(t, "", got.DefaultRoleID)
		assert.False(t, got.DisablePasswordForLinked)
		assert.Equal(t, "", got.GroupClaim)
	})

	t.Run("required fields validated", func(t *testing.T) {
		base := map[string]any{
			"name":       "X",
			"slug":       "x",
			"client_id":  "c",
			"issuer_url": "https://x.example.com",
		}
		for _, drop := range []string{"name", "slug", "client_id", "issuer_url"} {
			t.Run("missing "+drop, func(t *testing.T) {
				payload := map[string]any{}
				for k, v := range base {
					if k == drop {
						continue
					}
					payload[k] = v
				}
				_, err := projectors.IdentityProviderCreatedFromEvent(store.PersistedEvent{
					StreamType: "identity_provider", StreamID: "idp-x",
					EventType: "IdentityProviderCreated", ActorID: "u",
					Data: jsonOrFail(t, payload),
				})
				require.Error(t, err)
				assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
				assert.Contains(t, err.Error(), drop)
			})
		}
	})

	t.Run("wrong stream/event type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.IdentityProviderCreatedFromEvent(store.PersistedEvent{
			StreamType: "user", EventType: "IdentityProviderCreated",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
		_, err = projectors.IdentityProviderCreatedFromEvent(store.PersistedEvent{
			StreamType: "identity_provider", EventType: "IdentityProviderUpdated",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestIdentityProviderListener_FullLifecycle walks Create → Update →
// SCIM Enable → SCIM TokenRotated → SCIM Disable → Delete and asserts
// the projection state at each step.
func TestIdentityProviderListener_FullLifecycle(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	idpID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider", StreamID: idpID,
		EventType: "IdentityProviderCreated",
		Data: map[string]any{
			"name":       "test-idp",
			"slug":       "test-" + testutil.NewID(),
			"client_id":  "c",
			"issuer_url": "https://idp.example.com",
		},
		ActorType: "user", ActorID: "u",
	}))
	idp, err := st.Queries().GetIdentityProviderByID(ctx, idpID)
	require.NoError(t, err)
	assert.Equal(t, "test-idp", idp.Name)
	assert.True(t, idp.Enabled, "newly-created IdP starts enabled")
	assert.False(t, idp.IsDeleted)
	assert.False(t, idp.ScimEnabled)

	// Update name + flip enabled.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider", StreamID: idpID,
		EventType: "IdentityProviderUpdated",
		Data: map[string]any{"name": "renamed", "enabled": false},
		ActorType: "user", ActorID: "u",
	}))
	idp, err = st.Queries().GetIdentityProviderByID(ctx, idpID)
	require.NoError(t, err)
	assert.Equal(t, "renamed", idp.Name)
	assert.False(t, idp.Enabled)
	assert.Equal(t, "c", idp.ClientID, "client_id preserved (omitted)")

	// SCIM Enable.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider", StreamID: idpID,
		EventType: "IdentityProviderSCIMEnabled",
		Data:      map[string]any{"scim_token_hash": "hash-1"},
		ActorType: "user", ActorID: "u",
	}))
	idp, err = st.Queries().GetIdentityProviderByID(ctx, idpID)
	require.NoError(t, err)
	assert.True(t, idp.ScimEnabled)
	assert.Equal(t, "hash-1", idp.ScimTokenHash)

	// Token rotate.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider", StreamID: idpID,
		EventType: "IdentityProviderSCIMTokenRotated",
		Data:      map[string]any{"scim_token_hash": "hash-2"},
		ActorType: "user", ActorID: "u",
	}))
	idp, err = st.Queries().GetIdentityProviderByID(ctx, idpID)
	require.NoError(t, err)
	assert.True(t, idp.ScimEnabled, "rotation does not disable")
	assert.Equal(t, "hash-2", idp.ScimTokenHash)

	// SCIM Disable.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider", StreamID: idpID,
		EventType: "IdentityProviderSCIMDisabled",
		Data:      map[string]any{},
		ActorType: "user", ActorID: "u",
	}))
	idp, err = st.Queries().GetIdentityProviderByID(ctx, idpID)
	require.NoError(t, err)
	assert.False(t, idp.ScimEnabled)
	assert.Equal(t, "", idp.ScimTokenHash, "token cleared on disable")

	// Delete.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider", StreamID: idpID,
		EventType: "IdentityProviderDeleted",
		Data:      map[string]any{},
		ActorType: "user", ActorID: "u",
	}))
	_, err = st.Queries().GetIdentityProviderByID(ctx, idpID)
	require.Error(t, err, "GetIdentityProviderByID excludes is_deleted=TRUE rows")

	var isDeleted, enabled, scimEnabled bool
	require.NoError(t, st.Pool().QueryRow(ctx,
		"SELECT is_deleted, enabled, scim_enabled FROM identity_providers_projection WHERE id = $1", idpID,
	).Scan(&isDeleted, &enabled, &scimEnabled))
	assert.True(t, isDeleted)
	assert.False(t, enabled, "delete also flips enabled to FALSE")
	assert.False(t, scimEnabled, "delete also flips scim_enabled to FALSE")
}

// TestIdentityProviderListener_DeleteCascadesIdentityLinksAndSCIM
// confirms IdentityProviderDeleted cleans up identity_links_projection
// AND scim_group_mapping_projection rows referencing this provider,
// inside store.WithTx so the projection never observes the
// "provider deleted but child rows linger" intermediate state.
func TestIdentityProviderListener_DeleteCascadesIdentityLinksAndSCIM(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	idpID := testutil.NewID()
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pw", "user")

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider", StreamID: idpID,
		EventType: "IdentityProviderCreated",
		Data: map[string]any{
			"name": "x", "slug": "x-" + testutil.NewID(),
			"client_id": "c", "issuer_url": "https://x.example.com",
		},
		ActorType: "user", ActorID: "u",
	}))

	// Plant an identity_links row + scim_group_mapping row.
	_, err := st.Pool().Exec(ctx,
		"INSERT INTO identity_links_projection (id, user_id, provider_id, external_id) VALUES ($1, $2, $3, $4)",
		"link-"+testutil.NewID(), userID, idpID, "ext-1",
	)
	require.NoError(t, err)
	groupID := testutil.CreateTestUserGroup(t, st, "actor", "test-group")
	_, err = st.Pool().Exec(ctx,
		"INSERT INTO scim_group_mapping_projection (id, provider_id, scim_group_id, user_group_id) VALUES ($1, $2, $3, $4)",
		"mapping-"+testutil.NewID(), idpID, "sg-1", groupID,
	)
	require.NoError(t, err)

	// Delete the IdP.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider", StreamID: idpID,
		EventType: "IdentityProviderDeleted",
		Data:      map[string]any{},
		ActorType: "user", ActorID: "u",
	}))

	count := 0
	require.NoError(t, st.Pool().QueryRow(ctx,
		"SELECT count(*) FROM identity_links_projection WHERE provider_id = $1", idpID,
	).Scan(&count))
	assert.Equal(t, 0, count, "identity_links_projection rows for the deleted IdP are removed")

	require.NoError(t, st.Pool().QueryRow(ctx,
		"SELECT count(*) FROM scim_group_mapping_projection WHERE provider_id = $1", idpID,
	).Scan(&count))
	assert.Equal(t, 0, count, "scim_group_mapping_projection rows for the deleted IdP are removed")
}

// TestIdentityProviderListener_SCIMDisableCascadesGroupMappings
// confirms IdentityProviderSCIMDisabled clears the scim_group_mapping
// rows for this provider — operators expect re-enabling SCIM to
// require fresh group mapping configuration.
func TestIdentityProviderListener_SCIMDisableCascadesGroupMappings(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	idpID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider", StreamID: idpID,
		EventType: "IdentityProviderCreated",
		Data: map[string]any{
			"name": "x", "slug": "x-" + testutil.NewID(),
			"client_id": "c", "issuer_url": "https://x.example.com",
		},
		ActorType: "user", ActorID: "u",
	}))

	groupID := testutil.CreateTestUserGroup(t, st, "actor", "test-group-scim")
	_, err := st.Pool().Exec(ctx,
		"INSERT INTO scim_group_mapping_projection (id, provider_id, scim_group_id, user_group_id) VALUES ($1, $2, $3, $4)",
		"mapping-"+testutil.NewID(), idpID, "sg-x", groupID,
	)
	require.NoError(t, err)

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider", StreamID: idpID,
		EventType: "IdentityProviderSCIMDisabled",
		Data:      map[string]any{},
		ActorType: "user", ActorID: "u",
	}))

	count := 0
	require.NoError(t, st.Pool().QueryRow(ctx,
		"SELECT count(*) FROM scim_group_mapping_projection WHERE provider_id = $1", idpID,
	).Scan(&count))
	assert.Equal(t, 0, count, "SCIM disable wipes group mappings for that provider")
}

// TestIdentityLinkListener_LinkUpdateUnlink walks IdentityLinked →
// IdentityLinkLoginUpdated → IdentityUnlinked.
func TestIdentityLinkListener_LinkUpdateUnlink(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	idpID := testutil.NewID()
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pw", "user")

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider", StreamID: idpID,
		EventType: "IdentityProviderCreated",
		Data: map[string]any{
			"name": "x", "slug": "x-" + testutil.NewID(),
			"client_id": "c", "issuer_url": "https://x.example.com",
		},
		ActorType: "user", ActorID: "u",
	}))

	linkID := "link-" + testutil.NewID()
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider", StreamID: linkID,
		EventType: "IdentityLinked",
		Data: map[string]any{
			"user_id":        userID,
			"provider_id":    idpID,
			"external_id":    "ext-1",
			"external_email": "user@external.com",
			"external_name":  "External User",
		},
		ActorType: "user", ActorID: "u",
	}))

	link, err := st.Queries().GetIdentityLinkByProviderAndExternalID(ctx, db.GetIdentityLinkByProviderAndExternalIDParams{
		ProviderID: idpID, ExternalID: "ext-1",
	})
	require.NoError(t, err)
	assert.Equal(t, "user@external.com", link.ExternalEmail)
	assert.Equal(t, "External User", link.ExternalName)

	// Re-link with login update (UPSERT path).
	time.Sleep(10 * time.Millisecond) // ensure distinct timestamp
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider", StreamID: linkID,
		EventType: "IdentityLinkLoginUpdated",
		Data: map[string]any{
			"provider_id":    idpID,
			"external_id":    "ext-1",
			"external_name":  "Updated Name",
		},
		ActorType: "user", ActorID: userID,
	}))
	link, err = st.Queries().GetIdentityLinkByProviderAndExternalID(ctx, db.GetIdentityLinkByProviderAndExternalIDParams{
		ProviderID: idpID, ExternalID: "ext-1",
	})
	require.NoError(t, err)
	assert.Equal(t, "Updated Name", link.ExternalName)
	assert.Equal(t, "user@external.com", link.ExternalEmail, "external_email preserved (omitted via NULLIF)")

	// Unlink.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider", StreamID: linkID,
		EventType: "IdentityUnlinked",
		Data:      map[string]any{},
		ActorType: "user", ActorID: userID,
	}))
	_, err = st.Queries().GetIdentityLinkByProviderAndExternalID(ctx, db.GetIdentityLinkByProviderAndExternalIDParams{
		ProviderID: idpID, ExternalID: "ext-1",
	})
	require.Error(t, err, "IdentityUnlinked removes the row")
}

// TestIdentityProviderListener_StaleDeleteReplay regression-locks the
// asymmetric-guard rule from `feedback_projector_multiwrite_guard_asymmetry`:
// IdentityProviderDeleted's SoftDelete update is guarded by
// projection_version, but the cascade DELETEs on identity_links and
// scim_group_mapping are unguarded. Listener must short-circuit when
// soft-delete affects 0 rows.
func TestIdentityProviderListener_StaleDeleteReplay(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	idpID := testutil.NewID()
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pw", "user")

	// Land + update so projection_version > 0.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider", StreamID: idpID,
		EventType: "IdentityProviderCreated",
		Data: map[string]any{
			"name": "live", "slug": "live-" + testutil.NewID(),
			"client_id": "c", "issuer_url": "https://x.example.com",
		},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider", StreamID: idpID,
		EventType: "IdentityProviderUpdated",
		Data:      map[string]any{"name": "still-live"},
		ActorType: "user", ActorID: "u",
	}))
	live, err := st.Queries().GetIdentityProviderByID(ctx, idpID)
	require.NoError(t, err)

	// Plant a link + mapping that a stale replay would wrongly nuke.
	_, err = st.Pool().Exec(ctx,
		"INSERT INTO identity_links_projection (id, user_id, provider_id, external_id) VALUES ($1, $2, $3, $4)",
		"link-"+testutil.NewID(), userID, idpID, "ext-2",
	)
	require.NoError(t, err)
	groupID := testutil.CreateTestUserGroup(t, st, "actor", "test-group-stale")
	_, err = st.Pool().Exec(ctx,
		"INSERT INTO scim_group_mapping_projection (id, provider_id, scim_group_id, user_group_id) VALUES ($1, $2, $3, $4)",
		"mapping-"+testutil.NewID(), idpID, "sg-y", groupID,
	)
	require.NoError(t, err)

	// Drive the listener with a stale projection_version.
	older := live.ProjectionVersion - 5
	listener := projectors.IdentityProviderListener(st, slog.Default())
	listener(ctx, store.PersistedEvent{
		ID:          uuid.New(),
		SequenceNum: &older,
		StreamType:  "identity_provider",
		StreamID:    idpID,
		EventType:   "IdentityProviderDeleted",
		Data:        []byte("{}"),
		ActorType:   "user",
		ActorID:     "u",
		OccurredAt:  live.CreatedAt,
	})

	// Identity link + SCIM mapping survive.
	count := 0
	require.NoError(t, st.Pool().QueryRow(ctx,
		"SELECT count(*) FROM identity_links_projection WHERE provider_id = $1", idpID,
	).Scan(&count))
	assert.Equal(t, 1, count, "stale IdentityProviderDeleted must NOT cascade-delete identity_links")

	require.NoError(t, st.Pool().QueryRow(ctx,
		"SELECT count(*) FROM scim_group_mapping_projection WHERE provider_id = $1", idpID,
	).Scan(&count))
	assert.Equal(t, 1, count, "stale IdentityProviderDeleted must NOT cascade-delete scim_group_mappings")

	stillAlive, err := st.Queries().GetIdentityProviderByID(ctx, idpID)
	require.NoError(t, err)
	assert.False(t, stillAlive.IsDeleted)
}

// TestIdentityProviderListener_IgnoresWrongStreamType — defensive.
func TestIdentityProviderListener_IgnoresWrongStreamType(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	idpID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user", // wrong
		StreamID:   idpID,
		EventType:  "IdentityProviderCreated",
		Data: map[string]any{
			"name": "ghost", "slug": "ghost", "client_id": "c", "issuer_url": "https://x",
		},
		ActorType: "user", ActorID: "u",
	}))
	_, err := st.Queries().GetIdentityProviderByID(ctx, idpID)
	require.Error(t, err, "wrong-stream-type IdentityProviderCreated must NOT create a row")
}
