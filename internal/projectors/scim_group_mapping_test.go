package projectors_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/projectors"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// TestSCIMGroupMappedFromEvent_Pure exercises the decoder. provider_id,
// scim_group_id, and user_group_id are required (composite-key
// columns + FK to user_groups_projection); scim_display_name defaults
// to "" (empty string) to match the PL/pgSQL COALESCE.
func TestSCIMGroupMappedFromEvent_Pure(t *testing.T) {
	t.Run("happy path with display name", func(t *testing.T) {
		got, err := projectors.SCIMGroupMappedFromEvent(store.PersistedEvent{
			StreamType: "scim_group_mapping", StreamID: "mapping-1",
			EventType: "SCIMGroupMapped",
			Data: jsonOrFail(t, map[string]any{
				"provider_id":       "idp-1",
				"scim_group_id":     "sg-eng",
				"scim_display_name": "Engineering",
				"user_group_id":     "ug-eng",
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, "mapping-1", got.ID)
		assert.Equal(t, "idp-1", got.ProviderID)
		assert.Equal(t, "sg-eng", got.SCIMGroupID)
		assert.Equal(t, "Engineering", got.SCIMDisplayName)
		assert.Equal(t, "ug-eng", got.UserGroupID)
	})

	t.Run("missing scim_display_name defaults to empty", func(t *testing.T) {
		got, err := projectors.SCIMGroupMappedFromEvent(store.PersistedEvent{
			StreamType: "scim_group_mapping", StreamID: "mapping-2",
			EventType: "SCIMGroupMapped",
			Data: jsonOrFail(t, map[string]any{
				"provider_id":   "idp-1",
				"scim_group_id": "sg",
				"user_group_id": "ug",
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, "", got.SCIMDisplayName)
	})

	t.Run("required fields validated", func(t *testing.T) {
		base := map[string]any{
			"provider_id":   "p",
			"scim_group_id": "sg",
			"user_group_id": "ug",
		}
		for _, drop := range []string{"provider_id", "scim_group_id", "user_group_id"} {
			t.Run("missing "+drop, func(t *testing.T) {
				payload := map[string]any{}
				for k, v := range base {
					if k == drop {
						continue
					}
					payload[k] = v
				}
				_, err := projectors.SCIMGroupMappedFromEvent(store.PersistedEvent{
					StreamType: "scim_group_mapping", StreamID: "m", EventType: "SCIMGroupMapped",
					Data: jsonOrFail(t, payload),
				})
				require.Error(t, err)
				assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
				assert.Contains(t, err.Error(), drop)
			})
		}
	})

	t.Run("wrong stream/event type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.SCIMGroupMappedFromEvent(store.PersistedEvent{
			StreamType: "identity_provider", EventType: "SCIMGroupMapped",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
		_, err = projectors.SCIMGroupMappedFromEvent(store.PersistedEvent{
			StreamType: "scim_group_mapping", EventType: "SCIMGroupUnmapped",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestSCIMGroupUnmappedFromEvent_Pure — composite-key shape.
func TestSCIMGroupUnmappedFromEvent_Pure(t *testing.T) {
	got, err := projectors.SCIMGroupUnmappedFromEvent(store.PersistedEvent{
		StreamType: "scim_group_mapping", StreamID: "m",
		EventType: "SCIMGroupUnmapped",
		Data:      jsonOrFail(t, map[string]any{"provider_id": "p", "scim_group_id": "sg"}),
	})
	require.NoError(t, err)
	assert.Equal(t, "p", got.ProviderID)
	assert.Equal(t, "sg", got.SCIMGroupID)

	for _, drop := range []string{"provider_id", "scim_group_id"} {
		t.Run("missing "+drop, func(t *testing.T) {
			payload := map[string]any{"provider_id": "p", "scim_group_id": "sg"}
			delete(payload, drop)
			_, err := projectors.SCIMGroupUnmappedFromEvent(store.PersistedEvent{
				StreamType: "scim_group_mapping", EventType: "SCIMGroupUnmapped",
				Data: jsonOrFail(t, payload),
			})
			require.Error(t, err)
			assert.Contains(t, err.Error(), drop)
		})
	}
}

// TestSCIMGroupMappingUpdatedFromEvent_Pure — only display_name is
// updatable (the PL/pgSQL projector exposes nothing else for update).
func TestSCIMGroupMappingUpdatedFromEvent_Pure(t *testing.T) {
	got, err := projectors.SCIMGroupMappingUpdatedFromEvent(store.PersistedEvent{
		StreamType: "scim_group_mapping", EventType: "SCIMGroupMappingUpdated",
		Data: jsonOrFail(t, map[string]any{
			"provider_id":       "p",
			"scim_group_id":     "sg",
			"scim_display_name": "New Name",
		}),
	})
	require.NoError(t, err)
	assert.Equal(t, "p", got.ProviderID)
	assert.Equal(t, "sg", got.SCIMGroupID)
	require.NotNil(t, got.SCIMDisplayName)
	assert.Equal(t, "New Name", *got.SCIMDisplayName)

	t.Run("missing scim_display_name → nil (preserves existing via COALESCE)", func(t *testing.T) {
		got, err := projectors.SCIMGroupMappingUpdatedFromEvent(store.PersistedEvent{
			StreamType: "scim_group_mapping", EventType: "SCIMGroupMappingUpdated",
			Data: jsonOrFail(t, map[string]any{
				"provider_id":   "p",
				"scim_group_id": "sg",
			}),
		})
		require.NoError(t, err)
		assert.Nil(t, got.SCIMDisplayName, "missing field stays nil so SQL COALESCE preserves existing")
	})
}

// TestSCIMGroupMappingListener_MapUpdateUnmap walks the full lifecycle.
func TestSCIMGroupMappingListener_MapUpdateUnmap(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	idpID := testutil.NewID()
	groupID := testutil.CreateTestUserGroup(t, st, "actor", "scim-target")

	// Create the IdP first (FK target).
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider", StreamID: idpID,
		EventType: "IdentityProviderCreated",
		Data: map[string]any{
			"name": "x", "slug": "x-" + testutil.NewID(),
			"client_id": "c", "issuer_url": "https://x.example.com",
		},
		ActorType: "user", ActorID: "u",
	}))

	mappingID := "mapping-" + testutil.NewID()
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "scim_group_mapping", StreamID: mappingID,
		EventType: "SCIMGroupMapped",
		Data: map[string]any{
			"provider_id":       idpID,
			"scim_group_id":     "sg-eng",
			"scim_display_name": "Engineering",
			"user_group_id":     groupID,
		},
		ActorType: "user", ActorID: "u",
	}))

	// Read back via direct SQL (no GetByCompositeKey query exists).
	var displayName, userGroupID string
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT scim_display_name, user_group_id FROM scim_group_mapping_projection WHERE provider_id=$1 AND scim_group_id=$2",
		idpID, "sg-eng",
	).Scan(&displayName, &userGroupID))
	assert.Equal(t, "Engineering", displayName)
	assert.Equal(t, groupID, userGroupID)

	// Update display name.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "scim_group_mapping", StreamID: mappingID,
		EventType: "SCIMGroupMappingUpdated",
		Data: map[string]any{
			"provider_id":       idpID,
			"scim_group_id":     "sg-eng",
			"scim_display_name": "Engineering Team",
		},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT scim_display_name FROM scim_group_mapping_projection WHERE provider_id=$1 AND scim_group_id=$2",
		idpID, "sg-eng",
	).Scan(&displayName))
	assert.Equal(t, "Engineering Team", displayName)

	// Unmap.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "scim_group_mapping", StreamID: mappingID,
		EventType: "SCIMGroupUnmapped",
		Data: map[string]any{
			"provider_id":   idpID,
			"scim_group_id": "sg-eng",
		},
		ActorType: "user", ActorID: "u",
	}))
	count := 0
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT count(*) FROM scim_group_mapping_projection WHERE provider_id=$1 AND scim_group_id=$2",
		idpID, "sg-eng",
	).Scan(&count))
	assert.Equal(t, 0, count, "SCIMGroupUnmapped removes the row")
}

// TestSCIMGroupMappingListener_MapReplayIsIdempotent — UPSERT semantics
// must match the PL/pgSQL ON CONFLICT DO UPDATE: re-mapping the same
// (provider, scim_group) refreshes display_name + user_group_id but
// doesn't mint a duplicate row.
func TestSCIMGroupMappingListener_MapReplayIsIdempotent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	idpID := testutil.NewID()
	groupA := testutil.CreateTestUserGroup(t, st, "actor", "ug-a")
	groupB := testutil.CreateTestUserGroup(t, st, "actor", "ug-b")

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider", StreamID: idpID,
		EventType: "IdentityProviderCreated",
		Data: map[string]any{
			"name": "x", "slug": "x-" + testutil.NewID(),
			"client_id": "c", "issuer_url": "https://x.example.com",
		},
		ActorType: "user", ActorID: "u",
	}))

	mappingID := "mapping-" + testutil.NewID()
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "scim_group_mapping", StreamID: mappingID,
		EventType: "SCIMGroupMapped",
		Data: map[string]any{
			"provider_id": idpID, "scim_group_id": "sg",
			"scim_display_name": "Initial", "user_group_id": groupA,
		},
		ActorType: "user", ActorID: "u",
	}))
	// Re-map with different display name + different user_group.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "scim_group_mapping", StreamID: mappingID,
		EventType: "SCIMGroupMapped",
		Data: map[string]any{
			"provider_id": idpID, "scim_group_id": "sg",
			"scim_display_name": "Refreshed", "user_group_id": groupB,
		},
		ActorType: "user", ActorID: "u",
	}))

	count := 0
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT count(*) FROM scim_group_mapping_projection WHERE provider_id=$1 AND scim_group_id=$2",
		idpID, "sg",
	).Scan(&count))
	assert.Equal(t, 1, count, "ON CONFLICT preserves uniqueness on (provider_id, scim_group_id)")

	var displayName, ugID string
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT scim_display_name, user_group_id FROM scim_group_mapping_projection WHERE provider_id=$1 AND scim_group_id=$2",
		idpID, "sg",
	).Scan(&displayName, &ugID))
	assert.Equal(t, "Refreshed", displayName, "ON CONFLICT DO UPDATE refreshes display_name")
	assert.Equal(t, groupB, ugID, "ON CONFLICT DO UPDATE refreshes user_group_id")
}

// TestSCIMGroupMappingListener_StaleUpdateIgnored verifies the
// projection_version guard on UpdateSCIMGroupMappingDisplayName: an
// older SCIMGroupMappingUpdated event must not overwrite a projection
// that was already advanced by a newer event. The PR description
// called out this guard as the key tightening over the PL/pgSQL
// original; it deserves a dedicated regression test.
func TestSCIMGroupMappingListener_StaleUpdateIgnored(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	idpID := testutil.NewID()
	groupID := testutil.CreateTestUserGroup(t, st, "actor", "scim-stale")
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider", StreamID: idpID,
		EventType: "IdentityProviderCreated",
		Data: map[string]any{
			"name": "x", "slug": "x-" + testutil.NewID(),
			"client_id": "c", "issuer_url": "https://x.example.com",
		},
		ActorType: "user", ActorID: "u",
	}))

	mappingID := "mapping-" + testutil.NewID()
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "scim_group_mapping", StreamID: mappingID,
		EventType: "SCIMGroupMapped",
		Data: map[string]any{
			"provider_id": idpID, "scim_group_id": "sg-stale",
			"scim_display_name": "Initial", "user_group_id": groupID,
		},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "scim_group_mapping", StreamID: mappingID,
		EventType: "SCIMGroupMappingUpdated",
		Data: map[string]any{
			"provider_id": idpID, "scim_group_id": "sg-stale",
			"scim_display_name": "Current State",
		},
		ActorType: "user", ActorID: "u",
	}))

	// Capture current projection_version, then apply a stale UPDATE
	// directly with version-5. The guard must reject it.
	var currentVer int64
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT projection_version FROM scim_group_mapping_projection WHERE provider_id=$1 AND scim_group_id=$2",
		idpID, "sg-stale",
	).Scan(&currentVer))
	older := currentVer - 5
	staleName := "stale replay would set this"
	require.NoError(t, st.Queries().UpdateSCIMGroupMappingDisplayName(ctx, db.UpdateSCIMGroupMappingDisplayNameParams{
		ProviderID:        idpID,
		ScimGroupID:       "sg-stale",
		ScimDisplayName:   &staleName,
		ProjectionVersion: older,
	}))

	var displayName string
	var afterVer int64
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT scim_display_name, projection_version FROM scim_group_mapping_projection WHERE provider_id=$1 AND scim_group_id=$2",
		idpID, "sg-stale",
	).Scan(&displayName, &afterVer))
	assert.Equal(t, "Current State", displayName, "stale projection_version must NOT clobber fresher state")
	assert.Equal(t, currentVer, afterVer, "projection_version unchanged when guard rejects")
}

// TestSCIMGroupMappingListener_IgnoresWrongStreamType — defensive.
func TestSCIMGroupMappingListener_IgnoresWrongStreamType(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	idpID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider", // wrong (would dispatch to IdP listener, not this one)
		StreamID:   "m-" + testutil.NewID(),
		EventType:  "SCIMGroupMapped",
		Data: map[string]any{
			"provider_id": idpID, "scim_group_id": "sg",
			"scim_display_name": "X", "user_group_id": "ug",
		},
		ActorType: "user", ActorID: "u",
	}))

	count := 0
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT count(*) FROM scim_group_mapping_projection WHERE provider_id=$1", idpID,
	).Scan(&count))
	assert.Equal(t, 0, count, "wrong-stream-type SCIMGroupMapped must NOT create a row")
}
