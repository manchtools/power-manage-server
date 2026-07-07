package store_test

// Spec 21 AC 6 (absorbs audit F-04): the standing proof that "replay
// reproduces 1:1" holds PER COLUMN, not spot-checked. A rich fixture is
// seeded through the live pipeline, every AllRebuildTargets table is
// dumped as ordered row::text, a full no-arg RebuildAll runs, and the
// re-dump must be byte-identical. Self-discovering over the target
// registry, so a new rebuild target is covered the day it is added.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// dumpRebuildTables returns, for every table owned by a rebuild target,
// the full-row dump: each row cast to its composite text form (every
// column, no sampling), aggregated in deterministic order.
func dumpRebuildTables(t *testing.T, st *store.Store) map[string]string {
	t.Helper()
	ctx := context.Background()
	out := map[string]string{}
	for _, tgt := range store.AllRebuildTargets {
		for _, tbl := range tgt.Tables {
			var dump string
			require.NoErrorf(t, st.TestingPool().QueryRow(ctx,
				`SELECT COALESCE(string_agg(t::text, E'\n' ORDER BY t::text), '') FROM `+tbl+` t`,
			).Scan(&dump), "dump %s", tbl)
			out[tbl] = dump
		}
	}
	return out
}

// seedRichFixture drives the live pipeline across many stream types so
// the round-trip exercises a broad slice of the projector surface.
func seedRichFixture(t *testing.T, st *store.Store) {
	t.Helper()
	ctx := context.Background()

	adminID := testutil.CreateTestUser(t, st, "fidelity-"+testutil.NewID()[:8]+"@test.com", "pass", "admin")
	userID, _, groupID := seedUsersCascadeChildren(t, st) // user + TOTP + identity link + group membership

	// A crypto-shredded user (spec 19 AC 11): a rebuild must reproduce
	// their projection as the redaction sentinel — the delete redaction
	// and the rebuild share one path, so the full-row dump stays
	// byte-identical across the prune/rebuild round-trip.
	erased := testutil.CreateTestUser(t, st, "fidelity-erased-"+testutil.NewID()[:8]+"@test.com", "pass", "user")
	require.NoError(t, st.AppendUserDeletionWithShred(ctx, store.Event{
		StreamType: "user", StreamID: erased, EventType: "UserDeleted",
		Data: map[string]any{}, ActorType: "user", ActorID: adminID,
	}))

	roleID := testutil.CreateTestRole(t, st, adminID, "fidelity-role-"+testutil.NewID()[:8], []string{"GetDevice"})
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_role",
		StreamID:   userID + ":" + roleID,
		EventType:  "UserRoleAssigned",
		Data:       map[string]any{"user_id": userID, "role_id": roleID},
		ActorType:  "user",
		ActorID:    adminID,
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_group",
		StreamID:   groupID + ":role:" + roleID,
		EventType:  "UserGroupRoleAssigned",
		Data:       map[string]any{"group_id": groupID, "role_id": roleID},
		ActorType:  "user",
		ActorID:    adminID,
	}))

	deviceID := testutil.CreateTestDevice(t, st, "fidelity-host-"+testutil.NewID()[:8])
	deviceGroupID := testutil.CreateTestDeviceGroup(t, st, adminID, "fidelity-dg-"+testutil.NewID()[:8])
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   deviceID,
		EventType:  "DeviceLabelSet",
		Data:       map[string]any{"key": "environment", "value": "test"},
		ActorType:  "user",
		ActorID:    adminID,
	}))
	// Spec 22: inventory-interval policy columns must replay
	// byte-identically on both projections.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   deviceID,
		EventType:  "DeviceInventoryIntervalSet",
		Data:       map[string]any{"inventory_interval_minutes": 240},
		ActorType:  "user",
		ActorID:    adminID,
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device_group",
		StreamID:   deviceGroupID,
		EventType:  "DeviceGroupInventoryIntervalSet",
		Data:       map[string]any{"inventory_interval_minutes": 720},
		ActorType:  "user",
		ActorID:    adminID,
	}))

	actionID := testutil.CreateTestAction(t, st, adminID, "fidelity-action-"+testutil.NewID()[:8], 1)
	setID := testutil.CreateTestActionSet(t, st, adminID, "fidelity-set-"+testutil.NewID()[:8])
	testutil.CreateTestDefinition(t, st, adminID, "fidelity-def-"+testutil.NewID()[:8])
	testutil.CreateTestToken(t, st, adminID, "fidelity-token", "hash-"+testutil.NewID()[:8])
	testutil.CreateTestAssignment(t, st, adminID, "action", actionID, "device", deviceID, 0)
	_ = setID
	_ = deviceGroupID

	enc := testutil.NewEncryptor(t)
	providerID := testutil.CreateTestIdentityProvider(t, st, enc, adminID, "Fidelity IdP", "fidelity-"+testutil.NewID()[:8])
	testutil.EnableSCIMForProvider(t, st, adminID, providerID)

	// Secret-history + security-alert projections: their row ids are the
	// rotating/raising event's ULID (spec 20 / F-15) — before that
	// change they were DB-minted random uuids, which a rebuild silently
	// re-minted. These rows make the round-trip prove the determinism.
	rotatedAt := "2026-07-01T10:00:00Z"
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "lps_password",
		StreamID:   deviceID + ":" + actionID + ":root",
		EventType:  "LpsPasswordRotated",
		Data: map[string]any{
			"device_id": deviceID, "action_id": actionID, "username": "root",
			"password": "enc:v1:fixture-lps", "rotated_at": rotatedAt, "rotation_reason": "scheduled",
		},
		ActorType: "device",
		ActorID:   deviceID,
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "luks_key",
		StreamID:   deviceID + ":" + actionID + ":/dev/sda2",
		EventType:  "LuksKeyRotated",
		Data: map[string]any{
			"device_id": deviceID, "action_id": actionID, "device_path": "/dev/sda2",
			"passphrase": "enc:v1:fixture-luks", "rotated_at": rotatedAt, "rotation_reason": "scheduled",
		},
		ActorType: "device",
		ActorID:   deviceID,
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   deviceID,
		EventType:  "SecurityAlert",
		Data: map[string]any{
			"alert_type": "fidelity-probe", "message": "round-trip fixture alert",
		},
		ActorType: "device",
		ActorID:   deviceID,
	}))
	// Acknowledge it by the raising event's ULID so the ack column set
	// (a projection UPDATE keyed by the id) is exercised too.
	var alertEventID string
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		`SELECT id FROM events WHERE event_type = 'SecurityAlert' AND stream_id = $1
		 ORDER BY sequence_num DESC LIMIT 1`, deviceID).Scan(&alertEventID))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   deviceID,
		EventType:  "SecurityAlertAcknowledged",
		Data:       map[string]any{"alert_id": alertEventID, "acknowledged_by": adminID},
		ActorType:  "user",
		ActorID:    adminID,
	}))
}

// TestRebuildAll_FullFidelityRoundTrip pins spec 21 AC 6: a no-arg
// rebuild reproduces every projection byte-identically.
func TestRebuildAll_FullFidelityRoundTrip(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	seedRichFixture(t, st)

	before := dumpRebuildTables(t, st)
	require.NotEmpty(t, before)
	nonEmpty := 0
	for _, rows := range before {
		if rows != "" {
			nonEmpty++
		}
	}
	// Matches-zero guard: a fixture that populates almost nothing would
	// make the byte-compare pass vacuously.
	require.GreaterOrEqual(t, nonEmpty, 10,
		"fixture too thin (%d non-empty projection tables) — round-trip would prove little", nonEmpty)

	_, err := st.RebuildAll(ctx)
	require.NoError(t, err)

	after := dumpRebuildTables(t, st)
	for tbl, rows := range before {
		assert.Equalf(t, rows, after[tbl],
			"projection table %q did not reproduce byte-identically after a full rebuild — replay infidelity (F-04 class)", tbl)
	}
}
