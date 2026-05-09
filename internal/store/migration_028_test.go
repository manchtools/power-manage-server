package store_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/testutil"
)

// TestMigration028_DroppedStubsAreGone — migration 028 drops the ten
// no-op PL/pgSQL projector stubs left behind by tracker #107. If any
// future migration restores them (or someone re-adds one by accident),
// this test fails. Bug-class avoidance: silent re-creation of a stub
// would let a future event-store path call into a no-op without
// projecting, which is exactly the #125 footgun this cleanup is
// closing.
func TestMigration028_DroppedStubsAreGone(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	droppedStubs := []string{
		"project_token_event",
		"project_user_selection_event",
		"project_role_event",
		"project_user_role_event",
		"project_totp_event",
		"project_identity_provider_event",
		"project_scim_group_mapping_event",
		"project_server_settings_event",
		"project_lps_password_event",
		"project_luks_key_event",
	}
	for _, fn := range droppedStubs {
		var exists bool
		err := st.Pool().QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM pg_proc WHERE proname = $1)`, fn,
		).Scan(&exists)
		require.NoError(t, err)
		assert.False(t, exists, "%s must be dropped by migration 028 — re-introducing it reopens issue #125", fn)
	}
}

// TestMigration041_AllProjectorsAndDispatcherDropped — after the
// final cleanup migration drops the project_event() dispatcher,
// the event_projector trigger, and every Phase 2 no-op stub.
// Re-introducing any of them would bring back the silent-no-op
// footgun that motivated #136.
//
// (This test replaces the previous TestMigration028_UnportedProjectorsRemain
// which asserted the eleven PL/pgSQL projectors still existed
// after migration 028. They did at that point — but migration 041
// drops them all. The schema is now Go-projector-only.)
func TestMigration041_AllProjectorsAndDispatcherDropped(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	droppedAfter041 := []string{
		"project_user_event",
		"project_device_event",
		"project_action_event",
		"project_definition_event",
		"project_action_set_event",
		"project_device_group_event",
		"project_assignment_event",
		"project_execution_event",
		"project_user_group_event",
		"project_compliance_event",
		"project_compliance_policy_event",
		"project_event", // the dispatcher itself
	}
	for _, fn := range droppedAfter041 {
		var exists bool
		err := st.Pool().QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM pg_proc WHERE proname = $1)`, fn,
		).Scan(&exists)
		require.NoError(t, err)
		assert.False(t, exists, "%s must be dropped by migration 041 — re-introducing it brings back the silent-no-op trigger overhead and the #125 footgun", fn)
	}

	var triggerExists bool
	require.NoError(t, st.Pool().QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'event_projector')`,
	).Scan(&triggerExists))
	assert.False(t, triggerExists, "event_projector trigger must be dropped by migration 041")
}
