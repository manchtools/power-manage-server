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

// TestMigration028_UnportedProjectorsRemain — the eleven still-PL/pgSQL
// projectors must survive migration 028 untouched, otherwise the
// dispatcher would trigger "function does not exist" errors for
// every event of those stream types. Sibling-sweep coverage paired
// with TestMigration028_DroppedStubsAreGone.
func TestMigration028_UnportedProjectorsRemain(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	keptProjectors := []string{
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
	for _, fn := range keptProjectors {
		var exists bool
		err := st.Pool().QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM pg_proc WHERE proname = $1)`, fn,
		).Scan(&exists)
		require.NoError(t, err)
		assert.True(t, exists, "%s must survive migration 028 — its stream type is not yet ported to Go", fn)
	}
}
