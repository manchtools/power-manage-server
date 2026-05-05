package projectors

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// ServerSettingsUpdatedPayload represents the decoded shape of a
// ServerSettingUpdated event. Pointer fields distinguish "field
// present in payload" from "field omitted" — the deleted PL/pgSQL
// projector used `COALESCE((event.data->>'k')::BOOLEAN, existing)`
// to preserve unset values, and the Go shape mirrors that contract
// by passing nil through to the SQL UPDATE which uses COALESCE on
// the receiving side.
type ServerSettingsUpdatedPayload struct {
	UserProvisioningEnabled *bool `json:"user_provisioning_enabled,omitempty"`
	SshAccessForAll         *bool `json:"ssh_access_for_all,omitempty"`
}

// ServerSettingsUpdate carries the same payload shape plus the
// per-event metadata the listener stamps onto the projection row.
// Exposed so the test suite can drive the SQL UPDATE directly to
// exercise the projection_version guard without faking an event.
type ServerSettingsUpdate struct {
	UserProvisioningEnabled *bool
	SshAccessForAll         *bool
	OccurredAt              time.Time
	ProjectionVersion       int64
}

// ServerSettingsUpdatedFromEvent decodes ServerSettingUpdated.
// Returns ErrIgnoredEvent for any other (stream, event_type) so the
// listener wrapper can silently no-op.
//
// An empty payload is NOT an error — the deleted PL/pgSQL projector
// would have applied `COALESCE(NULL, existing)` to every field,
// which is a no-op UPDATE. We preserve that behavior.
func ServerSettingsUpdatedFromEvent(e store.PersistedEvent) (ServerSettingsUpdatedPayload, error) {
	if e.StreamType != "server_settings" || e.EventType != "ServerSettingUpdated" {
		return ServerSettingsUpdatedPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return ServerSettingsUpdatedPayload{}, nil
	}
	var p ServerSettingsUpdatedPayload
	if err := json.Unmarshal(e.Data, &p); err != nil {
		return ServerSettingsUpdatedPayload{}, fmt.Errorf("projector: invalid ServerSettingUpdated payload: %w", err)
	}
	return p, nil
}

// ApplyServerSettingsUpdateForTest exposes the SQL UPDATE side of
// the listener so tests can drive it with a synthetic
// projection_version (e.g. an artificially-stale replay). Production
// code goes through the listener; this is test-only seam.
func ApplyServerSettingsUpdateForTest(ctx context.Context, st *store.Store, u ServerSettingsUpdate) error {
	return st.Queries().UpdateServerSettings(ctx, db.UpdateServerSettingsParams{
		UserProvisioningEnabled: u.UserProvisioningEnabled,
		SshAccessForAll:         u.SshAccessForAll,
		UpdatedAt:               u.OccurredAt,
		ProjectionVersion:       u.ProjectionVersion,
	})
}
