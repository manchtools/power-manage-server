package projectors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
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
	if e.StreamType != "server_settings" || e.EventType != string(eventtypes.ServerSettingUpdated) {
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

// ApplyServerSettingsUpdate runs the COALESCE-based UPDATE behind
// the listener. Shared between the production listener and the test
// suite, which uses it to drive a synthetic projection_version (e.g.
// an artificially-stale replay) without faking an event.
func ApplyServerSettingsUpdate(ctx context.Context, st *store.Store, u ServerSettingsUpdate) error {
	return st.Queries().UpdateServerSettings(ctx, db.UpdateServerSettingsParams{
		UserProvisioningEnabled: u.UserProvisioningEnabled,
		SshAccessForAll:         u.SshAccessForAll,
		UpdatedAt:               u.OccurredAt,
		ProjectionVersion:       u.ProjectionVersion,
	})
}

// ApplyServerSettingsRebuild is the rebuild applier for the singleton
// server_settings_projection (#497). A rebuild TRUNCATEs the table, dropping
// the migration-seeded 'global' row; the projector's UPDATE ... WHERE id =
// 'global' would then match nothing and the current settings would be lost.
//
// Every replayed event first ensures the seed row exists (idempotent INSERT
// at projection_version 0), then applies the COALESCE UPDATE. Seeding on
// every event — rather than once — keeps the applier stateless and correct
// whether it replays one event or a thousand; ON CONFLICT DO NOTHING makes
// the repeat seeds free. Non-ServerSettingUpdated events on the stream
// (there are none today) no-op via the decoder's ErrIgnoredEvent.
func ApplyServerSettingsRebuild(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	if e.StreamType != "server_settings" {
		return nil
	}
	payload, err := ServerSettingsUpdatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	if err := q.SeedServerSettings(ctx); err != nil {
		return err
	}
	return q.UpdateServerSettings(ctx, db.UpdateServerSettingsParams{
		UserProvisioningEnabled: payload.UserProvisioningEnabled,
		SshAccessForAll:         payload.SshAccessForAll,
		UpdatedAt:               e.OccurredAt,
		ProjectionVersion:       e.SequenceNum,
	})
}
