package store_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/searchrpc"
	"github.com/manchtools/power-manage/server/internal/store"
)

func TestPostgresSearchHandlers_ValidateAuthorizeScopeAndAssign(t *testing.T) {
	st, raw := setupPostgres(t)
	ctx := context.Background()
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	h := searchrpc.NewHandlers(st, slog.New(slog.NewTextHandler(io.Discard, nil)), func() time.Time { return now })

	_, err := h.Search(ctx, connect.NewRequest(&pmv1.SearchRequest{Query: strings.Repeat("x", 1025)}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	_, err = h.Search(ctx, connect.NewRequest(&pmv1.SearchRequest{Scope: pmv1.SearchScope_SEARCH_SCOPE_ACTIONS}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))

	actorID, groupA, groupB := newID(), newID(), newID()
	actionA, actionB, deviceA, deviceB := newID(), newID(), newID(), newID()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO users (id, email, display_name, linux_username, linux_uid, created_at, updated_at)
			VALUES ($1, 'searcher@example.test', 'Searcher', 'searcher', 210001, $2, $2)`, []any{actorID, now}},
		{`INSERT INTO device_groups (id, name, created_at) VALUES ($1, 'Fleet A', $3), ($2, 'Fleet B', $3)`, []any{groupA, groupB, now}},
		{`INSERT INTO actions (id, name, action_type, params, created_at, updated_at)
			VALUES ($1, 'Scoped alpha', 100, '{}'::jsonb, $3, $3), ($2, 'Scoped beta', 100, '{}'::jsonb, $3, $3)`, []any{actionA, actionB, now}},
		{`INSERT INTO assignments (id, source_type, source_id, target_type, target_id, mode, created_at, created_by)
			VALUES ($1, 'action', $2, 'device_group', $3, 0, $5, $6),
			       ($4, 'action', $7, 'device_group', $8, 0, $5, $6)`, []any{newID(), actionA, groupA, newID(), now, actorID, actionB, groupB}},
		{`INSERT INTO devices (id, hostname, agent_version, agent_sealing_public_key, registered_at)
			VALUES ($1, 'assigned-device', '1', decode(repeat('01', 32), 'hex'), $3),
			       ($2, 'foreign-device', '1', decode(repeat('02', 32), 'hex'), $3)`, []any{deviceA, deviceB, now}},
		{`INSERT INTO device_assigned_users (device_id, user_id, assigned_at, assigned_by)
			VALUES ($1, $2, $3, $2)`, []any{deviceA, actorID, now}},
	}
	for _, statement := range statements {
		_, err := raw.Exec(ctx, statement.query, statement.args...)
		require.NoError(t, err)
	}

	searchOnly := auth.WithUser(ctx, &auth.UserContext{
		ID: actorID, Kind: auth.PrincipalUser, Permissions: []string{"Search"},
	})
	_, err = h.Search(searchOnly, connect.NewRequest(&pmv1.SearchRequest{Scope: pmv1.SearchScope_SEARCH_SCOPE_ACTIONS}))
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err), "Search never bypasses the facet's List permission")

	scoped := auth.WithUser(ctx, &auth.UserContext{
		ID: actorID, Kind: auth.PrincipalUser, Permissions: []string{"Search", "ListActions", "ListDevices"},
		ScopedGrants: []auth.ScopedGrant{{Permission: "ListDevices", ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: groupA}},
	})
	resp, err := h.Search(scoped, connect.NewRequest(&pmv1.SearchRequest{
		Scope: pmv1.SearchScope_SEARCH_SCOPE_ACTIONS, Query: "Scoped", SortField: pmv1.SortField_SORT_FIELD_NAME,
		SortDirection: pmv1.SortDirection_SORT_DIRECTION_ASC,
	}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.Results, 1)
	assert.Equal(t, actionA, resp.Msg.Results[0].Id)
	assert.Equal(t, pmv1.SearchScope_SEARCH_SCOPE_ACTIONS, resp.Msg.Results[0].Scope)
	assert.Equal(t, int32(1), resp.Msg.TotalCount)

	assigned := auth.WithUser(ctx, &auth.UserContext{
		ID: actorID, Kind: auth.PrincipalUser, Permissions: []string{"Search", "ListDevices:assigned"},
	})
	resp, err = h.Search(assigned, connect.NewRequest(&pmv1.SearchRequest{
		Scope: pmv1.SearchScope_SEARCH_SCOPE_DEVICES, PageSize: 200,
	}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.Results, 1)
	assert.Equal(t, deviceA, resp.Msg.Results[0].Id)
	assert.Equal(t, int32(1), resp.Msg.TotalCount)

	_, err = h.Search(scoped, connect.NewRequest(&pmv1.SearchRequest{
		Scope: pmv1.SearchScope_SEARCH_SCOPE_ACTIONS, PageToken: "-1",
	}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestPostgresSearchHandlers_AuditSearchAndRebuildRecordEvidence(t *testing.T) {
	st, raw := setupPostgres(t)
	ctx := context.Background()
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	h := searchrpc.NewHandlers(st, slog.New(slog.NewTextHandler(io.Discard, nil)), func() time.Time { return now })
	actorID := newID()
	_, err := raw.Exec(ctx, `INSERT INTO users
		(id, email, display_name, linux_username, linux_uid, created_at, updated_at)
		VALUES ($1, 'auditor@example.test', 'Auditor', 'auditor', 210001, $2, $2)`, actorID, now)
	require.NoError(t, err)
	_, err = st.RecordOperation(ctx, store.AuditOperation{
		Class: store.ClassMutation, ActorType: "user", ActorID: actorID,
		Origin: auth.ControlRPCOrigin, RequestDescriptor: "/powermanage.v1.ControlService/DeleteAction",
		AuthorizationOutcome: store.AuthorizationAllowed, AuthorizationDetail: "DeleteAction",
		Result: store.ResultSuccess, ResultCode: "OK",
	}, store.AuditEffect{ResourceType: "action", ResourceID: newID(), Action: "DELETE", Outcome: store.EffectApplied})
	require.NoError(t, err)

	auditor := auth.WithUser(ctx, &auth.UserContext{
		ID: actorID, Kind: auth.PrincipalUser,
		Permissions: []string{"Search", "ListAuditEvents", "RebuildSearchIndex"},
	})
	resp, err := h.Search(auditor, connect.NewRequest(&pmv1.SearchRequest{
		Scope: pmv1.SearchScope_SEARCH_SCOPE_AUDIT_EVENTS, Query: "DeleteAction",
	}))
	require.NoError(t, err)
	require.NotEmpty(t, resp.Msg.Results)

	var class, descriptor, effectAction string
	var returned int64
	err = raw.QueryRow(ctx, `SELECT o.operation_class, o.request_descriptor, e.action, e.after_count
		FROM audit_operations o JOIN audit_effects e ON e.operation_id = o.operation_id
		WHERE o.request_descriptor = $1 ORDER BY o.chain_seq DESC LIMIT 1`,
		powermanagev1connect.ControlServiceSearchProcedure).Scan(&class, &descriptor, &effectAction, &returned)
	require.NoError(t, err)
	assert.Equal(t, string(store.ClassSensitiveRead), class)
	assert.Equal(t, powermanagev1connect.ControlServiceSearchProcedure, descriptor)
	assert.Equal(t, "SEARCH", effectAction)
	assert.Equal(t, int64(len(resp.Msg.Results)), returned)

	_, err = h.RebuildSearchIndex(auditor, connect.NewRequest(&pmv1.RebuildSearchIndexRequest{}))
	require.NoError(t, err)
	err = raw.QueryRow(ctx, `SELECT e.action FROM audit_operations o
		JOIN audit_effects e ON e.operation_id = o.operation_id
		WHERE o.request_descriptor = $1 ORDER BY o.chain_seq DESC LIMIT 1`,
		powermanagev1connect.ControlServiceRebuildSearchIndexProcedure).Scan(&effectAction)
	require.NoError(t, err)
	assert.Equal(t, "REBUILD_SEARCH", effectAction)

	assert.ElementsMatch(t, []string{
		powermanagev1connect.ControlServiceSearchProcedure,
		powermanagev1connect.ControlServiceRebuildSearchIndexProcedure,
	}, h.Mount(http.NewServeMux()))
	assert.Equal(t, []string{powermanagev1connect.ControlServiceSearchProcedure}, searchrpc.ReadProcedures())
	assert.Equal(t, []string{powermanagev1connect.ControlServiceRebuildSearchIndexProcedure}, searchrpc.MutationProcedures())
}
