package api_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/search"
	"github.com/manchtools/power-manage/server/internal/store"
)

// TestAffectedSearchOps is a table-driven exercise of the classifier
// for every event type Phase 1 of #81 covers. A future event type
// added in a handler must show up here with an explicit case (or an
// explicit "no-op" entry) so missed coverage is caught at review
// time rather than as silently-stale search results in production.
func TestAffectedSearchOps(t *testing.T) {
	cases := []struct {
		name      string
		event     store.PersistedEvent
		want      []api.SearchAffected
	}{
		// User scope — reindex on field-changing events
		{
			"UserCreated reindexes user",
			store.PersistedEvent{EventType: "UserCreated", StreamID: "USR1", StreamType: "user"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeUser, ID: "USR1"}},
		},
		{
			"UserEmailChanged reindexes user",
			store.PersistedEvent{EventType: "UserEmailChanged", StreamID: "USR1", StreamType: "user"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeUser, ID: "USR1"}},
		},
		{
			"UserDisabled reindexes user (the disabled flag is in the search payload)",
			store.PersistedEvent{EventType: "UserDisabled", StreamID: "USR1", StreamType: "user"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeUser, ID: "USR1"}},
		},
		{
			"UserDeleted removes user from index",
			store.PersistedEvent{EventType: "UserDeleted", StreamID: "USR1", StreamType: "user"},
			[]api.SearchAffected{{Op: api.SearchOpRemove, Scope: search.ScopeUser, ID: "USR1"}},
		},

		// User events that should NOT touch search — proves the
		// classifier doesn't over-trigger.
		{
			"UserPasswordChanged is search-irrelevant",
			store.PersistedEvent{EventType: "UserPasswordChanged", StreamID: "USR1", StreamType: "user"},
			nil,
		},
		{
			"UserSshKeyAdded is search-irrelevant",
			store.PersistedEvent{EventType: "UserSshKeyAdded", StreamID: "USR1", StreamType: "user"},
			nil,
		},
		{
			"UserLoggedIn is search-irrelevant",
			store.PersistedEvent{EventType: "UserLoggedIn", StreamID: "USR1", StreamType: "user"},
			nil,
		},

		// Device scope — reindex on field-changing events
		{
			"DeviceRegistered reindexes device",
			store.PersistedEvent{EventType: "DeviceRegistered", StreamID: "DEV1", StreamType: "device"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeDevice, ID: "DEV1"}},
		},
		{
			"DeviceLabelSet reindexes device (labels are searchable)",
			store.PersistedEvent{EventType: "DeviceLabelSet", StreamID: "DEV1", StreamType: "device"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeDevice, ID: "DEV1"}},
		},
		{
			"DeviceLabelRemoved reindexes device",
			store.PersistedEvent{EventType: "DeviceLabelRemoved", StreamID: "DEV1", StreamType: "device"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeDevice, ID: "DEV1"}},
		},
		{
			"DeviceDeleted removes device from index",
			store.PersistedEvent{EventType: "DeviceDeleted", StreamID: "DEV1", StreamType: "device"},
			[]api.SearchAffected{{Op: api.SearchOpRemove, Scope: search.ScopeDevice, ID: "DEV1"}},
		},

		// Device events that should NOT touch search.
		{
			"DeviceCertRenewed is search-irrelevant",
			store.PersistedEvent{EventType: "DeviceCertRenewed", StreamID: "DEV1", StreamType: "device"},
			nil,
		},
		{
			"DeviceAssigned is search-irrelevant (search payload has no assignee field)",
			store.PersistedEvent{EventType: "DeviceAssigned", StreamID: "DEV1", StreamType: "device"},
			nil,
		},

		// Out-of-scope (Phase 2): event types from other handlers
		// classify as nil today. When Phase 2 adds them they MUST
		// move from nil to a populated slice in the same PR that
		// removes the handler-side enqueue.
		{
			"DeviceGroupCreated is Phase-2 scope (returns nil today)",
			store.PersistedEvent{EventType: "DeviceGroupCreated", StreamID: "DGRP1", StreamType: "device_group"},
			nil,
		},
		{
			"ActionSetCreated is Phase-2 scope (returns nil today)",
			store.PersistedEvent{EventType: "ActionSetCreated", StreamID: "AS1", StreamType: "action_set"},
			nil,
		},

		// Unknown event type
		{
			"unknown event classifies as no-op",
			store.PersistedEvent{EventType: "SomeNewEventTypeWeHaveNotSeenBefore", StreamID: "X", StreamType: "future"},
			nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := api.AffectedSearchOps(tc.event)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestSearchListener_NilDepsAreSafe — boot-time guard. If the search
// index isn't configured (single-instance dev without Valkey), the
// listener factory must hand back a no-op closure rather than
// crashing AppendEvent on every write.
func TestSearchListener_NilDepsAreSafe(t *testing.T) {
	listener := api.SearchListener(nil, nil, nil)
	if listener == nil {
		t.Fatal("SearchListener should never return nil — factory contract")
	}
	// Calling the no-op listener must not panic, even with junk data.
	listener(nil, store.PersistedEvent{EventType: "UserCreated", StreamID: "X"})
}
