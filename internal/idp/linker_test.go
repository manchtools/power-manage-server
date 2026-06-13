package idp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// mockQuerier implements the Querier interface for testing. Optional override
// fields make each lookup branch reachable; unset fields keep the default
// ErrNotFound so existing tests are unaffected (WS5 #3).
type mockQuerier struct {
	linuxUID      int32
	groupRoles    map[string][]db.RolesProjection
	groupRolesErr error

	// linkByExternalID, when non-nil, is returned by
	// GetIdentityLinkByProviderAndExternalID (the existing-link branch).
	linkByExternalID *db.IdentityLinksProjection
	// userByEmail, when non-nil, is returned by GetUserByEmail (auto-link branch).
	userByEmail *db.UsersProjection
	// userByID, when non-nil, is returned by GetUserByID (live-user check after
	// finding an existing link). Leave nil to simulate a soft-deleted user.
	userByID *db.UsersProjection
}

func (m *mockQuerier) GetUserGroupRoles(_ context.Context, groupID string) ([]db.RolesProjection, error) {
	if m.groupRolesErr != nil {
		return nil, m.groupRolesErr
	}
	return m.groupRoles[groupID], nil
}

func (m *mockQuerier) GetIdentityLinkByProviderAndExternalID(_ context.Context, _ db.GetIdentityLinkByProviderAndExternalIDParams) (db.IdentityLinksProjection, error) {
	if m.linkByExternalID != nil {
		return *m.linkByExternalID, nil
	}
	return db.IdentityLinksProjection{}, store.ErrNotFound
}

func (m *mockQuerier) GetUserByEmail(_ context.Context, _ string) (db.UsersProjection, error) {
	if m.userByEmail != nil {
		return *m.userByEmail, nil
	}
	return db.UsersProjection{}, store.ErrNotFound
}

func (m *mockQuerier) GetUserByID(_ context.Context, _ string) (db.UsersProjection, error) {
	if m.userByID != nil {
		return *m.userByID, nil
	}
	return db.UsersProjection{}, store.ErrNotFound
}

func (m *mockQuerier) GetServerSettings(_ context.Context) (db.ServerSettingsProjection, error) {
	return db.ServerSettingsProjection{}, nil
}

func (m *mockQuerier) GetNextLinuxUID(_ context.Context) (int32, error) {
	return m.linuxUID, nil
}

// mockAppender captures appended events for inspection.
type mockAppender struct {
	events []EventInput
}

// TestGroupIsAdminBearing pins the SSO admin-group audit decision (#9): only a
// group carrying the SYSTEM Admin role triggers the privileged-grant audit, and
// a lookup failure is best-effort (false) so it never blocks the SSO sync.
func TestGroupIsAdminBearing(t *testing.T) {
	adminRole := db.RolesProjection{ID: "r-admin", Name: "Admin", IsSystem: true}
	plainRole := db.RolesProjection{ID: "r-ops", Name: "Ops", IsSystem: false}
	namedAdmin := db.RolesProjection{ID: "r-x", Name: "Admin", IsSystem: false} // coincidental name

	cases := []struct {
		name  string
		q     *mockQuerier
		group string
		want  bool
	}{
		{"system Admin role → audited", &mockQuerier{groupRoles: map[string][]db.RolesProjection{"g": {plainRole, adminRole}}}, "g", true},
		{"plain role only → not audited", &mockQuerier{groupRoles: map[string][]db.RolesProjection{"g": {plainRole}}}, "g", false},
		{"non-system role named Admin → not audited (keys on IsSystem)", &mockQuerier{groupRoles: map[string][]db.RolesProjection{"g": {namedAdmin}}}, "g", false},
		{"no roles → not audited", &mockQuerier{groupRoles: map[string][]db.RolesProjection{}}, "g", false},
		{"lookup error → false, never blocks sync", &mockQuerier{groupRolesErr: assert.AnError}, "g", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := NewLinker(tc.q, &mockAppender{})
			assert.Equal(t, tc.want, l.groupIsAdminBearing(context.Background(), tc.group))
		})
	}
}

func (m *mockAppender) AppendEvent(_ context.Context, event EventInput) error {
	m.events = append(m.events, event)
	return nil
}

func TestLinkOrCreate_AutoCreateUserIncludesLinuxFields(t *testing.T) {
	querier := &mockQuerier{linuxUID: 10001}
	appender := &mockAppender{}
	linker := NewLinker(querier, appender)

	provider := store.IdentityProvider{
		ID:              "provider-1",
		Slug:            "test-idp",
		AutoCreateUsers: true,
		AutoLinkByEmail: false,
	}

	claims := &UserClaims{
		Subject:           "ext-user-123",
		Email:             "john.doe@example.com",
		Name:              "John Doe",
		GivenName:         "John",
		FamilyName:        "Doe",
		PreferredUsername: "johndoe",
	}

	result, err := linker.LinkOrCreate(context.Background(), provider, claims)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.IsNew)

	// Find the UserCreatedWithRoles event
	var userCreatedEvent *EventInput
	for i, e := range appender.events {
		if e.EventType == "UserCreatedWithRoles" {
			userCreatedEvent = &appender.events[i]
			break
		}
	}
	require.NotNil(t, userCreatedEvent, "expected a UserCreatedWithRoles event to be emitted")

	// Linker emits a typed payloads.UserCreatedWithRoles after the
	// PR-F sweep — assert the typed shape directly. Pointer fields
	// preserve absent-vs-explicit distinction; require.NotNil before
	// dereferencing so a regression to nil pointers fails loudly.
	created, ok := userCreatedEvent.Data.(payloads.UserCreatedWithRoles)
	require.True(t, ok, "UserCreatedWithRoles event Data should be a typed payloads.UserCreatedWithRoles")
	require.NotNil(t, created.LinuxUsername, "linux_username pointer must be set")
	assert.Equal(t, "johndoe", *created.LinuxUsername)
	require.NotNil(t, created.LinuxUID, "linux_uid pointer must be set")
	assert.Equal(t, int32(10001), *created.LinuxUID)

	// Verify the event data can be marshaled (sanity check)
	_, err = json.Marshal(userCreatedEvent.Data)
	require.NoError(t, err)
}

func TestLinkOrCreate_AutoCreateUserDeriveUsernameFromEmail(t *testing.T) {
	querier := &mockQuerier{linuxUID: 10002}
	appender := &mockAppender{}
	linker := NewLinker(querier, appender)

	provider := store.IdentityProvider{
		ID:              "provider-2",
		Slug:            "test-idp",
		AutoCreateUsers: true,
		AutoLinkByEmail: false,
	}

	claims := &UserClaims{
		Subject: "ext-user-456",
		Email:   "jane.doe@example.com",
		Name:    "Jane Doe",
		// No PreferredUsername — should fall back to email local part
	}

	result, err := linker.LinkOrCreate(context.Background(), provider, claims)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.IsNew)

	// Find the UserCreatedWithRoles event
	var userCreatedEvent *EventInput
	for i, e := range appender.events {
		if e.EventType == "UserCreatedWithRoles" {
			userCreatedEvent = &appender.events[i]
			break
		}
	}
	require.NotNil(t, userCreatedEvent)

	created, ok := userCreatedEvent.Data.(payloads.UserCreatedWithRoles)
	require.True(t, ok, "UserCreatedWithRoles event Data should be a typed payloads.UserCreatedWithRoles")
	require.NotNil(t, created.LinuxUsername)
	assert.Equal(t, "jane.doe", *created.LinuxUsername)
	require.NotNil(t, created.LinuxUID)
	assert.Equal(t, int32(10002), *created.LinuxUID)
}

// eventTypes lists the EventType of every appended event (WS5 #3 helpers).
func eventTypes(a *mockAppender) []string {
	out := make([]string, 0, len(a.events))
	for _, e := range a.events {
		out = append(out, e.EventType)
	}
	return out
}

func countEventsOfType(a *mockAppender, eventType string) int {
	n := 0
	for _, e := range a.events {
		if e.EventType == eventType {
			n++
		}
	}
	return n
}

// TestLinkOrCreate_AutoLinkByEmail_EmitsLinkForExistingUser pins WS5 #3: with
// AutoLinkByEmail on and a matching existing user, exactly one IdentityLinked
// event is emitted for that user and the result is not new.
func TestLinkOrCreate_AutoLinkByEmail_EmitsLinkForExistingUser(t *testing.T) {
	existing := db.UsersProjection{ID: "user-existing", Email: "match@example.com"}
	querier := &mockQuerier{userByEmail: &existing}
	appender := &mockAppender{}
	linker := NewLinker(querier, appender)

	provider := store.IdentityProvider{ID: "p1", Slug: "idp", AutoLinkByEmail: true}
	claims := &UserClaims{Subject: "ext-1", Email: "match@example.com"}

	result, err := linker.LinkOrCreate(context.Background(), provider, claims)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.IsNew)
	assert.Equal(t, "user-existing", result.UserID)

	require.Equal(t, 1, countEventsOfType(appender, "IdentityLinked"),
		"exactly one IdentityLinked, got events: %v", eventTypes(appender))
	for _, e := range appender.events {
		if e.EventType == "IdentityLinked" {
			linked, ok := e.Data.(payloads.IdentityLinked)
			require.True(t, ok)
			assert.Equal(t, "user-existing", linked.UserID)
		}
	}
}

// TestLinkOrCreate_AutoLinkDisabled_NoLink pins WS5 #3: with AutoLinkByEmail
// AND AutoCreateUsers off, an existing-by-email user is NOT linked — the
// rejection path returns ErrNoMatchingAccount and emits no IdentityLinked.
func TestLinkOrCreate_AutoLinkDisabled_NoLink(t *testing.T) {
	existing := db.UsersProjection{ID: "user-x", Email: "x@example.com"}
	querier := &mockQuerier{userByEmail: &existing}
	appender := &mockAppender{}
	linker := NewLinker(querier, appender)

	provider := store.IdentityProvider{ID: "p1", Slug: "idp", AutoLinkByEmail: false, AutoCreateUsers: false}
	claims := &UserClaims{Subject: "ext-2", Email: "x@example.com"}

	_, err := linker.LinkOrCreate(context.Background(), provider, claims)
	require.ErrorIs(t, err, ErrNoMatchingAccount)
	assert.Equal(t, 0, countEventsOfType(appender, "IdentityLinked"),
		"no link may be emitted when auto-link is off")
}

// TestLinkOrCreate_ExistingLink_UpdatesLogin pins WS5 #3: a live existing link
// updates the login timestamp (IdentityLinkLoginUpdated), not a new link.
func TestLinkOrCreate_ExistingLink_UpdatesLogin(t *testing.T) {
	link := db.IdentityLinksProjection{ID: "link-1", UserID: "user-1", ProviderID: "p1", ExternalID: "ext-3"}
	user := db.UsersProjection{ID: "user-1", Email: "u1@example.com"}
	querier := &mockQuerier{linkByExternalID: &link, userByID: &user}
	appender := &mockAppender{}
	linker := NewLinker(querier, appender)

	provider := store.IdentityProvider{ID: "p1", Slug: "idp"}
	claims := &UserClaims{Subject: "ext-3", Email: "u1@example.com"}

	result, err := linker.LinkOrCreate(context.Background(), provider, claims)
	require.NoError(t, err)
	assert.False(t, result.IsNew)
	assert.Equal(t, "user-1", result.UserID)
	assert.Equal(t, 1, countEventsOfType(appender, "IdentityLinkLoginUpdated"),
		"existing live link must update login, got: %v", eventTypes(appender))
	assert.Equal(t, 0, countEventsOfType(appender, "IdentityLinked"),
		"must not emit a fresh IdentityLinked for an already-linked user")
}

// TestLinkOrCreate_SoftDeletedLinkedUser_CleansUpAndFallsThrough pins WS5 #3: a
// link whose user was soft-deleted emits IdentityUnlinked and then falls
// through (auto-link/create off → ErrNoMatchingAccount).
func TestLinkOrCreate_SoftDeletedLinkedUser_CleansUpAndFallsThrough(t *testing.T) {
	link := db.IdentityLinksProjection{ID: "link-2", UserID: "ghost", ProviderID: "p1", ExternalID: "ext-4"}
	querier := &mockQuerier{linkByExternalID: &link /* userByID nil → soft-deleted */}
	appender := &mockAppender{}
	linker := NewLinker(querier, appender)

	provider := store.IdentityProvider{ID: "p1", Slug: "idp", AutoLinkByEmail: false, AutoCreateUsers: false}
	claims := &UserClaims{Subject: "ext-4", Email: "ghost@example.com"}

	_, err := linker.LinkOrCreate(context.Background(), provider, claims)
	require.ErrorIs(t, err, ErrNoMatchingAccount)
	assert.Equal(t, 1, countEventsOfType(appender, "IdentityUnlinked"),
		"a soft-deleted linked user must be cleaned up, got: %v", eventTypes(appender))
}
