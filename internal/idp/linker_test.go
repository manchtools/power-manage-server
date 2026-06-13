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

// mockQuerier implements the Querier interface for testing.
type mockQuerier struct {
	linuxUID      int32
	groupRoles    map[string][]db.RolesProjection
	groupRolesErr error
}

func (m *mockQuerier) GetUserGroupRoles(_ context.Context, groupID string) ([]db.RolesProjection, error) {
	if m.groupRolesErr != nil {
		return nil, m.groupRolesErr
	}
	return m.groupRoles[groupID], nil
}

func (m *mockQuerier) GetIdentityLinkByProviderAndExternalID(_ context.Context, _ db.GetIdentityLinkByProviderAndExternalIDParams) (db.IdentityLinksProjection, error) {
	return db.IdentityLinksProjection{}, store.ErrNotFound
}

func (m *mockQuerier) GetUserByEmail(_ context.Context, _ string) (db.UsersProjection, error) {
	return db.UsersProjection{}, store.ErrNotFound
}

func (m *mockQuerier) GetUserByID(_ context.Context, _ string) (db.UsersProjection, error) {
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
