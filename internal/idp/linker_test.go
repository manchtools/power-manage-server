package idp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// mockQuerier implements the Querier interface for testing.
type mockQuerier struct {
	linuxUID int32
}

func (m *mockQuerier) GetIdentityLinkByProviderAndExternalID(_ context.Context, _ db.GetIdentityLinkByProviderAndExternalIDParams) (db.IdentityLinksProjection, error) {
	return db.IdentityLinksProjection{}, pgx.ErrNoRows
}

func (m *mockQuerier) GetUserByEmail(_ context.Context, _ string) (db.UsersProjection, error) {
	return db.UsersProjection{}, pgx.ErrNoRows
}

func (m *mockQuerier) GetUserByID(_ context.Context, _ string) (db.UsersProjection, error) {
	return db.UsersProjection{}, pgx.ErrNoRows
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

func (m *mockAppender) AppendEvent(_ context.Context, event EventInput) error {
	m.events = append(m.events, event)
	return nil
}

func TestLinkOrCreate_AutoCreateUserIncludesLinuxFields(t *testing.T) {
	querier := &mockQuerier{linuxUID: 10001}
	appender := &mockAppender{}
	linker := NewLinker(querier, appender)

	provider := db.IdentityProvidersProjection{
		ID:              "provider-1",
		Slug:            "test-idp",
		AutoCreateUsers: true,
		AutoLinkByEmail: false,
	}

	claims := &UserClaims{
		Subject:          "ext-user-123",
		Email:            "john.doe@example.com",
		Name:             "John Doe",
		GivenName:        "John",
		FamilyName:       "Doe",
		PreferredUsername: "johndoe",
	}

	result, err := linker.LinkOrCreate(context.Background(), provider, claims)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.IsNew)

	// Find the UserCreated event
	var userCreatedEvent *EventInput
	for i, e := range appender.events {
		if e.EventType == "UserCreated" {
			userCreatedEvent = &appender.events[i]
			break
		}
	}
	require.NotNil(t, userCreatedEvent, "expected a UserCreated event to be emitted")

	// Verify linux_username is present and derived from preferred_username
	linuxUsername, ok := userCreatedEvent.Data["linux_username"]
	assert.True(t, ok, "UserCreated event data should include linux_username")
	assert.Equal(t, "johndoe", linuxUsername)

	// Verify linux_uid is present and matches the mock return value
	linuxUID, ok := userCreatedEvent.Data["linux_uid"]
	assert.True(t, ok, "UserCreated event data should include linux_uid")
	assert.Equal(t, int32(10001), linuxUID)

	// Verify the event data can be marshaled (sanity check)
	_, err = json.Marshal(userCreatedEvent.Data)
	require.NoError(t, err)
}

func TestLinkOrCreate_AutoCreateUserDeriveUsernameFromEmail(t *testing.T) {
	querier := &mockQuerier{linuxUID: 10002}
	appender := &mockAppender{}
	linker := NewLinker(querier, appender)

	provider := db.IdentityProvidersProjection{
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

	// Find the UserCreated event
	var userCreatedEvent *EventInput
	for i, e := range appender.events {
		if e.EventType == "UserCreated" {
			userCreatedEvent = &appender.events[i]
			break
		}
	}
	require.NotNil(t, userCreatedEvent)

	// When preferred_username is empty, linux_username should be derived from email
	linuxUsername, ok := userCreatedEvent.Data["linux_username"]
	assert.True(t, ok, "UserCreated event data should include linux_username")
	assert.Equal(t, "jane.doe", linuxUsername)

	linuxUID, ok := userCreatedEvent.Data["linux_uid"]
	assert.True(t, ok, "UserCreated event data should include linux_uid")
	assert.Equal(t, int32(10002), linuxUID)
}
