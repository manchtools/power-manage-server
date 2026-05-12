package api

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sdkvalidate "github.com/manchtools/power-manage/sdk/go/validate"
)

type validStruct struct {
	Name  string `validate:"required,min=2,max=100"`
	Email string `validate:"required,email"`
	ID    string `validate:"required,ulid"`
}

type optionalStruct struct {
	Name string `validate:"omitempty,min=2"`
}

func TestValidate_ValidStruct(t *testing.T) {
	err := Validate(context.Background(), validStruct{
		Name:  "Alice",
		Email: "alice@example.com",
		ID:    "01ARZ3NDEKTSV4RRFFQ69G5FAV",
	})
	assert.NoError(t, err)
}

func TestValidate_MissingRequired(t *testing.T) {
	err := Validate(context.Background(), validStruct{})
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	assert.Contains(t, err.Error(), "name is required")
	assert.Contains(t, err.Error(), "email is required")
}

func TestValidate_InvalidEmail(t *testing.T) {
	err := Validate(context.Background(), validStruct{
		Name:  "Alice",
		Email: "not-an-email",
		ID:    "01ARZ3NDEKTSV4RRFFQ69G5FAV",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email must be a valid email")
}

func TestValidate_InvalidULID(t *testing.T) {
	err := Validate(context.Background(), validStruct{
		Name:  "Alice",
		Email: "alice@example.com",
		ID:    "not-a-ulid",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "id must be a valid ULID")
}

func TestValidate_ValidULID(t *testing.T) {
	err := Validate(context.Background(), validStruct{
		Name:  "Alice",
		Email: "alice@example.com",
		ID:    "01ARZ3NDEKTSV4RRFFQ69G5FAV",
	})
	assert.NoError(t, err)
}

func TestValidate_TooShort(t *testing.T) {
	err := Validate(context.Background(), validStruct{
		Name:  "A",
		Email: "alice@example.com",
		ID:    "01ARZ3NDEKTSV4RRFFQ69G5FAV",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "name must be at least 2 characters")
}

func TestValidate_Optional_Empty(t *testing.T) {
	err := Validate(context.Background(), optionalStruct{Name: ""})
	assert.NoError(t, err)
}

func TestValidate_Optional_TooShort(t *testing.T) {
	err := Validate(context.Background(), optionalStruct{Name: "A"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "name must be at least 2 characters")
}

func TestToSnakeCase(t *testing.T) {
	// Acronym handling pinned by #140 — the previous shape split
	// contiguous uppercase letters one at a time (`UserID` →
	// `user_i_d`), which leaked nonsense into operator-facing
	// validation error messages. New rule: `_` is inserted before an
	// uppercase letter only at word boundaries (lowercase→upper or
	// end-of-acronym), so acronyms ride together.
	tests := map[string]string{
		"Name":           "name",
		"UserID":         "user_id",
		"ActionSetID":    "action_set_id",
		"createdAt":      "created_at",
		"simple":         "simple",
		"HTTPStatusCode": "http_status_code",
		"IDOnly":         "id_only", // acronym at start
		"ID":             "id",      // pure acronym
		"a":              "a",       // single lowercase
		"":               "",        // empty
	}
	for input, expected := range tests {
		assert.Equal(t, expected, sdkvalidate.ToSnakeCase(input), "ToSnakeCase(%q)", input)
	}
}
