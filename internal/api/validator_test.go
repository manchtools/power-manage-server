package api

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	err := Validate(validStruct{
		Name:  "Alice",
		Email: "alice@example.com",
		ID:    "01ARZ3NDEKTSV4RRFFQ69G5FAV",
	})
	assert.NoError(t, err)
}

func TestValidate_MissingRequired(t *testing.T) {
	err := Validate(validStruct{})
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	assert.Contains(t, err.Error(), "name is required")
	assert.Contains(t, err.Error(), "email is required")
}

func TestValidate_InvalidEmail(t *testing.T) {
	err := Validate(validStruct{
		Name:  "Alice",
		Email: "not-an-email",
		ID:    "01ARZ3NDEKTSV4RRFFQ69G5FAV",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email must be a valid email")
}

func TestValidate_InvalidULID(t *testing.T) {
	err := Validate(validStruct{
		Name:  "Alice",
		Email: "alice@example.com",
		ID:    "not-a-ulid",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "i_d must be a valid ULID")
}

func TestValidate_ValidULID(t *testing.T) {
	err := Validate(validStruct{
		Name:  "Alice",
		Email: "alice@example.com",
		ID:    "01ARZ3NDEKTSV4RRFFQ69G5FAV",
	})
	assert.NoError(t, err)
}

func TestValidate_TooShort(t *testing.T) {
	err := Validate(validStruct{
		Name:  "A",
		Email: "alice@example.com",
		ID:    "01ARZ3NDEKTSV4RRFFQ69G5FAV",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "name must be at least 2 characters")
}

func TestValidate_Optional_Empty(t *testing.T) {
	err := Validate(optionalStruct{Name: ""})
	assert.NoError(t, err)
}

func TestValidate_Optional_TooShort(t *testing.T) {
	err := Validate(optionalStruct{Name: "A"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "name must be at least 2 characters")
}

func TestToSnakeCase(t *testing.T) {
	tests := map[string]string{
		"Name":            "name",
		"UserID":          "user_i_d",
		"ActionSetID":     "action_set_i_d",
		"createdAt":       "created_at",
		"simple":          "simple",
		"HTTPStatusCode":  "h_t_t_p_status_code",
	}
	for input, expected := range tests {
		assert.Equal(t, expected, toSnakeCase(input), "toSnakeCase(%q)", input)
	}
}
