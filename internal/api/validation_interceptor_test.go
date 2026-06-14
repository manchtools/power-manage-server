package api

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

type validationInterceptorFixture struct {
	ID string `validate:"required,ulid"`
}

func TestValidationInterceptor_RejectsInvalidUnaryRequestBeforeHandler(t *testing.T) {
	interceptor := NewValidationInterceptor()
	called := false

	next := func(_ context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		called = true
		return connect.NewResponse(&validationInterceptorFixture{}), nil
	}

	_, err := interceptor.WrapUnary(next)(context.Background(), connect.NewRequest(&validationInterceptorFixture{ID: "not-a-ulid"}))

	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	assert.False(t, called, "invalid boundary input must not reach the RPC handler")
}

// TestValidationInterceptor_RejectsRealProtoRequestWithMalformedField drives a
// REAL generated pm.*Request (not the synthetic fixture) through the
// interceptor, so it regresses if the generated `validate` tags are ever
// stripped — something the synthetic-struct test cannot catch. GetUserRequest.Id
// carries `validate:"required,ulid"`; the malformed value is sourced from intent
// (ids are ULIDs), not from the tag under test.
func TestValidationInterceptor_RejectsRealProtoRequestWithMalformedField(t *testing.T) {
	cases := []struct {
		name      string
		id        string
		wantCalls bool
	}{
		{"valid ULID reaches the handler", "01ARZ3NDEKTSV4RRFFQ69G5FAV", true},
		{"absent id is rejected", "", false},
		{"present-but-malformed id is rejected", "not-a-ulid", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			interceptor := NewValidationInterceptor()
			called := false
			next := func(_ context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
				called = true
				return connect.NewResponse(&pm.GetUserResponse{}), nil
			}

			_, err := interceptor.WrapUnary(next)(context.Background(),
				connect.NewRequest(&pm.GetUserRequest{Id: tc.id}))

			if tc.wantCalls {
				require.NoError(t, err)
				assert.True(t, called, "a valid real proto request must reach the handler")
				return
			}
			require.Error(t, err)
			assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
			assert.False(t, called, "an invalid real proto request must not reach the handler")
		})
	}
}

func TestValidationInterceptor_AllowsValidUnaryRequest(t *testing.T) {
	interceptor := NewValidationInterceptor()
	called := false

	next := func(_ context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		called = true
		return connect.NewResponse(&validationInterceptorFixture{}), nil
	}

	_, err := interceptor.WrapUnary(next)(context.Background(), connect.NewRequest(&validationInterceptorFixture{ID: "01ARZ3NDEKTSV4RRFFQ69G5FAV"}))

	require.NoError(t, err)
	assert.True(t, called)
}
