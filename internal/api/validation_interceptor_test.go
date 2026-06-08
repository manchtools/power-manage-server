package api

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
