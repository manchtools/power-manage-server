package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/gen/go/pm/v1/pmv1connect"
)

// readLimitSpyControl records whether the handler body ran, so the test can
// prove an over-cap request is rejected BEFORE the RPC method executes.
type readLimitSpyControl struct {
	pmv1connect.UnimplementedControlServiceHandler
	loginCalled bool
}

func (s *readLimitSpyControl) Login(context.Context, *connect.Request[pm.LoginRequest]) (*connect.Response[pm.LoginResponse], error) {
	s.loginCalled = true
	return connect.NewResponse(&pm.LoginResponse{}), nil
}

// TestControlServiceHandler_ReadMaxBytesEnforced pins WS13 #4: a request body
// over the configured cap is rejected with CodeResourceExhausted before the
// (unauthenticated) handler runs, so a pre-auth caller cannot force unbounded
// buffering. Uses a small per-test cap; the production wiring uses
// controlMaxRequestBytes.
func TestControlServiceHandler_ReadMaxBytesEnforced(t *testing.T) {
	const cap = 1024 // 1 KiB, small so the test body is cheap

	svc := &readLimitSpyControl{}
	path, h := pmv1connect.NewControlServiceHandler(svc, connect.WithReadMaxBytes(cap))
	mux := http.NewServeMux()
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client := pmv1connect.NewControlServiceClient(srv.Client(), srv.URL)

	// Over-cap: a Password far larger than the cap → rejected before Login runs.
	_, err := client.Login(context.Background(), connect.NewRequest(&pm.LoginRequest{
		Email:    "a@b.com",
		Password: strings.Repeat("x", cap*2),
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeResourceExhausted, connect.CodeOf(err),
		"an over-cap request body must be rejected with ResourceExhausted")
	assert.False(t, svc.loginCalled, "the handler must NOT run for an over-cap request (rejected pre-handler)")

	// Under-cap: reaches the handler normally.
	_, err = client.Login(context.Background(), connect.NewRequest(&pm.LoginRequest{
		Email:    "a@b.com",
		Password: "short",
	}))
	require.NoError(t, err)
	assert.True(t, svc.loginCalled, "an under-cap request must reach the handler")
}
