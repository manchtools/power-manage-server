package api_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/gen/go/pm/v1/pmv1connect"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/middleware"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

type controlRPCFixture struct {
	client      pmv1connect.ControlServiceClient
	server      *httptest.Server
	jwtManager  *auth.JWTManager
	accessToken string
	store       *store.Store
}

func newControlRPCFixture(t *testing.T) *controlRPCFixture {
	t.Helper()

	st := testutil.SetupPostgres(t)
	jwtManager := testutil.NewJWTManager()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := api.NewControlService(
		st,
		jwtManager,
		api.NoOpSigner{},
		nil,
		"https://gateway.test",
		logger,
		testutil.NewEncryptor(t),
		api.ControlServiceConfig{
			PasswordAuthEnabled: true,
			SSOCallbackBaseURL:  "https://app.example.com",
			SCIMBaseURL:         "https://control.example.com/scim/v2",
		},
	)

	path, h := pmv1connect.NewControlServiceHandler(
		svc,
		connect.WithInterceptors(
			api.NewLoggingInterceptor(logger),
			auth.NewAuthInterceptor(logger, jwtManager, auth.RateLimiters{}),
			api.NewValidationInterceptor(),
			auth.NewAuthzInterceptor(),
		),
	)
	mux := http.NewServeMux()
	mux.Handle(path, h)
	srv := httptest.NewServer(middleware.RequestID(mux))
	t.Cleanup(srv.Close)

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	tokens, err := jwtManager.GenerateTokens(userID, "admin@example.com", auth.AdminPermissions(), nil, 0)
	require.NoError(t, err)

	return &controlRPCFixture{
		client:      pmv1connect.NewControlServiceClient(srv.Client(), srv.URL),
		server:      srv,
		jwtManager:  jwtManager,
		accessToken: tokens.AccessToken,
		store:       st,
	}
}

func TestControlRPCBoundaryValidationRejectsInvalidRequestBeforeHandler(t *testing.T) {
	f := newControlRPCFixture(t)

	req := connect.NewRequest(&pm.ListDevicesRequest{PageSize: 201})
	req.Header().Set("Authorization", "Bearer "+f.accessToken)
	_, err := f.client.ListDevices(context.Background(), req)

	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	assert.NotEmpty(t, errorDetailRequestID(t, err), "boundary validation errors must carry request correlation IDs")
}

func TestControlRPCBoundaryAuthzStillRunsAfterValidation(t *testing.T) {
	f := newControlRPCFixture(t)
	limited, err := f.jwtManager.GenerateTokens("user-no-device-list", "limited@example.com", []string{"GetCurrentUser"}, nil, 0)
	require.NoError(t, err)

	req := connect.NewRequest(&pm.ListDevicesRequest{PageSize: 1})
	req.Header().Set("Authorization", "Bearer "+limited.AccessToken)
	_, err = f.client.ListDevices(context.Background(), req)

	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	assert.NotEmpty(t, errorDetailRequestID(t, err), "authz errors must carry request correlation IDs")
}

// TestRegister_FieldBounds_OverlongRejectedByValidation pins the pre-auth field
// bounds for the public Register RPC: an over-bound Token / Hostname /
// AgentVersion is rejected by the validation interceptor with
// CodeInvalidArgument BEFORE the handler does its token lookup. (The ABSENT/zero
// case is covered by the self-discovering sweep above.) Lengths are sourced from
// the documented caps (255 / 253 / 32), one character over each — not from the
// validate tag.
func TestRegister_FieldBounds_OverlongRejectedByValidation(t *testing.T) {
	f := newControlRPCFixture(t)
	valid := func() *pm.RegisterRequest {
		return &pm.RegisterRequest{Token: "tok", Hostname: "host", AgentVersion: "1.0.0", Csr: []byte("csr")}
	}
	cases := []struct {
		name string
		mut  func(*pm.RegisterRequest)
	}{
		{"token over 255", func(r *pm.RegisterRequest) { r.Token = strings.Repeat("a", 256) }},
		{"hostname over 253", func(r *pm.RegisterRequest) { r.Hostname = strings.Repeat("a", 254) }},
		{"agent_version over 32", func(r *pm.RegisterRequest) { r.AgentVersion = strings.Repeat("a", 33) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := valid()
			tc.mut(req)
			// Register is public — no bearer needed; validation runs before the
			// token lookup regardless.
			_, err := f.client.Register(context.Background(), connect.NewRequest(req))
			require.Error(t, err)
			assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err),
				"an overlong %s must be rejected by validation before the token lookup", tc.name)
		})
	}
}

func errorDetailRequestID(t *testing.T, err error) string {
	t.Helper()
	var connectErr *connect.Error
	require.True(t, errors.As(err, &connectErr))
	require.NotEmpty(t, connectErr.Details())
	value, detailErr := connectErr.Details()[0].Value()
	require.NoError(t, detailErr)
	detail, ok := value.(*pm.ErrorDetail)
	require.True(t, ok)
	return detail.RequestId
}
