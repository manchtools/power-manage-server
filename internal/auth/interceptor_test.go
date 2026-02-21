package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestAuthInterceptor_Creation(t *testing.T) {
	jwtMgr := NewJWTManager(JWTConfig{Secret: []byte("test")})
	loginLimiter := NewRateLimiter(10, time.Minute)
	refreshLimiter := NewRateLimiter(20, time.Minute)
	registerLimiter := NewRateLimiter(5, time.Minute)

	interceptor := NewAuthInterceptor(jwtMgr, loginLimiter, refreshLimiter, registerLimiter)
	assert.NotNil(t, interceptor)
	assert.NotNil(t, interceptor.jwtManager)
	assert.NotNil(t, interceptor.loginLimiter)
	assert.NotNil(t, interceptor.refreshLimiter)
	assert.NotNil(t, interceptor.registerLimiter)
}

func TestAuthInterceptor_NilLimiters(t *testing.T) {
	jwtMgr := NewJWTManager(JWTConfig{Secret: []byte("test")})
	interceptor := NewAuthInterceptor(jwtMgr, nil, nil, nil)
	assert.NotNil(t, interceptor)
}

func TestPublicProcedures(t *testing.T) {
	expected := map[string]bool{
		"/pm.v1.ControlService/Login":           true,
		"/pm.v1.ControlService/RefreshToken":    true,
		"/pm.v1.ControlService/Logout":          true,
		"/pm.v1.ControlService/Register":        true,
		"/pm.v1.ControlService/VerifyLoginTOTP": true,
	}
	assert.Equal(t, expected, PublicProcedures)
}

func TestPublicProcedures_NonPublic(t *testing.T) {
	assert.False(t, PublicProcedures["/pm.v1.ControlService/GetUser"])
	assert.False(t, PublicProcedures["/pm.v1.ControlService/CreateUser"])
	assert.False(t, PublicProcedures["/pm.v1.ControlService/ListDevices"])
}

func TestAuthzInterceptor_Creation(t *testing.T) {
	interceptor := NewAuthzInterceptor()
	assert.NotNil(t, interceptor)
}

func TestAuthInterceptor_StreamingPassthrough(t *testing.T) {
	jwtMgr := NewJWTManager(JWTConfig{Secret: []byte("test")})
	interceptor := NewAuthInterceptor(jwtMgr, nil, nil, nil)

	clientFunc := func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		return nil
	}
	wrappedClient := interceptor.WrapStreamingClient(clientFunc)
	assert.NotNil(t, wrappedClient)

	handlerFunc := func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		return nil
	}
	wrappedHandler := interceptor.WrapStreamingHandler(handlerFunc)
	assert.NotNil(t, wrappedHandler)
}

func TestAuthzInterceptor_StreamingPassthrough(t *testing.T) {
	interceptor := NewAuthzInterceptor()

	clientFunc := func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		return nil
	}
	wrappedClient := interceptor.WrapStreamingClient(clientFunc)
	assert.NotNil(t, wrappedClient)

	handlerFunc := func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		return nil
	}
	wrappedHandler := interceptor.WrapStreamingHandler(handlerFunc)
	assert.NotNil(t, wrappedHandler)
}

// setupInterceptorTest creates an httptest server with connect unary handlers
// that use the auth interceptor. Returns the server URL and JWTManager.
func setupInterceptorTest(t *testing.T) (string, *JWTManager) {
	t.Helper()

	jwtMgr := NewJWTManager(JWTConfig{
		Secret:            []byte("test-secret-for-interceptor-test"),
		AccessTokenExpiry: 15 * time.Minute,
	})
	interceptor := NewAuthInterceptor(jwtMgr, nil, nil, nil)

	mux := http.NewServeMux()

	// Protected handler — echoes user context via response header
	protectedProcedure := "/pm.v1.ControlService/GetUser"
	protectedHandler := connect.NewUnaryHandler(
		protectedProcedure,
		func(ctx context.Context, req *connect.Request[emptypb.Empty]) (*connect.Response[emptypb.Empty], error) {
			userCtx, ok := UserFromContext(ctx)
			if !ok {
				return nil, connect.NewError(connect.CodeInternal, nil)
			}
			resp := connect.NewResponse(&emptypb.Empty{})
			resp.Header().Set("X-User-ID", userCtx.ID)
			resp.Header().Set("X-User-Email", userCtx.Email)
			return resp, nil
		},
		connect.WithInterceptors(interceptor),
	)
	mux.Handle(protectedProcedure, protectedHandler)

	// Public handler (Login)
	loginProcedure := "/pm.v1.ControlService/Login"
	loginHandler := connect.NewUnaryHandler(
		loginProcedure,
		func(ctx context.Context, req *connect.Request[emptypb.Empty]) (*connect.Response[emptypb.Empty], error) {
			resp := connect.NewResponse(&emptypb.Empty{})
			resp.Header().Set("X-Public", "true")
			return resp, nil
		},
		connect.WithInterceptors(interceptor),
	)
	mux.Handle(loginProcedure, loginHandler)

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return server.URL, jwtMgr
}

// TestAuthInterceptor_BearerTokenAccepted verifies that a valid Bearer token
// passes authentication and injects user context.
func TestAuthInterceptor_BearerTokenAccepted(t *testing.T) {
	serverURL, jwtMgr := setupInterceptorTest(t)

	tokens, err := jwtMgr.GenerateTokens("user123", "test@example.com", []string{"GetUser"}, 1)
	require.NoError(t, err)

	client := connect.NewClient[emptypb.Empty, emptypb.Empty](
		http.DefaultClient, serverURL+"/pm.v1.ControlService/GetUser",
	)

	req := connect.NewRequest(&emptypb.Empty{})
	req.Header().Set("Authorization", "Bearer "+tokens.AccessToken)

	resp, err := client.CallUnary(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "user123", resp.Header().Get("X-User-ID"))
	assert.Equal(t, "test@example.com", resp.Header().Get("X-User-Email"))
}

// TestAuthInterceptor_MissingHeader verifies that requests without Authorization
// header are rejected.
func TestAuthInterceptor_MissingHeader(t *testing.T) {
	serverURL, _ := setupInterceptorTest(t)

	client := connect.NewClient[emptypb.Empty, emptypb.Empty](
		http.DefaultClient, serverURL+"/pm.v1.ControlService/GetUser",
	)

	req := connect.NewRequest(&emptypb.Empty{})

	_, err := client.CallUnary(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	assert.Contains(t, err.Error(), "missing authentication credentials")
}

// TestAuthInterceptor_InvalidToken verifies that an invalid JWT is rejected.
func TestAuthInterceptor_InvalidToken(t *testing.T) {
	serverURL, _ := setupInterceptorTest(t)

	client := connect.NewClient[emptypb.Empty, emptypb.Empty](
		http.DefaultClient, serverURL+"/pm.v1.ControlService/GetUser",
	)

	req := connect.NewRequest(&emptypb.Empty{})
	req.Header().Set("Authorization", "Bearer invalid-jwt-token")

	_, err := client.CallUnary(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	assert.Contains(t, err.Error(), "invalid or expired token")
}

// TestAuthInterceptor_CookieNoLongerAccepted verifies that cookie-based auth
// is no longer accepted — only Bearer header works.
func TestAuthInterceptor_CookieNoLongerAccepted(t *testing.T) {
	serverURL, jwtMgr := setupInterceptorTest(t)

	tokens, err := jwtMgr.GenerateTokens("user123", "test@example.com", []string{"GetUser"}, 1)
	require.NoError(t, err)

	client := connect.NewClient[emptypb.Empty, emptypb.Empty](
		http.DefaultClient, serverURL+"/pm.v1.ControlService/GetUser",
	)

	// Send token via Cookie header (old way) instead of Authorization header
	req := connect.NewRequest(&emptypb.Empty{})
	req.Header().Set("Cookie", "pm_access="+tokens.AccessToken)

	_, err = client.CallUnary(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	assert.Contains(t, err.Error(), "missing authentication credentials")
}

// TestAuthInterceptor_InvalidHeaderFormat verifies that non-Bearer auth schemes
// are rejected.
func TestAuthInterceptor_InvalidHeaderFormat(t *testing.T) {
	serverURL, _ := setupInterceptorTest(t)

	client := connect.NewClient[emptypb.Empty, emptypb.Empty](
		http.DefaultClient, serverURL+"/pm.v1.ControlService/GetUser",
	)

	tests := []struct {
		name   string
		header string
		errMsg string
	}{
		{"Basic auth", "Basic dXNlcjpwYXNz", "invalid authorization header format"},
		{"No scheme", "just-a-token", "invalid authorization header format"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := connect.NewRequest(&emptypb.Empty{})
			req.Header().Set("Authorization", tt.header)

			_, err := client.CallUnary(context.Background(), req)
			require.Error(t, err)
			assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

// TestAuthInterceptor_PublicProcedureSkipsAuth verifies public procedures bypass auth.
func TestAuthInterceptor_PublicProcedureSkipsAuth(t *testing.T) {
	serverURL, _ := setupInterceptorTest(t)

	client := connect.NewClient[emptypb.Empty, emptypb.Empty](
		http.DefaultClient, serverURL+"/pm.v1.ControlService/Login",
	)

	req := connect.NewRequest(&emptypb.Empty{})
	// No Authorization header — should still succeed for public procedure

	resp, err := client.CallUnary(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "true", resp.Header().Get("X-Public"))
}

// TestAuthInterceptor_ExpiredToken verifies that an expired token is rejected.
func TestAuthInterceptor_ExpiredToken(t *testing.T) {
	expiredMgr := NewJWTManager(JWTConfig{
		Secret:            []byte("test-secret-for-interceptor-test"),
		AccessTokenExpiry: -1 * time.Second, // Already expired
	})

	tokens, err := expiredMgr.GenerateTokens("user123", "test@example.com", []string{"GetUser"}, 1)
	require.NoError(t, err)

	serverURL, _ := setupInterceptorTest(t)

	client := connect.NewClient[emptypb.Empty, emptypb.Empty](
		http.DefaultClient, serverURL+"/pm.v1.ControlService/GetUser",
	)

	req := connect.NewRequest(&emptypb.Empty{})
	req.Header().Set("Authorization", "Bearer "+tokens.AccessToken)

	_, err = client.CallUnary(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

// TestAuthInterceptor_WrongSecret verifies that a token signed with a different
// secret is rejected.
func TestAuthInterceptor_WrongSecret(t *testing.T) {
	otherMgr := NewJWTManager(JWTConfig{
		Secret:            []byte("other-secret-key"),
		AccessTokenExpiry: 15 * time.Minute,
	})
	tokens, err := otherMgr.GenerateTokens("user123", "test@example.com", []string{"GetUser"}, 1)
	require.NoError(t, err)

	serverURL, _ := setupInterceptorTest(t)

	client := connect.NewClient[emptypb.Empty, emptypb.Empty](
		http.DefaultClient, serverURL+"/pm.v1.ControlService/GetUser",
	)

	req := connect.NewRequest(&emptypb.Empty{})
	req.Header().Set("Authorization", "Bearer "+tokens.AccessToken)

	_, err = client.CallUnary(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}
