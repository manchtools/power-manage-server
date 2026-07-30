package auth

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

var testLogger = slog.Default()

func TestAuthInterceptor_Creation(t *testing.T) {
	jwtMgr := NewJWTManager(JWTConfig{Secret: []byte("test")})
	limiters := RateLimiters{
		Login:     NewRateLimiter(10, time.Minute),
		Refresh:   NewRateLimiter(60, time.Minute),
		Register:  NewRateLimiter(5, time.Minute),
		Logout:    NewRateLimiter(30, time.Minute),
		RenewCert: NewRateLimiter(5, time.Minute),
	}

	interceptor := NewAuthInterceptor(testLogger, jwtMgr, limiters)
	assert.NotNil(t, interceptor)
	assert.NotNil(t, interceptor.jwtManager)
	assert.NotNil(t, interceptor.limiters.Login)
	assert.NotNil(t, interceptor.limiters.Refresh)
	assert.NotNil(t, interceptor.limiters.Register)
	assert.NotNil(t, interceptor.limiters.Logout)
	assert.NotNil(t, interceptor.limiters.RenewCert)
}

func TestAuthInterceptor_NilLimiters(t *testing.T) {
	jwtMgr := NewJWTManager(JWTConfig{Secret: []byte("test")})
	interceptor := NewAuthInterceptor(testLogger, jwtMgr, RateLimiters{})
	assert.NotNil(t, interceptor)
}

func TestPublicProcedures(t *testing.T) {
	expected := map[string]bool{
		"/pm.v1.ControlService/Login":            true,
		"/pm.v1.ControlService/RefreshToken":     true,
		"/pm.v1.ControlService/Logout":           true,
		"/pm.v1.ControlService/Register":         true,
		"/pm.v1.ControlService/RenewCertificate": true,
		"/pm.v1.ControlService/VerifyLoginTOTP":  true,
		"/pm.v1.ControlService/ListAuthMethods":  true,
		"/pm.v1.ControlService/GetSSOLoginURL":   true,
		"/pm.v1.ControlService/SSOCallback":      true,
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
	interceptor := NewAuthInterceptor(testLogger, jwtMgr, RateLimiters{})

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
	interceptor := NewAuthInterceptor(testLogger, jwtMgr, RateLimiters{})

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

	tokens, err := jwtMgr.GenerateTokens("user123", "test@example.com", []string{"GetUser"}, nil, 1)
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

// TestAuthInterceptor_InvalidToken verifies that a malformed JWT is
// rejected with the "invalid token" message — distinct from the
// "token expired" wording covered by TestAuthInterceptor_ExpiredToken.
// The split (#139) lets the web client choose refresh-and-retry vs
// forced-relogin instead of reflexively retrying on every 401.
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
	assert.Contains(t, err.Error(), "invalid token")
	assert.NotContains(t, err.Error(), "expired",
		"malformed-token failures must not surface as 'expired' — keeps the web error-mapping branches disjoint")
}

// TestAuthInterceptor_CookieNoLongerAccepted verifies that cookie-based auth
// is no longer accepted — only Bearer header works.
func TestAuthInterceptor_CookieNoLongerAccepted(t *testing.T) {
	serverURL, jwtMgr := setupInterceptorTest(t)

	tokens, err := jwtMgr.GenerateTokens("user123", "test@example.com", []string{"GetUser"}, nil, 1)
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

	tokens, err := expiredMgr.GenerateTokens("user123", "test@example.com", []string{"GetUser"}, nil, 1)
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
	// #139: expired tokens specifically must surface the "token
	// expired" wording so the web client can pick refresh-and-retry.
	// Malformed-token failures use "invalid token" instead — see
	// TestAuthInterceptor_InvalidToken.
	assert.Contains(t, err.Error(), "token expired")
}

// TestAuthInterceptor_WrongSecret verifies that a token signed with a different
// secret is rejected.
func TestAuthInterceptor_WrongSecret(t *testing.T) {
	otherMgr := NewJWTManager(JWTConfig{
		Secret:            []byte("other-secret-key"),
		AccessTokenExpiry: 15 * time.Minute,
	})
	tokens, err := otherMgr.GenerateTokens("user123", "test@example.com", []string{"GetUser"}, nil, 1)
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
	// #139: signature-invalid is a hard "invalid", not an expiry —
	// the web client must NOT treat this as a refreshable failure.
	assert.Contains(t, err.Error(), "invalid token")
	assert.NotContains(t, err.Error(), "expired")
}

// setupRateLimitedInterceptorTest stands up an httptest server that
// mounts a single connect handler under the named procedure with the
// AuthInterceptor's rate limiters fully configured. Returns the URL.
func setupRateLimitedInterceptorTest(t *testing.T, procedure string, limiters RateLimiters) string {
	t.Helper()
	jwtMgr := NewJWTManager(JWTConfig{
		Secret:            []byte("test-secret-for-ratelimit-test"),
		AccessTokenExpiry: 15 * time.Minute,
	})
	interceptor := NewAuthInterceptor(testLogger, jwtMgr, limiters)

	mux := http.NewServeMux()
	mux.Handle(procedure, connect.NewUnaryHandler(
		procedure,
		func(_ context.Context, _ *connect.Request[emptypb.Empty]) (*connect.Response[emptypb.Empty], error) {
			return connect.NewResponse(&emptypb.Empty{}), nil
		},
		connect.WithInterceptors(interceptor),
	))
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server.URL
}

// TestAuthInterceptor_LogoutRateLimit pins the #142 fix: Logout was
// listed in PublicProcedures but had no rate limiter. An attacker who
// learned a session token (XSS, log leak, shared browser) could
// invalidate that user's sessions arbitrarily often. The new Logout
// limiter caps the call rate per IP.
func TestAuthInterceptor_LogoutRateLimit(t *testing.T) {
	procedure := "/pm.v1.ControlService/Logout"
	url := setupRateLimitedInterceptorTest(t, procedure, RateLimiters{
		Logout: NewRateLimiter(2, time.Minute),
	})
	client := connect.NewClient[emptypb.Empty, emptypb.Empty](http.DefaultClient, url+procedure)

	for i := 0; i < 2; i++ {
		_, err := client.CallUnary(context.Background(), connect.NewRequest(&emptypb.Empty{}))
		require.NoError(t, err, "call %d should succeed within the 2/min budget", i+1)
	}
	_, err := client.CallUnary(context.Background(), connect.NewRequest(&emptypb.Empty{}))
	require.Error(t, err, "call 3 MUST be rate-limited — Logout was previously unrate-limited (issue #142)")
	assert.Equal(t, connect.CodeResourceExhausted, connect.CodeOf(err))
	assert.Contains(t, err.Error(), "too many logout attempts")
}

// TestAuthInterceptor_ExpensiveProcedureRateLimit pins WS13-9: the per-user
// "Expensive" limiter actually gates the heavy procedures (Evaluate*/Search*/
// *Query). No test previously configured Expensive, so a regression dropping the
// check — or isExpensiveProcedure no longer matching EvaluateDynamicGroup —
// would go unnoticed. An authenticated caller's SECOND expensive call within a
// 1/min budget is rejected with ResourceExhausted, before the handler runs.
func TestAuthInterceptor_ExpensiveProcedureRateLimit(t *testing.T) {
	jwtMgr := NewJWTManager(JWTConfig{
		Secret:            []byte("test-secret-for-expensive-limiter"),
		AccessTokenExpiry: 15 * time.Minute,
	})
	interceptor := NewAuthInterceptor(testLogger, jwtMgr, RateLimiters{
		Expensive: NewRateLimiter(1, time.Minute),
	})

	const procedure = "/pm.v1.ControlService/EvaluateDynamicGroup"
	var handlerCalls atomic.Int32
	mux := http.NewServeMux()
	mux.Handle(procedure, connect.NewUnaryHandler(
		procedure,
		func(_ context.Context, _ *connect.Request[emptypb.Empty]) (*connect.Response[emptypb.Empty], error) {
			handlerCalls.Add(1)
			return connect.NewResponse(&emptypb.Empty{}), nil
		},
		connect.WithInterceptors(interceptor),
	))
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	tokens, err := jwtMgr.GenerateTokens("uid-expensive", "e@x.com", []string{"GetUser"}, nil, 1)
	require.NoError(t, err)

	client := connect.NewClient[emptypb.Empty, emptypb.Empty](http.DefaultClient, server.URL+procedure)
	call := func() error {
		req := connect.NewRequest(&emptypb.Empty{})
		req.Header().Set("Authorization", "Bearer "+tokens.AccessToken)
		_, callErr := client.CallUnary(context.Background(), req)
		return callErr
	}

	require.NoError(t, call(), "the first expensive call is within the 1/min budget")
	err = call()
	require.Error(t, err, "the second expensive call must be rejected by the Expensive limiter")
	assert.Equal(t, connect.CodeResourceExhausted, connect.CodeOf(err))
	assert.Contains(t, err.Error(), "expensive")
	assert.EqualValues(t, 1, handlerCalls.Load(), "the rejected call must not reach the handler")
}

// TestAuthInterceptor_RenewCertificateRateLimit pins the #142 fix for
// the second Public-but-unrate-limited procedure. Each RenewCertificate
// call exercises the CA signing path; concurrent floods could exhaust
// signer throughput.
func TestAuthInterceptor_RenewCertificateRateLimit(t *testing.T) {
	procedure := "/pm.v1.ControlService/RenewCertificate"
	url := setupRateLimitedInterceptorTest(t, procedure, RateLimiters{
		RenewCert: NewRateLimiter(1, time.Minute),
	})
	client := connect.NewClient[emptypb.Empty, emptypb.Empty](http.DefaultClient, url+procedure)

	_, err := client.CallUnary(context.Background(), connect.NewRequest(&emptypb.Empty{}))
	require.NoError(t, err)

	_, err = client.CallUnary(context.Background(), connect.NewRequest(&emptypb.Empty{}))
	require.Error(t, err, "RenewCertificate MUST be rate-limited — was previously unrate-limited (issue #142)")
	assert.Equal(t, connect.CodeResourceExhausted, connect.CodeOf(err))
	assert.Contains(t, err.Error(), "too many certificate renewal attempts")
}

// TestAuthInterceptor_LogoutWithoutLimiter_PassesThrough verifies the
// nil-limiter contract: when RateLimiters.Logout is nil, the gate is
// a no-op and the call falls through. Mirrors the long-standing
// behaviour for the other limiters.
func TestAuthInterceptor_LogoutWithoutLimiter_PassesThrough(t *testing.T) {
	procedure := "/pm.v1.ControlService/Logout"
	url := setupRateLimitedInterceptorTest(t, procedure, RateLimiters{})
	client := connect.NewClient[emptypb.Empty, emptypb.Empty](http.DefaultClient, url+procedure)

	for i := 0; i < 5; i++ {
		_, err := client.CallUnary(context.Background(), connect.NewRequest(&emptypb.Empty{}))
		require.NoError(t, err, "with no Logout limiter configured, every call must pass through")
	}
}

// =============================================================================
// AuthzInterceptor — ProcedureAlternatives path (server #7 T-S2).
//
// Drive both interceptors (auth + authz) against a real procedure
// that's in the alternatives map. Tests prove the interceptor accepts
// ANY alternative, rejects when none are held, and does NOT fall
// through to the default Authorize path for a procedure in the map.
// =============================================================================

// setupAlternativesInterceptorTest wires AuthInterceptor +
// AuthzInterceptor against the CreateDeviceGroup procedure, which
// is in the ProcedureAlternatives map. Returns the server URL +
// JWT manager so each test mints its own token with custom perms.
func setupAlternativesInterceptorTest(t *testing.T) (string, *JWTManager) {
	t.Helper()

	jwtMgr := NewJWTManager(JWTConfig{
		Secret:            []byte("test-secret-alternatives"),
		AccessTokenExpiry: 15 * time.Minute,
	})
	authIc := NewAuthInterceptor(testLogger, jwtMgr, RateLimiters{})
	authzIc := NewAuthzInterceptor()

	mux := http.NewServeMux()
	procedure := "/pm.v1.ControlService/CreateDeviceGroup"
	handler := connect.NewUnaryHandler(
		procedure,
		func(ctx context.Context, req *connect.Request[emptypb.Empty]) (*connect.Response[emptypb.Empty], error) {
			return connect.NewResponse(&emptypb.Empty{}), nil
		},
		connect.WithInterceptors(authIc, authzIc),
	)
	mux.Handle(procedure, handler)

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return server.URL, jwtMgr
}

func TestAuthzInterceptor_AlternativesPath_StaticAltOnly_Accepts(t *testing.T) {
	serverURL, jwtMgr := setupAlternativesInterceptorTest(t)
	tokens, err := jwtMgr.GenerateTokens("u1", "alice@test", []string{"CreateStaticDeviceGroup"}, nil, 1)
	require.NoError(t, err)

	client := connect.NewClient[emptypb.Empty, emptypb.Empty](
		http.DefaultClient, serverURL+"/pm.v1.ControlService/CreateDeviceGroup",
	)
	req := connect.NewRequest(&emptypb.Empty{})
	req.Header().Set("Authorization", "Bearer "+tokens.AccessToken)

	_, err = client.CallUnary(context.Background(), req)
	require.NoError(t, err,
		"holding ONE of the alternatives is sufficient to pass the interceptor — handler narrows on request shape")
}

func TestAuthzInterceptor_AlternativesPath_DynamicAltOnly_Accepts(t *testing.T) {
	serverURL, jwtMgr := setupAlternativesInterceptorTest(t)
	tokens, err := jwtMgr.GenerateTokens("u1", "alice@test", []string{"CreateDynamicDeviceGroup"}, nil, 1)
	require.NoError(t, err)

	client := connect.NewClient[emptypb.Empty, emptypb.Empty](
		http.DefaultClient, serverURL+"/pm.v1.ControlService/CreateDeviceGroup",
	)
	req := connect.NewRequest(&emptypb.Empty{})
	req.Header().Set("Authorization", "Bearer "+tokens.AccessToken)

	_, err = client.CallUnary(context.Background(), req)
	require.NoError(t, err,
		"the OTHER alternative is also sufficient — symmetry")
}

func TestAuthzInterceptor_AlternativesPath_NeitherAltHeld_Denied(t *testing.T) {
	// Threat lens: even a user with a HUGE permission set that
	// happens to omit BOTH split alternatives must be rejected. A
	// future regression where the interceptor accidentally falls
	// through to the default Authorize path would let through any
	// permission whose base equals "CreateDeviceGroup" — but no
	// such permission is registered post-#7. Belt-and-suspenders
	// with the registry tests.
	serverURL, jwtMgr := setupAlternativesInterceptorTest(t)
	tokens, err := jwtMgr.GenerateTokens("u1", "alice@test", []string{
		// A grab-bag of unrelated perms — none satisfy the split.
		"GetUser", "ListUsers", "GetDevice", "ListDevices",
		"CreateAction", "RebuildSearchIndex",
	}, nil, 1)
	require.NoError(t, err)

	client := connect.NewClient[emptypb.Empty, emptypb.Empty](
		http.DefaultClient, serverURL+"/pm.v1.ControlService/CreateDeviceGroup",
	)
	req := connect.NewRequest(&emptypb.Empty{})
	req.Header().Set("Authorization", "Bearer "+tokens.AccessToken)

	_, err = client.CallUnary(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	assert.Contains(t, err.Error(), "permission denied")
}

// TestAuthzInterceptor_AlternativesPath_LegacyKeyAlone_Denied pins
// that holding the LEGACY base-key (e.g. "CreateDeviceGroup")
// without any of the split alternatives does NOT satisfy a procedure
// in the alternatives map. Forged-token threat: even if an attacker
// somehow forged a JWT with the legacy claim, the interceptor's
// alternatives-only gate refuses to fall through. Pins the
// "alternatives are exclusive" contract for this procedure.
func TestAuthzInterceptor_AlternativesPath_LegacyKeyAlone_Denied(t *testing.T) {
	serverURL, jwtMgr := setupAlternativesInterceptorTest(t)
	// Mint a token claiming the legacy "CreateDeviceGroup" perm —
	// not registered post-#7, but a forged or stale token might
	// carry it.
	tokens, err := jwtMgr.GenerateTokens("u1", "alice@test", []string{"CreateDeviceGroup"}, nil, 1)
	require.NoError(t, err)

	client := connect.NewClient[emptypb.Empty, emptypb.Empty](
		http.DefaultClient, serverURL+"/pm.v1.ControlService/CreateDeviceGroup",
	)
	req := connect.NewRequest(&emptypb.Empty{})
	req.Header().Set("Authorization", "Bearer "+tokens.AccessToken)

	_, err = client.CallUnary(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err),
		"legacy CreateDeviceGroup key alone (no alternatives held) must be rejected — alternatives are exclusive for procedures in the map")
}

func TestPermissionIsAlternative_KnownAlt(t *testing.T) {
	assert.True(t, PermissionIsAlternative("CreateStaticDeviceGroup"))
	assert.True(t, PermissionIsAlternative("CreateDynamicDeviceGroup"))
	assert.True(t, PermissionIsAlternative("CreateStaticUserGroup"))
	assert.True(t, PermissionIsAlternative("CreateDynamicUserGroup"))
	assert.True(t, PermissionIsAlternative("UpdateDynamicDeviceGroupQuery"))
	assert.True(t, PermissionIsAlternative("UpdateDynamicUserGroupQuery"))
}

func TestPermissionIsAlternative_UnknownAlt(t *testing.T) {
	// Negative case — a permission that is NOT in the alternatives
	// map must NOT pass this check. A regression that lets
	// PermissionIsAlternative return true for arbitrary keys would
	// silently widen the parity test exemptions.
	assert.False(t, PermissionIsAlternative("GetUser"))
	assert.False(t, PermissionIsAlternative("CreateAction"))
	assert.False(t, PermissionIsAlternative(""))
	assert.False(t, PermissionIsAlternative("CreateDeviceGroup"),
		"the legacy single-key permission MUST NOT register as an alternative — it was removed by #7")
}

// TestAuthInterceptor_ListAuthMethodsThrottled pins that the unauthenticated
// ListAuthMethods lookup is rate-limited by IP (audit user-enumeration fix):
// it reflects whether an email exists + its auth config, so an unthrottled
// caller could bulk-enumerate accounts. Drives the real interceptor over an
// httptest server so the per-IP throttle (clientIP from the peer) is exercised.
func TestAuthInterceptor_ListAuthMethodsThrottled(t *testing.T) {
	jwtMgr := NewJWTManager(JWTConfig{Secret: []byte("test-secret"), AccessTokenExpiry: 15 * time.Minute})
	interceptor := NewAuthInterceptor(testLogger, jwtMgr, RateLimiters{
		AuthMethods: NewRateLimiter(3, time.Minute),
	})

	procedure := "/pm.v1.ControlService/ListAuthMethods"
	mux := http.NewServeMux()
	mux.Handle(procedure, connect.NewUnaryHandler(
		procedure,
		func(ctx context.Context, req *connect.Request[emptypb.Empty]) (*connect.Response[emptypb.Empty], error) {
			return connect.NewResponse(&emptypb.Empty{}), nil
		},
		connect.WithInterceptors(interceptor),
	))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := connect.NewClient[emptypb.Empty, emptypb.Empty](http.DefaultClient, srv.URL+procedure)

	// The first 3 (the configured limit) succeed; the 4th from the same IP is throttled.
	for i := 0; i < 3; i++ {
		_, err := client.CallUnary(context.Background(), connect.NewRequest(&emptypb.Empty{}))
		require.NoError(t, err, "request %d within the limit should succeed", i+1)
	}
	_, err := client.CallUnary(context.Background(), connect.NewRequest(&emptypb.Empty{}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeResourceExhausted, connect.CodeOf(err))
	assert.Contains(t, err.Error(), "too many", "must trip the AuthMethods limiter, not some other gate")
}

// TestAuthInterceptor_GetSSOLoginURLThrottled pins spec 29 S3: the unauthenticated
// GetSSOLoginURL — the most expensive public endpoint (auth_state DB write +
// secret decrypt + outbound OIDC discovery per call) — is rate-limited by IP, so
// a flood can't exhaust storage or amplify outbound discovery.
func TestAuthInterceptor_GetSSOLoginURLThrottled(t *testing.T) {
	jwtMgr := NewJWTManager(JWTConfig{Secret: []byte("test-secret"), AccessTokenExpiry: 15 * time.Minute})
	interceptor := NewAuthInterceptor(testLogger, jwtMgr, RateLimiters{
		SSO: NewRateLimiter(3, time.Minute),
	})

	procedure := "/pm.v1.ControlService/GetSSOLoginURL"
	mux := http.NewServeMux()
	mux.Handle(procedure, connect.NewUnaryHandler(
		procedure,
		func(ctx context.Context, req *connect.Request[emptypb.Empty]) (*connect.Response[emptypb.Empty], error) {
			return connect.NewResponse(&emptypb.Empty{}), nil
		},
		connect.WithInterceptors(interceptor),
	))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := connect.NewClient[emptypb.Empty, emptypb.Empty](http.DefaultClient, srv.URL+procedure)

	for i := 0; i < 3; i++ {
		_, err := client.CallUnary(context.Background(), connect.NewRequest(&emptypb.Empty{}))
		require.NoError(t, err, "request %d within the limit should succeed", i+1)
	}
	_, err := client.CallUnary(context.Background(), connect.NewRequest(&emptypb.Empty{}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeResourceExhausted, connect.CodeOf(err))
	assert.Contains(t, err.Error(), "too many", "must trip the SSO limiter")
}

// setupAuthRateLimitTest mounts the EvaluateDynamicGroup (expensive) procedure
// behind the REAL AuthInterceptor with the supplied limiters, recording whether
// the handler ran via a per-request header. Returns the server URL + manager.
func setupAuthRateLimitTest(t *testing.T, limiters RateLimiters) (string, *JWTManager) {
	t.Helper()
	jwtMgr := NewJWTManager(JWTConfig{
		Secret:            []byte("test-secret-for-interceptor-test"),
		AccessTokenExpiry: 15 * time.Minute,
	})
	interceptor := NewAuthInterceptor(testLogger, jwtMgr, limiters)

	const procedure = "/pm.v1.ControlService/EvaluateDynamicGroup"
	mux := http.NewServeMux()
	mux.Handle(procedure, connect.NewUnaryHandler(
		procedure,
		func(_ context.Context, _ *connect.Request[emptypb.Empty]) (*connect.Response[emptypb.Empty], error) {
			resp := connect.NewResponse(&emptypb.Empty{})
			resp.Header().Set("X-Handler-Ran", "true")
			return resp, nil
		},
		connect.WithInterceptors(interceptor),
	))
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server.URL, jwtMgr
}

// TestAuthInterceptor_AuthenticatedRPCRateLimited pins WS11 finding 6: the
// per-user authenticated limiter gates ahead of the handler, and buckets are
// keyed per user (two users on the same connection do not share a budget).
func TestAuthInterceptor_AuthenticatedRPCRateLimited(t *testing.T) {
	const ceiling = 3
	serverURL, jwtMgr := setupAuthRateLimitTest(t, RateLimiters{
		Authenticated: NewRateLimiter(ceiling, time.Minute),
	})
	const procedure = "/pm.v1.ControlService/EvaluateDynamicGroup"
	client := connect.NewClient[emptypb.Empty, emptypb.Empty](http.DefaultClient, serverURL+procedure)

	call := func(t *testing.T, userID string) (*connect.Response[emptypb.Empty], error) {
		t.Helper()
		tokens, err := jwtMgr.GenerateTokens(userID, userID+"@x", []string{"EvaluateDynamicGroup"}, nil, 1)
		require.NoError(t, err)
		req := connect.NewRequest(&emptypb.Empty{})
		req.Header().Set("Authorization", "Bearer "+tokens.AccessToken)
		return client.CallUnary(context.Background(), req)
	}

	// First `ceiling` calls for user A reach the handler.
	for i := 0; i < ceiling; i++ {
		resp, err := call(t, "userA")
		require.NoError(t, err, "call %d within the ceiling must succeed", i+1)
		assert.Equal(t, "true", resp.Header().Get("X-Handler-Ran"))
	}

	// The next call from the SAME user is rejected BEFORE the handler runs.
	_, err := call(t, "userA")
	require.Error(t, err)
	assert.Equal(t, connect.CodeResourceExhausted, connect.CodeOf(err))
	assert.Contains(t, err.Error(), "too many")

	// A DIFFERENT user on the same connection has an independent bucket — the
	// limiter must not collapse per-user budgets onto one axis.
	resp, err := call(t, "userB")
	require.NoError(t, err, "a distinct user must have an independent per-user bucket")
	assert.Equal(t, "true", resp.Header().Get("X-Handler-Ran"))
}

// TestIsExpensiveProcedure_MatchesRealProcedures is the self-discovering guard
// for the expensive matcher: it walks the real ControlService descriptor and
// asserts the matcher recognises at least one actual procedure (so the patterns
// can never silently match zero), and that an ordinary read (GetUser) is NOT
// classified as expensive.
func TestIsExpensiveProcedure_MatchesRealProcedures(t *testing.T) {
	svc := pm.File_pm_v1_control_proto.Services().ByName("ControlService")
	require.NotNil(t, svc, "ControlService descriptor must resolve")

	matched := []string{}
	methods := svc.Methods()
	for i := 0; i < methods.Len(); i++ {
		name := string(methods.Get(i).Name())
		if isExpensiveProcedure(name) {
			matched = append(matched, name)
		}
	}
	require.NotEmpty(t, matched,
		"isExpensiveProcedure matched zero real ControlService procedures — the patterns drifted")
	assert.False(t, isExpensiveProcedure("GetUser"), "an ordinary read must not be classified expensive")
}

// TestClientIPFromHTTP_TrustAttribution pins the rate-limit spoof surface
// (finding 3): X-Forwarded-For / X-Real-IP are honoured ONLY when the direct
// peer is in the configured trusted-proxy set, and malformed config is dropped
// rather than widening trust. Every attacker-supplied header value is sourced
// from intent (an arbitrary spoofed address), never from the function's own
// output. TrustedProxies is a package global; the cleanup resets it.
func TestClientIPFromHTTP_TrustAttribution(t *testing.T) {
	t.Cleanup(func() { SetTrustedProxies(nil) })

	const spoofed = "203.0.113.66" // attacker-chosen XFF value

	cases := []struct {
		name       string
		trusted    []string
		remoteAddr string
		xff        string
		xri        string
		want       string
	}{
		{
			name:       "untrusted peer + spoofed XFF returns the peer, not the XFF",
			remoteAddr: "198.51.100.5:443",
			xff:        spoofed,
			want:       "198.51.100.5",
		},
		{
			// Right-to-left walk: the trailing trusted-proxy hop (10.9.9.9) is
			// skipped and the first untrusted address (the spoofed left entry) is
			// returned — here there is only one untrusted candidate.
			name:       "trusted /8 peer + XFF: trailing trusted hop skipped, untrusted returned",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.1.2.3:1234",
			xff:        spoofed + ", 10.9.9.9",
			want:       spoofed,
		},
		{
			// The distinguishing right-to-left case (AC6): attacker prepends a
			// spoofed left entry, then the real client, then a trusted proxy hop.
			// Leftmost-selection would return the spoof; right-to-left skips the
			// trusted tail hop and returns the real client.
			name:       "trusted peer + [spoof, client, trusted-proxy]: returns the client, not the spoof",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.1.2.3:1234",
			xff:        spoofed + ", 198.51.100.20, 10.9.9.9",
			want:       "198.51.100.20",
		},
		{
			// Multiple trusted proxies at the tail are all skipped.
			name:       "trusted peer + [client, proxy, proxy]: skips both trusted tail hops",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.1.2.3:1234",
			xff:        "198.51.100.20, 10.9.9.9, 10.8.8.8",
			want:       "198.51.100.20",
		},
		{
			// Every XFF hop is a trusted proxy: the real client is farther
			// upstream than any recorded address, so fall back to the direct peer
			// rather than invent one.
			name:       "trusted peer + all-trusted XFF chain falls back to the peer",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.1.2.3:1234",
			xff:        "10.9.9.9, 10.8.8.8",
			want:       "10.1.2.3",
		},
		{
			name:       "trusted peer + X-Real-IP (no XFF) returns X-Real-IP",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.1.2.3:1234",
			xri:        "192.0.2.7",
			want:       "192.0.2.7",
		},
		{
			// XFF is present but malformed: X-Real-IP is consulted ONLY when XFF is
			// absent, and a malformed hop stops the right-to-left walk — so this
			// falls back to the direct peer, never to X-Real-IP or a farther-left
			// (attacker-controllable) value.
			name:       "trusted peer + malformed XFF falls back to the peer, not X-Real-IP",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.1.2.3:1234",
			xff:        "not-an-ip",
			xri:        "192.0.2.7",
			want:       "10.1.2.3",
		},
		{
			// A malformed hop encountered before a trustworthy client is
			// established (AC7): the trailing trusted hop is skipped, then the
			// malformed middle hop aborts the walk to the direct peer instead of
			// trusting the farther-left spoof.
			name:       "trusted peer + malformed middle hop aborts to the peer (AC7)",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.1.2.3:1234",
			xff:        spoofed + ", garbage, 10.9.9.9",
			want:       "10.1.2.3",
		},
		{
			name:       "trusted peer + malformed XFF + no X-Real-IP falls through to the peer",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.1.2.3:1234",
			xff:        "not-an-ip",
			want:       "10.1.2.3",
		},
		{
			name:       "bare-IP trusted entry parsed as /32 (IPv4) trusts the exact peer",
			trusted:    []string{"172.16.0.9"},
			remoteAddr: "172.16.0.9:5555",
			xff:        spoofed,
			want:       spoofed,
		},
		{
			name:       "bare-IP /32 does not widen to a neighbouring address",
			trusted:    []string{"172.16.0.9"},
			remoteAddr: "172.16.0.10:5555", // one off — not trusted
			xff:        spoofed,
			want:       "172.16.0.10",
		},
		{
			name:       "bare-IP trusted entry parsed as /128 (IPv6) trusts the exact peer",
			trusted:    []string{"2001:db8::1"},
			remoteAddr: "[2001:db8::1]:5555",
			xff:        spoofed,
			want:       spoofed,
		},
		{
			name:       "malformed CIDR entries are skipped, not fatal, and do not widen trust",
			trusted:    []string{"10.0.0.0/999", "garbage"},
			remoteAddr: "10.1.2.3:1234",
			xff:        spoofed,
			want:       "10.1.2.3", // peer untrusted because the bad CIDRs were dropped
		},
		{
			name:       "RemoteAddr without a port parses to the bare IP",
			remoteAddr: "198.51.100.5",
			want:       "198.51.100.5",
		},
		{
			name:       "no parsable IP anywhere returns the empty string",
			remoteAddr: "",
			want:       "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			SetTrustedProxies(tc.trusted)
			r := &http.Request{RemoteAddr: tc.remoteAddr, Header: http.Header{}}
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if tc.xri != "" {
				r.Header.Set("X-Real-IP", tc.xri)
			}
			assert.Equal(t, tc.want, ClientIPFromHTTP(r))
		})
	}
}

// TestClientIP_ConnectPathResolution drives the Connect interceptor's clientIP
// (the rate-limit resolver) end-to-end through an httptest server, so the
// Connect path is covered independently of the shared resolveClientIP unit
// table (exercised via the HTTP path). The handler echoes clientIP(req) back in
// a header, so the assertion is on the resolved value directly — it would catch
// a drift where clientIP read the wrong header or the peer address instead of
// delegating to resolveClientIP. The loopback test peer is trusted so forwarded
// headers are honoured.
func TestClientIP_ConnectPathResolution(t *testing.T) {
	t.Cleanup(func() { SetTrustedProxies(nil) })
	// Trust the loopback test peer and any loopback tail hops in XFF.
	SetTrustedProxies([]string{"127.0.0.0/8", "::1/128"})

	jwtMgr := NewJWTManager(JWTConfig{Secret: []byte("test-secret"), AccessTokenExpiry: 15 * time.Minute})
	interceptor := NewAuthInterceptor(testLogger, jwtMgr, RateLimiters{})

	procedure := "/pm.v1.ControlService/Login" // public: no auth needed
	mux := http.NewServeMux()
	mux.Handle(procedure, connect.NewUnaryHandler(
		procedure,
		func(ctx context.Context, req *connect.Request[emptypb.Empty]) (*connect.Response[emptypb.Empty], error) {
			resp := connect.NewResponse(&emptypb.Empty{})
			resp.Header().Set("X-Resolved-IP", clientIP(req))
			return resp, nil
		},
		connect.WithInterceptors(interceptor),
	))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	client := connect.NewClient[emptypb.Empty, emptypb.Empty](http.DefaultClient, srv.URL+procedure)

	resolve := func(xff string) string {
		req := connect.NewRequest(&emptypb.Empty{})
		if xff != "" {
			req.Header().Set("X-Forwarded-For", xff)
		}
		resp, err := client.CallUnary(context.Background(), req)
		require.NoError(t, err)
		return resp.Header().Get("X-Resolved-IP")
	}

	// Right-to-left: skip the trusted loopback tail hop and return the real
	// client, NOT the spoofed leftmost entry (which first-hop selection would
	// return).
	assert.Equal(t, "203.0.113.10", resolve("9.9.9.9, 203.0.113.10, 127.0.0.1"))
	// A single untrusted hop is returned as-is.
	assert.Equal(t, "203.0.113.10", resolve("203.0.113.10"))
	// No XFF + trusted peer → the loopback peer itself (a valid IP, not "").
	peer := resolve("")
	assert.NotEmpty(t, peer)
	assert.NotNil(t, net.ParseIP(peer), "resolved peer must be a parsable IP, got %q", peer)
}
