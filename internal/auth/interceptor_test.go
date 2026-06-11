package auth

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"
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
