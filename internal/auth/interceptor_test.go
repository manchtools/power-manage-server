package auth

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
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
		"/pm.v1.ControlService/Login":        true,
		"/pm.v1.ControlService/RefreshToken": true,
		"/pm.v1.ControlService/Logout":       true,
		"/pm.v1.ControlService/Register":     true,
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
