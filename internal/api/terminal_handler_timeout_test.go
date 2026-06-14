package api_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/gen/go/pm/v1/pmv1connect"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/gateway/registry"
	"github.com/manchtools/power-manage/server/internal/terminal"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// deadlineRequiringGateway rejects any TerminateGatewayTerminalSession call
// whose context carries no deadline. Connect propagates a client-side deadline
// to the handler ctx (Connect-Timeout-Ms), so this fails fast and observably
// when the caller used the bare request context, and succeeds only when the
// call is bounded.
type deadlineRequiringGateway struct {
	pmv1connect.UnimplementedGatewayServiceHandler
}

func (deadlineRequiringGateway) TerminateGatewayTerminalSession(
	ctx context.Context, _ *connect.Request[pm.TerminateGatewayTerminalSessionRequest],
) (*connect.Response[pm.TerminateGatewayTerminalSessionResponse], error) {
	if _, ok := ctx.Deadline(); !ok {
		return nil, connect.NewError(connect.CodeInternal,
			errors.New("gateway terminate call arrived without a propagated deadline"))
	}
	return connect.NewResponse(&pm.TerminateGatewayTerminalSessionResponse{Found: true}), nil
}

// TestTerminateTerminalSession_UsesBoundedContext pins WS11 finding 8: the
// gateway terminate fan-out must run under a deadline, not the bare request
// context, so a stuck/slow gateway can't hang the admin RPC. The fake gateway
// rejects a deadline-less call, so this is RED until TerminateTerminalSession
// wraps the call in a timeout.
func TestTerminateTerminalSession_UsesBoundedContext(t *testing.T) {
	st := testutil.SetupPostgres(t)
	tokenStore := terminal.NewTokenStore(terminal.NewFakeBackend(nil))
	reg := registry.New(registry.NewFakeBackend(nil), slog.Default())
	h := api.NewTerminalHandler(st, tokenStore, reg, "", slog.Default())

	path, gwHandler := pmv1connect.NewGatewayServiceHandler(deadlineRequiringGateway{})
	mux := http.NewServeMux()
	mux.Handle(path, gwHandler)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	h.SetInternalHTTPClient(srv.Client())

	ctx := context.Background()
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	device := testutil.CreateTestDevice(t, st, "host-term")
	const gwID = "gw-term"
	require.NoError(t, reg.AttachDevice(ctx, device, gwID, registry.DefaultDeviceTTL))
	require.NoError(t, reg.RegisterGatewayInternal(ctx, gwID, srv.URL, registry.DefaultGatewayTTL))

	mint, err := tokenStore.MintWithID(ctx, testutil.NewID(), terminal.MintParams{
		UserID: userID, DeviceID: device, TtyUser: "pm-tty-alice", Cols: 80, Rows: 24,
	})
	require.NoError(t, err)

	adminCtx := testutil.AuthContext(userID, "u@test.com", []string{"TerminateTerminalSession"})
	done := make(chan error, 1)
	go func() {
		_, terr := h.TerminateTerminalSession(adminCtx, connect.NewRequest(&pm.TerminateTerminalSessionRequest{
			SessionId: mint.SessionID,
			Reason:    "admin terminate",
		}))
		done <- terr
	}()

	select {
	case terr := <-done:
		require.NoError(t, terr,
			"terminate must succeed; the fake gateway requires a propagated deadline (RED if the call used the bare request ctx)")
	case <-time.After(15 * time.Second):
		t.Fatal("TerminateTerminalSession did not return — the gateway call is not bounded")
	}
}
