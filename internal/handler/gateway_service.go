package handler

import (
	"context"
	"log/slog"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/gen/go/pm/v1/pmv1connect"
	"github.com/manchtools/power-manage/server/internal/connection"
)

// GatewayServiceHandler implements the control → gateway RPCs for
// terminal session admin (list/terminate). It runs on the gateway's
// internal mTLS listener so it's only callable by the control server.
type GatewayServiceHandler struct {
	pmv1connect.UnimplementedGatewayServiceHandler

	sessions *connection.TerminalSessionRegistry
	manager  *connection.Manager
	logger   *slog.Logger
}

// NewGatewayServiceHandler constructs the handler.
func NewGatewayServiceHandler(
	sessions *connection.TerminalSessionRegistry,
	manager *connection.Manager,
	logger *slog.Logger,
) *GatewayServiceHandler {
	return &GatewayServiceHandler{
		sessions: sessions,
		manager:  manager,
		logger:   logger,
	}
}

// ListGatewayTerminalSessions returns a snapshot of the terminal
// sessions currently active on this gateway. The control server fans
// this out to every known gateway and merges the results with user/
// device metadata from its own database.
func (h *GatewayServiceHandler) ListGatewayTerminalSessions(
	ctx context.Context,
	req *connect.Request[pm.ListGatewayTerminalSessionsRequest],
) (*connect.Response[pm.ListGatewayTerminalSessionsResponse], error) {
	active := h.sessions.List()
	infos := make([]*pm.GatewayTerminalSessionInfo, 0, len(active))
	for _, s := range active {
		infos = append(infos, &pm.GatewayTerminalSessionInfo{
			SessionId:      s.SessionID,
			UserId:         s.UserID,
			DeviceId:       s.DeviceID,
			TtyUser:        s.TtyUser,
			StartedAt:      timestamppb.New(s.StartedAt),
			LastActivityAt: timestamppb.New(s.LastActivity()),
		})
	}
	return connect.NewResponse(&pm.ListGatewayTerminalSessionsResponse{
		Sessions: infos,
	}), nil
}

// TerminateGatewayTerminalSession kills a session on this gateway.
// The control server routes ControlService.TerminateTerminalSession
// to whichever gateway owns the session_id (looked up via the prior
// List call or via session affinity). Returns found=false (not an
// error) if the session isn't on this gateway.
func (h *GatewayServiceHandler) TerminateGatewayTerminalSession(
	ctx context.Context,
	req *connect.Request[pm.TerminateGatewayTerminalSessionRequest],
) (*connect.Response[pm.TerminateGatewayTerminalSessionResponse], error) {
	sess := h.sessions.Get(req.Msg.SessionId)
	if sess == nil {
		return connect.NewResponse(&pm.TerminateGatewayTerminalSessionResponse{
			Found: false,
		}), nil
	}

	h.logger.Info("admin terminating terminal session",
		"session_id", req.Msg.SessionId,
		"reason", req.Msg.Reason,
		"device_id", sess.DeviceID,
	)

	// Unregister closes the OutputCh, which unblocks the bridge's
	// agent→WS goroutine. The bridge's deferred cleanup then sends
	// TerminalStop to the agent.
	h.sessions.Unregister(req.Msg.SessionId)

	return connect.NewResponse(&pm.TerminateGatewayTerminalSessionResponse{
		Found: true,
	}), nil
}
