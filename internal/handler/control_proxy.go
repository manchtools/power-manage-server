package handler

import (
	"context"
	"net/http"

	"connectrpc.com/connect"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/gen/go/pm/v1/pmv1connect"
)

// ControlProxy wraps a Connect-RPC client for calling InternalService on the control server.
// This replaces direct database access for synchronous operations that need credential handling.
type ControlProxy struct {
	client pmv1connect.InternalServiceClient
	// gatewayID is this gateway's own identity, stamped onto every device-origin
	// request so control can confine the call to the device→gateway routing
	// binding (the gateway peer mTLS cert is shared and carries no per-gateway
	// identity, so the request must self-assert it). See server#403.
	gatewayID string
}

// NewControlProxy creates a new control proxy pointing at the given control server URL.
// The httpClient should be configured with mTLS when TLS is enabled. gatewayID is
// this gateway's identity, stamped onto device-origin requests for the
// device→gateway binding check on control.
func NewControlProxy(httpClient *http.Client, controlURL, gatewayID string) *ControlProxy {
	// Fail fast on an empty gatewayID: a gateway that stamps "" onto every
	// device-origin request has control reject ALL of them (the binding check
	// returns "gateway_id is required") — a total, silent outage. cmd/gateway
	// guarantees a non-empty id (config or a startup ULID), so this only fires
	// on a future wiring bug, and a loud crash beats a silently-dead gateway.
	if gatewayID == "" {
		panic("handler.NewControlProxy: gatewayID must not be empty")
	}
	client := pmv1connect.NewInternalServiceClient(httpClient, controlURL)
	return &ControlProxy{client: client, gatewayID: gatewayID}
}

// VerifyDevice checks that a device exists and is not deleted on the control server.
func (p *ControlProxy) VerifyDevice(ctx context.Context, deviceID string) error {
	_, err := p.client.VerifyDevice(ctx, connect.NewRequest(&pm.VerifyDeviceRequest{
		DeviceId:  deviceID,
		GatewayId: p.gatewayID,
	}))
	return err
}

// SyncActions resolves all assigned actions for a device via the control server.
func (p *ControlProxy) SyncActions(ctx context.Context, deviceID string) (*pm.SyncActionsResponse, error) {
	resp, err := p.client.ProxySyncActions(ctx, connect.NewRequest(&pm.InternalSyncActionsRequest{
		DeviceId:  deviceID,
		GatewayId: p.gatewayID,
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// ValidateLuksToken validates and consumes a one-time LUKS token via the control server.
func (p *ControlProxy) ValidateLuksToken(ctx context.Context, deviceID, token string) (*pm.ValidateLuksTokenResponse, error) {
	resp, err := p.client.ProxyValidateLuksToken(ctx, connect.NewRequest(&pm.InternalValidateLuksTokenRequest{
		DeviceId:  deviceID,
		Token:     token,
		GatewayId: p.gatewayID,
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// GetLuksKey retrieves and decrypts the current LUKS key via the control server.
func (p *ControlProxy) GetLuksKey(ctx context.Context, deviceID, actionID string) (*pm.GetLuksKeyResponse, error) {
	resp, err := p.client.ProxyGetLuksKey(ctx, connect.NewRequest(&pm.InternalGetLuksKeyRequest{
		DeviceId:  deviceID,
		ActionId:  actionID,
		GatewayId: p.gatewayID,
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// StoreLuksKey encrypts and stores a new LUKS key via the control server.
func (p *ControlProxy) StoreLuksKey(ctx context.Context, deviceID, actionID, devicePath, passphrase string, reason pm.RotationReason) (*pm.StoreLuksKeyResponse, error) {
	resp, err := p.client.ProxyStoreLuksKey(ctx, connect.NewRequest(&pm.InternalStoreLuksKeyRequest{
		DeviceId:       deviceID,
		ActionId:       actionID,
		DevicePath:     devicePath,
		Passphrase:     passphrase,
		RotationReason: reason,
		GatewayId:      p.gatewayID,
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// StoreLpsPasswords encrypts and stores LPS password rotation entries via the control server.
func (p *ControlProxy) StoreLpsPasswords(ctx context.Context, deviceID, actionID string, rotations []*pm.LpsPasswordRotation) error {
	_, err := p.client.ProxyStoreLpsPasswords(ctx, connect.NewRequest(&pm.InternalStoreLpsPasswordsRequest{
		DeviceId:  deviceID,
		ActionId:  actionID,
		Rotations: rotations,
		GatewayId: p.gatewayID,
	}))
	return err
}

// ValidateTerminalToken validates a session token presented by a web
// client opening the gateway's WebSocket terminal endpoint. Returns
// the session metadata (device_id, tty_user, cols, rows, user_id)
// the bridge needs to set up the session. Returns an error (typically
// connect.CodeUnauthenticated) if the token is invalid or expired.
func (p *ControlProxy) ValidateTerminalToken(ctx context.Context, sessionID, token string) (*pm.InternalValidateTerminalTokenResponse, error) {
	resp, err := p.client.ProxyValidateTerminalToken(ctx, connect.NewRequest(&pm.InternalValidateTerminalTokenRequest{
		SessionId: sessionID,
		Token:     token,
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}
