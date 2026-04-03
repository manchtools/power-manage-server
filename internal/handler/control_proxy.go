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
}

// NewControlProxy creates a new control proxy pointing at the given control server URL.
// The httpClient should be configured with mTLS when TLS is enabled.
func NewControlProxy(httpClient *http.Client, controlURL string) *ControlProxy {
	client := pmv1connect.NewInternalServiceClient(httpClient, controlURL)
	return &ControlProxy{client: client}
}

// VerifyDevice checks that a device exists and is not deleted on the control server.
func (p *ControlProxy) VerifyDevice(ctx context.Context, deviceID string) error {
	_, err := p.client.VerifyDevice(ctx, connect.NewRequest(&pm.VerifyDeviceRequest{
		DeviceId: deviceID,
	}))
	return err
}

// SyncActions resolves all assigned actions for a device via the control server.
func (p *ControlProxy) SyncActions(ctx context.Context, deviceID string) (*pm.SyncActionsResponse, error) {
	resp, err := p.client.ProxySyncActions(ctx, connect.NewRequest(&pm.InternalSyncActionsRequest{
		DeviceId: deviceID,
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// ValidateLuksToken validates and consumes a one-time LUKS token via the control server.
func (p *ControlProxy) ValidateLuksToken(ctx context.Context, deviceID, token string) (*pm.ValidateLuksTokenResponse, error) {
	resp, err := p.client.ProxyValidateLuksToken(ctx, connect.NewRequest(&pm.InternalValidateLuksTokenRequest{
		DeviceId: deviceID,
		Token:    token,
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// GetLuksKey retrieves and decrypts the current LUKS key via the control server.
func (p *ControlProxy) GetLuksKey(ctx context.Context, deviceID, actionID string) (*pm.GetLuksKeyResponse, error) {
	resp, err := p.client.ProxyGetLuksKey(ctx, connect.NewRequest(&pm.InternalGetLuksKeyRequest{
		DeviceId: deviceID,
		ActionId: actionID,
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// StoreLuksKey encrypts and stores a new LUKS key via the control server.
func (p *ControlProxy) StoreLuksKey(ctx context.Context, deviceID, actionID, devicePath, passphrase, reason string) (*pm.StoreLuksKeyResponse, error) {
	resp, err := p.client.ProxyStoreLuksKey(ctx, connect.NewRequest(&pm.InternalStoreLuksKeyRequest{
		DeviceId:       deviceID,
		ActionId:       actionID,
		DevicePath:     devicePath,
		Passphrase:     passphrase,
		RotationReason: reason,
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// GetAutoUpdateInfo returns the latest agent release info for the given architecture.
func (p *ControlProxy) GetAutoUpdateInfo(ctx context.Context, agentArch string) (*pm.GetAutoUpdateInfoResponse, error) {
	resp, err := p.client.GetAutoUpdateInfo(ctx, connect.NewRequest(&pm.GetAutoUpdateInfoRequest{
		AgentArch: agentArch,
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
	}))
	return err
}
