package handler

import (
	"context"
	"sync"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

// fakeAgentOps records what the stream handler asked control to do and lets a
// test flip any call to an error.
//
// It replaces a set of httptest servers that stood up a real InternalService so
// the handler could dial itself over HTTP. That indirection existed because the
// handler ran in a different process from the logic; it now calls in-process,
// so the double is a plain struct.
type fakeAgentOps struct {
	mu sync.Mutex

	verifyErr error
	verified  []string

	syncResp *pm.SyncActionsResponse
	syncErr  error
	synced   []string

	validateResp *pm.ValidateLuksTokenResponse
	validateErr  error
	lastValidate *pm.ValidateLuksTokenRequest
	validateDev  string

	getResp *pm.GetLuksKeyResponse
	getErr  error
	lastGet *pm.GetLuksKeyRequest
	getDev  string

	storeLuksResp *pm.StoreLuksKeyResponse
	storeLuksErr  error
	lastStoreLuks *pm.StoreLuksKeyRequest
	storeLuksDev  string

	storeLpsResp *pm.StoreLpsPasswordsResponse
	storeLpsErr  error
	lastStoreLps *pm.StoreLpsPasswordsRequest
	storeLpsDev  string
}

func (f *fakeAgentOps) VerifyDevice(_ context.Context, deviceID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verified = append(f.verified, deviceID)
	return f.verifyErr
}

func (f *fakeAgentOps) SyncActions(_ context.Context, deviceID string) (*pm.SyncActionsResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.synced = append(f.synced, deviceID)
	if f.syncErr != nil {
		return nil, f.syncErr
	}
	if f.syncResp != nil {
		return f.syncResp, nil
	}
	return &pm.SyncActionsResponse{}, nil
}

func (f *fakeAgentOps) ValidateLuksToken(_ context.Context, deviceID string, req *pm.ValidateLuksTokenRequest) (*pm.ValidateLuksTokenResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.validateDev, f.lastValidate = deviceID, req
	if f.validateErr != nil {
		return nil, f.validateErr
	}
	if f.validateResp != nil {
		return f.validateResp, nil
	}
	return &pm.ValidateLuksTokenResponse{}, nil
}

func (f *fakeAgentOps) GetLuksKey(_ context.Context, deviceID string, req *pm.GetLuksKeyRequest) (*pm.GetLuksKeyResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getDev, f.lastGet = deviceID, req
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.getResp != nil {
		return f.getResp, nil
	}
	return &pm.GetLuksKeyResponse{}, nil
}

func (f *fakeAgentOps) StoreLuksKey(_ context.Context, deviceID string, req *pm.StoreLuksKeyRequest) (*pm.StoreLuksKeyResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.storeLuksDev, f.lastStoreLuks = deviceID, req
	if f.storeLuksErr != nil {
		return nil, f.storeLuksErr
	}
	if f.storeLuksResp != nil {
		return f.storeLuksResp, nil
	}
	return &pm.StoreLuksKeyResponse{Success: true}, nil
}

func (f *fakeAgentOps) StoreLpsPasswords(_ context.Context, deviceID string, req *pm.StoreLpsPasswordsRequest) (*pm.StoreLpsPasswordsResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.storeLpsDev, f.lastStoreLps = deviceID, req
	if f.storeLpsErr != nil {
		return nil, f.storeLpsErr
	}
	if f.storeLpsResp != nil {
		return f.storeLpsResp, nil
	}
	return &pm.StoreLpsPasswordsResponse{}, nil
}

// syncedLast returns the device id of the most recent SyncActions call, or "".
func (f *fakeAgentOps) syncedLast() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.synced) == 0 {
		return ""
	}
	return f.synced[len(f.synced)-1]
}

// verifiedLast returns the device id of the most recent VerifyDevice call.
func (f *fakeAgentOps) verifiedLast() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.verified) == 0 {
		return ""
	}
	return f.verified[len(f.verified)-1]
}

// compile-time proof the double still satisfies the seam it stands in for.
var _ AgentOps = (*fakeAgentOps)(nil)
