package api

import (
	"context"
	"log/slog"

	"connectrpc.com/connect"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/store"
)

// AgentOps is the control-side logic behind the operations an agent invokes
// over its bidi stream: device verification, action sync, and the LUKS/LPS
// secret paths.
//
// These lived on InternalService, which existed for one reason — the gateway
// terminated the agent stream and had to reach back into control over mTLS to
// do anything privileged. Spec 41 deleted that tier, so the same logic is now
// called in-process by the stream handler. What disappears with the transport
// is only transport: the Connect request/response envelopes, the per-call mTLS
// dial, and the device→gateway binding check, which asked whether an
// intermediary was entitled to speak for a device. There is no intermediary.
//
// Two things deliberately do NOT disappear:
//
//   - VALIDATION. Every method still runs Validate on the agent's message
//     before touching the store. The proxy got this from its RPC boundary; an
//     in-process call has no boundary, so it is explicit here. These are the
//     credential-bearing paths, and validate-then-auth is the house rule.
//
//   - THE DEVICE IDENTITY ARGUMENT. deviceID is passed separately from the
//     request and must come from the caller's authenticated stream, never from
//     a field the agent controls. That is what stops one device asking for
//     another's LUKS key, and it replaces the binding check with something
//     stronger: the mTLS client certificate rather than a registry lookup.
type AgentOps struct {
	store     *store.Store
	encryptor *crypto.Encryptor
	logger    *slog.Logger

	// signer signs the SignedActionEnvelope for each action delivered by the
	// sync path, device-bound to the syncing device. A nil signer is a wiring
	// bug: sync fails closed rather than hand the agent an unsigned action it
	// would reject anyway.
	signer ca.ActionSigner
}

// NewAgentOps constructs the agent-facing control logic.
func NewAgentOps(st *store.Store, enc *crypto.Encryptor, signer ca.ActionSigner, logger *slog.Logger) *AgentOps {
	return &AgentOps{store: st, encryptor: enc, signer: signer, logger: logger}
}

// VerifyDevice admits a device's stream: it checks the device exists and is not
// deleted, and nothing else.
//
// It reads only existence, returns no secret, and appends no event, so there is
// nothing here to confine to a particular caller. The device's identity is
// already proven by its mTLS client certificate before this runs — the stream
// handler asserts the certificate's device ID equals the one in the hello.
func (h *AgentOps) VerifyDevice(ctx context.Context, deviceID string) error {
	if deviceID == "" {
		return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "device_id is required")
	}
	if _, err := h.store.Repos().Device.Get(ctx, store.GetDeviceKey{ID: deviceID}); err != nil {
		h.logger.Warn("device verification failed", "device_id", deviceID, "error", err)
		return apiErrorCtx(ctx, ErrDeviceNotFound, connect.CodeNotFound, "device not found or deleted")
	}
	return nil
}

// ValidateLuksToken redeems a one-time LUKS enrollment token for the device
// that presented it.
//
// deviceID scopes the redemption, so a token is only ever consumable by the
// device it was issued for — a token leaked to another device is inert.
func (h *AgentOps) ValidateLuksToken(ctx context.Context, deviceID string, req *pm.ValidateLuksTokenRequest) (*pm.ValidateLuksTokenResponse, error) {
	if err := Validate(ctx, req); err != nil {
		return nil, err
	}
	if deviceID == "" || req.Token == "" {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "device_id and token are required")
	}

	// WS10 #3: tokens are stored hashed — hash the presented plaintext before
	// lookup so the at-rest column never holds a usable token.
	token, err := h.store.Repos().Luks.ConsumeToken(ctx, store.ConsumeLuksTokenParams{
		Token:    hashLuksToken(req.Token),
		DeviceID: deviceID,
	})
	if err != nil {
		h.logger.Warn("LUKS token validation failed", "device_id", deviceID, "error", err)
		return nil, apiErrorCtx(ctx, ErrTokenNotFound, connect.CodeNotFound, "token is invalid or has expired")
	}

	devicePath := ""
	key, err := h.store.Repos().Luks.GetCurrentForAction(ctx, store.LuksKeyByActionKey{
		DeviceID: deviceID, ActionID: token.ActionID,
	})
	if err == nil {
		devicePath = key.DevicePath
	} else {
		logEnrichmentErr("GetCurrentLuksKeyForAction", "device_id", deviceID, err)
	}

	return &pm.ValidateLuksTokenResponse{
		ActionId:   token.ActionID,
		DevicePath: devicePath,
		MinLength:  token.MinLength,
		Complexity: pm.LpsPasswordComplexity(token.Complexity),
	}, nil
}

// GetLuksKey returns the decrypted LUKS passphrase for one device+action.
//
// The AAD binds the ciphertext to device, action, and secret type, so a row
// relocated to another device or action fails to decrypt rather than yielding
// the wrong device's passphrase. deviceID coming from the stream rather than
// the request is what makes that binding meaningful.
func (h *AgentOps) GetLuksKey(ctx context.Context, deviceID string, req *pm.GetLuksKeyRequest) (*pm.GetLuksKeyResponse, error) {
	if err := Validate(ctx, req); err != nil {
		return nil, err
	}
	if deviceID == "" || req.ActionId == "" {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "device_id and action_id are required")
	}

	key, err := h.store.Repos().Luks.GetCurrentForAction(ctx, store.LuksKeyByActionKey{
		DeviceID: deviceID, ActionID: req.ActionId,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrLuksKeyNotFound, connect.CodeNotFound, "no LUKS key found for this action")
	}

	passphrase, err := h.encryptor.DecryptWithContext(key.Passphrase, crypto.SecretAAD(deviceID, req.ActionId, "luks"))
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to decrypt passphrase")
	}

	return &pm.GetLuksKeyResponse{Passphrase: passphrase}, nil
}
