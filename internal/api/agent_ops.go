package api

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
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

	now func() time.Time // clock seam; defaults to time.Now, overridden in tests
}

// NewAgentOps constructs the agent-facing control logic.
func NewAgentOps(st *store.Store, enc *crypto.Encryptor, signer ca.ActionSigner, logger *slog.Logger) *AgentOps {
	return &AgentOps{store: st, encryptor: enc, signer: signer, logger: logger, now: time.Now}
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
		// Distinguish "no such device" from "the database did not answer".
		// Collapsing both into NotFound tells an operator their fleet was
		// deleted during an outage, and tells the agent to stop retrying
		// something that would succeed once the database is back.
		if !store.IsNotFound(err) {
			h.logger.Error("device lookup failed", "device_id", deviceID, "error", err)
			return apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "device lookup failed")
		}
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
		if !store.IsNotFound(err) {
			h.logger.Error("LUKS token lookup failed", "device_id", deviceID, "error", err)
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "token lookup failed")
		}
		// A token for another device is ALSO not-found here, deliberately: the
		// lookup is scoped by deviceID, so a leaked token is inert and reveals
		// nothing about whether it exists elsewhere.
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
		if !store.IsNotFound(err) {
			h.logger.Error("LUKS key lookup failed", "device_id", deviceID, "action_id", req.ActionId, "error", err)
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "key lookup failed")
		}
		// Another device's key is also not-found: the lookup is scoped by
		// deviceID, so this stays a uniform answer rather than an existence
		// oracle.
		return nil, apiErrorCtx(ctx, ErrLuksKeyNotFound, connect.CodeNotFound, "no LUKS key found for this action")
	}

	passphrase, err := h.encryptor.DecryptWithContext(key.Passphrase, crypto.SecretAAD(deviceID, req.ActionId, "luks"))
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to decrypt passphrase")
	}

	return &pm.GetLuksKeyResponse{Passphrase: passphrase}, nil
}

// StoreLuksKey encrypts and records a rotated LUKS passphrase.
//
// The agent sends the passphrase as plaintext over its authenticated stream.
// It used to seal it to a control public key first, because the blob crossed a
// gateway that was explicitly not trusted with it — the seal defended against a
// relay reading or relocating the bytes in flight. With the relay gone the
// stream's own mTLS is the confidentiality boundary, and the seal would be a
// second encryption of the same bytes over the same trusted hop.
//
// The AT-REST encryption is untouched: the same AES-GCM under the same
// device|action|"luks" AAD. Only the transport step is removed, so a stored
// ciphertext stays byte-compatible with one written before this change.
func (h *AgentOps) StoreLuksKey(ctx context.Context, deviceID string, req *pm.StoreLuksKeyRequest) (*pm.StoreLuksKeyResponse, error) {
	if err := Validate(ctx, req); err != nil {
		return nil, err
	}
	if deviceID == "" || req.ActionId == "" || req.Passphrase == "" {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument,
			"device_id, action_id and passphrase are required")
	}

	encPassphrase, err := h.encryptor.EncryptWithContext(req.Passphrase, crypto.SecretAAD(deviceID, req.ActionId, "luks"))
	if err != nil {
		h.logger.Error("failed to encrypt LUKS passphrase", "error", err, "device_id", deviceID)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to encrypt passphrase")
	}

	if err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "luks_key",
		StreamID:   ulid.Make().String(),
		EventType:  string(eventtypes.LuksKeyRotated),
		Data: payloads.LuksKeyRotated{
			DeviceID:       deviceID,
			ActionID:       req.ActionId,
			DevicePath:     req.DevicePath,
			Passphrase:     encPassphrase,
			RotatedAt:      h.now().UTC(),
			RotationReason: rotationReasonToString(req.RotationReason),
		},
		ActorType: "device",
		ActorID:   deviceID,
	}); err != nil {
		h.logger.Error("failed to store LUKS key event", "error", err, "device_id", deviceID)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to store LUKS key")
	}

	return &pm.StoreLuksKeyResponse{Success: true}, nil
}

// StoreLpsPasswords encrypts and records a batch of rotated local passwords.
//
// Two phases, and the split is load-bearing. Phase 1 encrypts and parses EVERY
// rotation before a single event is appended, so a bad entry cannot leave half
// a batch behind. Only once the whole batch is known persistable does phase 2
// append.
//
// Phase 2 must fail closed, and the reason is that LPS rotation is
// IRREVERSIBLE: the agent has already run chpasswd locally, so the old password
// is gone. If persistence silently fails, the only copy of the new one is lost
// and the user is locked out. Any append failure therefore returns an error,
// which leaves the agent's rotation metadata in place for a retry.
func (h *AgentOps) StoreLpsPasswords(ctx context.Context, deviceID string, req *pm.StoreLpsPasswordsRequest) (*pm.StoreLpsPasswordsResponse, error) {
	if err := Validate(ctx, req); err != nil {
		return nil, err
	}
	if deviceID == "" || req.ActionId == "" {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument,
			"device_id and action_id are required")
	}

	staged := make([]payloads.LpsPasswordRotated, 0, len(req.Rotations))
	for _, r := range req.Rotations {
		encPassword, err := h.encryptor.EncryptWithContext(r.Password, crypto.SecretAAD(deviceID, req.ActionId, "lps"))
		if err != nil {
			h.logger.Error("failed to encrypt LPS password", "error", err, "device_id", deviceID, "action_id", req.ActionId)
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to encrypt password")
		}

		// rotated_at rides the wire as an RFC 3339 string; parse it back so the
		// typed payload matches the projector's decoder. An unparseable stamp
		// falls back to now rather than failing the batch — the projector needs
		// a non-zero rotated_at, and losing the password over a malformed
		// timestamp would be the worse outcome.
		rotatedAt, err := time.Parse(time.RFC3339Nano, r.RotatedAt)
		if err != nil {
			if rotatedAt, err = time.Parse(time.RFC3339, r.RotatedAt); err != nil {
				h.logger.Warn("LpsPasswordRotation rotated_at unparseable; falling back to now",
					"raw", r.RotatedAt, "error", err)
				rotatedAt = h.now().UTC()
			}
		}

		staged = append(staged, payloads.LpsPasswordRotated{
			DeviceID:       deviceID,
			ActionID:       req.ActionId,
			Username:       r.Username,
			Password:       encPassword,
			RotatedAt:      rotatedAt,
			RotationReason: rotationReasonToString(r.Reason),
		})
	}

	var (
		persisted int
		firstErr  error
	)
	for _, payload := range staged {
		if err := h.store.AppendEvent(ctx, store.Event{
			StreamType: "lps_password",
			StreamID:   ulid.Make().String(),
			EventType:  string(eventtypes.LpsPasswordRotated),
			Data:       payload,
			ActorType:  "device",
			ActorID:    deviceID,
		}); err != nil {
			h.logger.Error("failed to append LpsPasswordRotated event",
				"device_id", deviceID, "action_id", req.ActionId,
				"persisted_before_failure", persisted, "total_rotations", len(staged), "error", err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		persisted++
	}
	if firstErr != nil {
		// Partial success is reported as failure on purpose: the agent retries
		// the whole list, and a re-appended rotation is harmless — the
		// projection dedupes by (device_id, username) and keeps the most
		// recent, while the event log honestly records that we saw it twice.
		h.logger.Error("LPS rotation persistence failed; returning error to trigger retry",
			"device_id", deviceID, "action_id", req.ActionId,
			"persisted", persisted, "total_rotations", len(staged), "first_error", firstErr)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal,
			fmt.Sprintf("failed to persist %d of %d LPS rotations", len(staged)-persisted, len(staged)))
	}

	return &pm.StoreLpsPasswordsResponse{}, nil
}
