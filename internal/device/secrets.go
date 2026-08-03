package device

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/auth"
	pmcrypto "github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

const luksTokenTTL = 24 * time.Hour

// ListLpsPasswords returns bounded current and historical LPS metadata. Its
// store query does not select ciphertext.
func (h *Handlers) ListLpsPasswords(ctx context.Context, req *connect.Request[pmv1.ListLpsPasswordsRequest]) (*connect.Response[pmv1.ListLpsPasswordsResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := h.readDevice(ctx, "ListLpsPasswords", req.Msg.DeviceId); err != nil {
		return nil, err
	}
	currentRows, historyRows, err := h.store.ListDeviceLpsPasswords(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, h.internal(ctx, "read LPS passwords", err)
	}
	current, err := h.lpsPasswordsToProto(currentRows)
	if err != nil {
		return nil, h.internal(ctx, "decode current LPS passwords", err)
	}
	history, err := h.lpsPasswordsToProto(historyRows)
	if err != nil {
		return nil, h.internal(ctx, "decode historical LPS passwords", err)
	}
	if err := h.recordSensitiveRead(ctx, req, actor,
		powermanagev1connect.ControlServiceListLpsPasswordsProcedure,
		"ListLpsPasswords", "device_lps_passwords", req.Msg.DeviceId); err != nil {
		return nil, err
	}
	return connect.NewResponse(&pmv1.ListLpsPasswordsResponse{Current: current, History: history}), nil
}

// RevealLpsPassword returns one plaintext password only after the dedicated
// reveal operation and its device/action/entry effects are durable.
func (h *Handlers) RevealLpsPassword(ctx context.Context, req *connect.Request[pmv1.RevealLpsPasswordRequest]) (*connect.Response[pmv1.RevealLpsPasswordResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "RevealLpsPassword", ""); err != nil {
		return nil, err
	}
	secret, err := h.store.GetLpsPasswordForReveal(ctx, req.Msg.Id)
	if err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, errLpsPasswordNotFound, "LPS password not found")
		}
		return nil, h.internal(ctx, "read LPS password for reveal", err)
	}
	if _, err := h.readDevice(ctx, "RevealLpsPassword", secret.DeviceID); err != nil {
		return nil, err
	}
	password, err := h.openStoredSecret(secret.Password,
		pmcrypto.SecretAADForRow(secret.DeviceID, secret.ActionID, "lps", secret.Username))
	if err != nil {
		return nil, h.internal(ctx, "open LPS password", err)
	}
	if err := h.recordSecretReveal(ctx, req, actor,
		powermanagev1connect.ControlServiceRevealLpsPasswordProcedure,
		"RevealLpsPassword", "lps_password", secret.ID, secret.DeviceID, secret.ActionID); err != nil {
		return nil, err
	}
	return connect.NewResponse(&pmv1.RevealLpsPasswordResponse{Password: password}), nil
}

// ListLuksKeys returns bounded current and historical LUKS metadata. Its store
// query does not select ciphertext.
func (h *Handlers) ListLuksKeys(ctx context.Context, req *connect.Request[pmv1.ListLuksKeysRequest]) (*connect.Response[pmv1.ListLuksKeysResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := h.readDevice(ctx, "ListLuksKeys", req.Msg.DeviceId); err != nil {
		return nil, err
	}
	currentRows, historyRows, err := h.store.ListDeviceLuksKeys(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, h.internal(ctx, "read LUKS keys", err)
	}
	current, err := h.luksKeysToProto(currentRows)
	if err != nil {
		return nil, h.internal(ctx, "decode current LUKS keys", err)
	}
	history, err := h.luksKeysToProto(historyRows)
	if err != nil {
		return nil, h.internal(ctx, "decode historical LUKS keys", err)
	}
	if err := h.recordSensitiveRead(ctx, req, actor,
		powermanagev1connect.ControlServiceListLuksKeysProcedure,
		"ListLuksKeys", "device_luks_keys", req.Msg.DeviceId); err != nil {
		return nil, err
	}
	return connect.NewResponse(&pmv1.ListLuksKeysResponse{Current: current, History: history}), nil
}

// RevealLuksKey returns one plaintext passphrase only after the dedicated
// reveal operation and its device/action/entry effects are durable.
func (h *Handlers) RevealLuksKey(ctx context.Context, req *connect.Request[pmv1.RevealLuksKeyRequest]) (*connect.Response[pmv1.RevealLuksKeyResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "RevealLuksKey", ""); err != nil {
		return nil, err
	}
	secret, err := h.store.GetLuksKeyForReveal(ctx, req.Msg.Id)
	if err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, errLuksKeyNotFound, "LUKS key not found")
		}
		return nil, h.internal(ctx, "read LUKS key for reveal", err)
	}
	if _, err := h.readDevice(ctx, "RevealLuksKey", secret.DeviceID); err != nil {
		return nil, err
	}
	passphrase, err := h.openStoredSecret(secret.Passphrase,
		pmcrypto.SecretAADForRow(secret.DeviceID, secret.ActionID, "luks", secret.DevicePath))
	if err != nil {
		return nil, h.internal(ctx, "open LUKS passphrase", err)
	}
	if err := h.recordSecretReveal(ctx, req, actor,
		powermanagev1connect.ControlServiceRevealLuksKeyProcedure,
		"RevealLuksKey", "luks_key", secret.ID, secret.DeviceID, secret.ActionID); err != nil {
		return nil, err
	}
	return connect.NewResponse(&pmv1.RevealLuksKeyResponse{Passphrase: passphrase}), nil
}

func (h *Handlers) lpsPasswordsToProto(rows []store.LpsPasswordView) ([]*pmv1.LpsPassword, error) {
	out := make([]*pmv1.LpsPassword, len(rows))
	for i, row := range rows {
		reason, ok := rotationReasonFromString(row.RotationReason)
		if !ok {
			return nil, fmt.Errorf("invalid LPS rotation reason %q", row.RotationReason)
		}
		out[i] = &pmv1.LpsPassword{
			Id: row.ID, DeviceId: row.DeviceID, DeviceHostname: row.DeviceHostname,
			ActionId: row.ActionID, ActionName: row.ActionName,
			Username:  row.Username,
			RotatedAt: timestamppb.New(row.RotatedAt), RotationReason: reason,
		}
	}
	return out, nil
}

func (h *Handlers) luksKeysToProto(rows []store.LuksKeyView) ([]*pmv1.LuksKey, error) {
	out := make([]*pmv1.LuksKey, len(rows))
	for i, row := range rows {
		reason, ok := rotationReasonFromString(row.RotationReason)
		if !ok {
			return nil, fmt.Errorf("invalid LUKS rotation reason %q", row.RotationReason)
		}
		key := &pmv1.LuksKey{
			Id: row.ID, DeviceId: row.DeviceID, DeviceHostname: row.DeviceHostname,
			ActionId: row.ActionID, ActionName: row.ActionName,
			DevicePath: row.DevicePath,
			RotatedAt:  timestamppb.New(row.RotatedAt), RotationReason: reason,
		}
		if row.RevocationStatus != nil {
			status, ok := luksRevocationStatusFromString(*row.RevocationStatus)
			if !ok {
				return nil, fmt.Errorf("invalid LUKS revocation status %q", *row.RevocationStatus)
			}
			key.RevocationStatus = status
		}
		if row.RevocationError != nil {
			key.RevocationError = *row.RevocationError
		}
		if row.RevocationAt != nil {
			key.RevocationAt = timestamppb.New(*row.RevocationAt)
		}
		out[i] = key
	}
	return out, nil
}

func (h *Handlers) recordSecretReveal(
	ctx context.Context,
	req connect.AnyRequest,
	actor *auth.UserContext,
	procedure, permission, secretType, secretID, deviceID, actionID string,
) error {
	op := h.operation(req, actor, procedure, permission)
	op.Class = store.ClassSensitiveRead
	if _, err := h.store.RecordOperation(ctx, op,
		store.AuditEffect{ResourceType: secretType, ResourceID: secretID, Action: "REVEAL", Outcome: store.EffectApplied},
		store.AuditEffect{ResourceType: "device", ResourceID: deviceID, Action: "REVEAL", Outcome: store.EffectApplied},
		store.AuditEffect{ResourceType: "action", ResourceID: actionID, Action: "REVEAL", Outcome: store.EffectApplied},
	); err != nil {
		return h.internal(ctx, "record secret reveal", err)
	}
	return nil
}

// CreateLuksToken atomically persists a hash of a one-time owner token with
// its audit evidence. The plaintext is returned exactly once.
func (h *Handlers) CreateLuksToken(ctx context.Context, req *connect.Request[pmv1.CreateLuksTokenRequest]) (*connect.Response[pmv1.CreateLuksTokenResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := h.mutationDevice(ctx, "CreateLuksToken", req.Msg.DeviceId); err != nil {
		return nil, err
	}
	owned, err := h.store.IsDeviceDirectlyAssignedToUser(ctx, req.Msg.DeviceId, actor.ID)
	if err != nil {
		return nil, h.internal(ctx, "check LUKS token owner", err)
	}
	if !owned {
		return nil, rpcError(ctx, errPermissionDenied, connect.CodePermissionDenied,
			"only the directly assigned device owner can create a LUKS passphrase token")
	}
	action, err := h.store.GetManifestAction(ctx, req.Msg.ActionId)
	if err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, errActionNotFound, "action not found")
		}
		return nil, h.internal(ctx, "read LUKS token action", err)
	}
	if pmv1.ActionType(action.ActionType) != pmv1.ActionType_ACTION_TYPE_ENCRYPTION {
		return nil, rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument,
			"action is not an encryption action")
	}
	var params pmv1.EncryptionParams
	if err := protojson.Unmarshal(action.Params, &params); err != nil {
		return nil, h.internal(ctx, "decode encryption action params", err)
	}
	minLength := params.UserPassphraseMinLength
	if minLength < 16 {
		minLength = 16
	}
	if _, ok := pmv1.LpsPasswordComplexity_name[int32(params.UserPassphraseComplexity)]; !ok {
		return nil, h.internal(ctx, "decode encryption action params",
			fmt.Errorf("invalid passphrase complexity %d", params.UserPassphraseComplexity))
	}

	issuedAt := h.now().UTC()
	tokenID, err := ulid.New(ulid.Timestamp(issuedAt), rand.Reader)
	if err != nil {
		return nil, h.internal(ctx, "generate LUKS token", err)
	}
	token := tokenID.String()
	hash := sha256.Sum256([]byte(token))
	expiresAt := issuedAt.Add(luksTokenTTL)
	rowID := ulid.Make().String()
	_, err = h.store.WithAudit(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceCreateLuksTokenProcedure, "CreateLuksToken"),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			if _, err := tx.InsertLuksToken(ctx, db.InsertLuksTokenParams{
				ID: rowID, DeviceID: req.Msg.DeviceId, ActionID: req.Msg.ActionId,
				Token: hex.EncodeToString(hash[:]), MinLength: minLength,
				Complexity: int32(params.UserPassphraseComplexity),
				CreatedAt:  issuedAt, ExpiresAt: expiresAt,
			}); err != nil {
				return fmt.Errorf("insert LUKS token: %w", err)
			}
			rec.Effect(store.AuditEffect{
				ResourceType: "luks_token", ResourceID: rowID,
				Action: "CREATE", Outcome: store.EffectApplied,
				ChangedFields: []string{
					"action_id", "complexity", "device_id", "expires_at", "min_length",
				},
			})
			return nil
		})
	if err != nil {
		return nil, h.internal(ctx, "create LUKS token", err)
	}
	return connect.NewResponse(&pmv1.CreateLuksTokenResponse{
		Token:      token,
		Uri:        "power-manage://luks/set-passphrase?token=" + token,
		CliCommand: "sudo power-manage-agent luks set-passphrase --token " + token,
	}), nil
}

func (h *Handlers) openStoredSecret(ciphertext string, aad []byte) (string, error) {
	if !strings.HasPrefix(ciphertext, "enc:v1:") {
		return "", fmt.Errorf("stored secret is not current ciphertext")
	}
	return h.decryptor.DecryptWithContext(ciphertext, aad)
}

func rotationReasonFromString(value string) (pmv1.RotationReason, bool) {
	switch value {
	case "initial":
		return pmv1.RotationReason_ROTATION_REASON_INITIAL, true
	case "scheduled":
		return pmv1.RotationReason_ROTATION_REASON_SCHEDULED, true
	case "auth_grace":
		return pmv1.RotationReason_ROTATION_REASON_AUTH_GRACE, true
	default:
		return pmv1.RotationReason_ROTATION_REASON_UNSPECIFIED, false
	}
}

func luksRevocationStatusFromString(value string) (pmv1.LuksRevocationStatus, bool) {
	switch value {
	case "none":
		return pmv1.LuksRevocationStatus_LUKS_REVOCATION_STATUS_NONE, true
	case "dispatched":
		return pmv1.LuksRevocationStatus_LUKS_REVOCATION_STATUS_DISPATCHED, true
	case "success":
		return pmv1.LuksRevocationStatus_LUKS_REVOCATION_STATUS_SUCCESS, true
	case "failed":
		return pmv1.LuksRevocationStatus_LUKS_REVOCATION_STATUS_FAILED, true
	default:
		return pmv1.LuksRevocationStatus_LUKS_REVOCATION_STATUS_UNSPECIFIED, false
	}
}
