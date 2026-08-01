// Package agentsecrets owns the narrow control-side sinks for sealed LUKS and
// LPS transport fields. Plaintext exists only while opening or resealing one
// field and is never written to audit or logs.
package agentsecrets

import (
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/oklog/ulid/v2"

	sdkcrypto "github.com/manchtools/power-manage-sdk/crypto"
	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	sdkvalidate "github.com/manchtools/power-manage-sdk/validate"
	pmcrypto "github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

const sealedFieldVersion = uint32(1)

var (
	ErrInvalidInput      = errors.New("invalid agent secret input")
	ErrWrongActionType   = errors.New("action has the wrong secret type")
	ErrUnsupportedSeal   = errors.New("unsupported sealed-field version")
	ErrDuplicateUsername = errors.New("LPS batch repeats a username")
)

// Config supplies the deployment recipient key and mandatory at-rest cipher.
type Config struct {
	Store                    *store.Store
	AtRest                   *pmcrypto.Encryptor
	ControlSealingPrivateKey *ecdh.PrivateKey
	Now                      func() time.Time
}

// Service implements the authenticated agent secret operations.
type Service struct {
	store          *store.Store
	atRest         *pmcrypto.Encryptor
	controlPrivate *ecdh.PrivateKey
	now            func() time.Time
	validator      interface{ Struct(any) error }
}

// New constructs the sealed-field service. Plaintext-at-rest and a missing
// deployment recipient key are boot-time failures, not optional modes.
func New(cfg Config) *Service {
	if cfg.Store == nil || cfg.AtRest == nil || cfg.ControlSealingPrivateKey == nil {
		panic("agentsecrets: store, at-rest cipher, and control X25519 key are required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Service{
		store: cfg.Store, atRest: cfg.AtRest, controlPrivate: cfg.ControlSealingPrivateKey,
		now: cfg.Now, validator: sdkvalidate.NewValidator(),
	}
}

// ValidateLuksToken consumes one device-bound token and returns its policy.
// docref: begin sealed-agent-secret-sinks
func (s *Service) ValidateLuksToken(ctx context.Context, deviceID string, request *pmv1.ValidateLuksTokenRequest) (*pmv1.ValidateLuksTokenResponse, error) {
	if ctx == nil || !validID(deviceID) || request == nil || s.validator.Struct(request) != nil {
		return nil, ErrInvalidInput
	}
	hash := sha256.Sum256([]byte(request.Token))
	now := s.now().UTC().Truncate(time.Microsecond)
	var token db.LuksToken
	_, err := s.store.WithAudit(ctx, agentOperation(deviceID, "ValidateLuksToken"),
		func(ctx context.Context, tx *store.Tx, recorder *store.AuditRecorder) error {
			var err error
			token, err = tx.ConsumeLuksToken(ctx, db.ConsumeLuksTokenParams{
				Token: hex.EncodeToString(hash[:]), DeviceID: deviceID, Now: now,
			})
			if errors.Is(err, pgx.ErrNoRows) {
				return store.ErrNotFound
			}
			if err != nil {
				return fmt.Errorf("consume LUKS token: %w", err)
			}
			recorder.Effect(store.AuditEffect{
				ResourceType: "luks_token", ResourceID: token.ID, Action: "CONSUME",
				Outcome: store.EffectApplied, ChangedFields: []string{"used"},
			})
			return nil
		})
	if err != nil {
		return nil, err
	}
	devicePath := ""
	key, err := s.store.GetCurrentLuksKeyForAgent(ctx, deviceID, token.ActionID)
	if err == nil {
		devicePath = key.DevicePath
	} else if !store.IsNotFound(err) {
		return nil, err
	}
	return &pmv1.ValidateLuksTokenResponse{
		ActionId: token.ActionID, DevicePath: devicePath, MinLength: token.MinLength,
		Complexity: pmv1.LpsPasswordComplexity(token.Complexity),
	}, nil
}

// GetLuksKey opens at-rest ciphertext and immediately reseals it to this
// device's enrollment recipient key.
func (s *Service) GetLuksKey(ctx context.Context, deviceID string, request *pmv1.GetLuksKeyRequest) (*pmv1.GetLuksKeyResponse, error) {
	if ctx == nil || !validID(deviceID) || request == nil || s.validator.Struct(request) != nil {
		return nil, ErrInvalidInput
	}
	key, err := s.store.GetCurrentLuksKeyForAgent(ctx, deviceID, request.ActionId)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(key.Passphrase, "enc:v1:") {
		return nil, errors.New("LUKS passphrase is not encrypted at rest")
	}
	plaintext, err := s.atRest.DecryptWithContext(key.Passphrase, pmcrypto.SecretAAD(deviceID, request.ActionId, "luks"))
	if err != nil {
		return nil, fmt.Errorf("open LUKS passphrase at rest: %w", err)
	}
	device, err := s.store.GetDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	recipient, err := sdkcrypto.ParseX25519PublicKey(device.AgentSealingPublicKey)
	if err != nil {
		return nil, err
	}
	aad, info, err := sdkcrypto.FieldSealContext(sdkcrypto.DirectionControlToAgent,
		"powermanage.v1.GetLuksKeyResponse", "passphrase", deviceID, request.ActionId)
	if err != nil {
		return nil, err
	}
	sealed, err := sdkcrypto.SealToPublicKey(recipient, []byte(plaintext), aad, info)
	if err != nil {
		return nil, fmt.Errorf("seal LUKS passphrase to agent: %w", err)
	}
	if _, err := s.store.RecordOperation(ctx, agentSensitiveReadOperation(deviceID, "GetLuksKey"), store.AuditEffect{
		ResourceType: "luks_key", ResourceID: key.ID, Action: "READ", Outcome: store.EffectApplied,
	}); err != nil {
		return nil, err
	}
	return &pmv1.GetLuksKeyResponse{Passphrase: &pmv1.SealedValue{
		Version: sealedFieldVersion, Ciphertext: sealed,
	}}, nil
}

// StoreLuksKey opens an agent-to-control field and re-encrypts it at rest in
// the same audited transaction that rotates the current row.
func (s *Service) StoreLuksKey(ctx context.Context, deviceID string, request *pmv1.StoreLuksKeyRequest) (*pmv1.StoreLuksKeyResponse, error) {
	if ctx == nil || !validID(deviceID) || request == nil || s.validator.Struct(request) != nil {
		return nil, ErrInvalidInput
	}
	if err := s.requireActionType(ctx, request.ActionId, pmv1.ActionType_ACTION_TYPE_ENCRYPTION); err != nil {
		return nil, err
	}
	plaintext, err := s.openAgentField(request.Passphrase, "powermanage.v1.StoreLuksKeyRequest", "passphrase", deviceID, request.ActionId)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	ciphertext, err := s.atRest.EncryptWithContext(string(plaintext), pmcrypto.SecretAAD(deviceID, request.ActionId, "luks"))
	if err != nil {
		return nil, fmt.Errorf("encrypt LUKS passphrase at rest: %w", err)
	}
	reason, ok := rotationReason(request.RotationReason)
	if !ok || request.RotationReason == pmv1.RotationReason_ROTATION_REASON_AUTH_GRACE {
		return nil, ErrInvalidInput
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	rowID := ulid.Make().String()
	_, err = s.store.WithAudit(ctx, agentOperation(deviceID, "StoreLuksKey"),
		func(ctx context.Context, tx *store.Tx, recorder *store.AuditRecorder) error {
			if _, err := tx.RetireCurrentLuksKeys(ctx, db.RetireCurrentLuksKeysParams{
				DeviceID: deviceID, ActionID: request.ActionId,
			}); err != nil {
				return fmt.Errorf("retire current LUKS key: %w", err)
			}
			if _, err := tx.InsertLuksKey(ctx, db.InsertLuksKeyParams{
				ID: rowID, DeviceID: deviceID, ActionID: request.ActionId, DevicePath: request.DevicePath,
				Passphrase: ciphertext, RotatedAt: now, RotationReason: reason, CreatedAt: now,
			}); err != nil {
				return fmt.Errorf("insert LUKS key: %w", err)
			}
			recorder.Effect(secretEffect("luks_key", rowID, "ROTATE",
				"device_path", "is_current", "passphrase", "rotated_at", "rotation_reason"))
			return nil
		})
	if err != nil {
		return nil, err
	}
	return &pmv1.StoreLuksKeyResponse{Success: true}, nil
}

// StoreLpsPasswords commits the whole already-performed rotation batch or none
// of it. Malformed timestamps fall back to receipt time so credentials are not
// discarded after the irreversible local change.
func (s *Service) StoreLpsPasswords(ctx context.Context, deviceID string, request *pmv1.StoreLpsPasswordsRequest) (*pmv1.StoreLpsPasswordsResponse, error) {
	if ctx == nil || !validID(deviceID) || request == nil || s.validator.Struct(request) != nil {
		return nil, ErrInvalidInput
	}
	if err := s.requireActionType(ctx, request.ActionId, pmv1.ActionType_ACTION_TYPE_LPS); err != nil {
		return nil, err
	}
	type preparedRotation struct {
		id, username, ciphertext, reason string
		rotatedAt                        time.Time
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	prepared := make([]preparedRotation, 0, len(request.Rotations))
	seen := make(map[string]struct{}, len(request.Rotations))
	for _, rotation := range request.Rotations {
		if rotation == nil {
			return nil, ErrInvalidInput
		}
		if _, duplicate := seen[rotation.Username]; duplicate {
			return nil, ErrDuplicateUsername
		}
		seen[rotation.Username] = struct{}{}
		plaintext, err := s.openAgentField(rotation.Password,
			"powermanage.v1.LpsPasswordRotation", "password", deviceID, request.ActionId, rotation.Username)
		if err != nil {
			return nil, err
		}
		ciphertext, encryptErr := s.atRest.EncryptWithContext(string(plaintext),
			pmcrypto.SecretAAD(deviceID, request.ActionId, "lps"))
		clear(plaintext)
		if encryptErr != nil {
			return nil, fmt.Errorf("encrypt LPS password at rest: %w", encryptErr)
		}
		rotatedAt, err := time.Parse(time.RFC3339Nano, rotation.RotatedAt)
		if err != nil {
			rotatedAt = now
		}
		reason, ok := rotationReason(rotation.Reason)
		if !ok {
			return nil, ErrInvalidInput
		}
		prepared = append(prepared, preparedRotation{
			id: ulid.Make().String(), username: rotation.Username, ciphertext: ciphertext,
			rotatedAt: rotatedAt.UTC().Truncate(time.Microsecond), reason: reason,
		})
	}
	_, err := s.store.WithAudit(ctx, agentOperation(deviceID, "StoreLpsPasswords"),
		func(ctx context.Context, tx *store.Tx, recorder *store.AuditRecorder) error {
			for _, rotation := range prepared {
				if _, err := tx.RetireCurrentLpsPassword(ctx, db.RetireCurrentLpsPasswordParams{
					DeviceID: deviceID, ActionID: request.ActionId, Username: rotation.username,
				}); err != nil {
					return fmt.Errorf("retire current LPS password: %w", err)
				}
				if _, err := tx.InsertLpsPassword(ctx, db.InsertLpsPasswordParams{
					ID: rotation.id, DeviceID: deviceID, ActionID: request.ActionId, Username: rotation.username,
					Password: rotation.ciphertext, RotatedAt: rotation.rotatedAt,
					RotationReason: rotation.reason, CreatedAt: now,
				}); err != nil {
					return fmt.Errorf("insert LPS password: %w", err)
				}
				recorder.Effect(secretEffect("lps_password", rotation.id, "ROTATE",
					"is_current", "password", "rotated_at", "rotation_reason", "username"))
			}
			return nil
		})
	if err != nil {
		return nil, err
	}
	return &pmv1.StoreLpsPasswordsResponse{Success: true}, nil
}

// docref: end sealed-agent-secret-sinks

func (s *Service) openAgentField(value *pmv1.SealedValue, message, field string, bindings ...string) ([]byte, error) {
	if value == nil || value.Version != sealedFieldVersion {
		return nil, ErrUnsupportedSeal
	}
	aad, info, err := sdkcrypto.FieldSealContext(sdkcrypto.DirectionAgentToControl, message, field, bindings...)
	if err != nil {
		return nil, err
	}
	plaintext, err := sdkcrypto.OpenWithPrivateKey(s.controlPrivate, value.Ciphertext, aad, info)
	if err != nil {
		return nil, fmt.Errorf("open sealed agent field: %w", err)
	}
	if len(plaintext) == 0 {
		return nil, ErrInvalidInput
	}
	return plaintext, nil
}

func (s *Service) requireActionType(ctx context.Context, actionID string, expected pmv1.ActionType) error {
	action, err := s.store.GetManifestAction(ctx, actionID)
	if err != nil {
		return err
	}
	if pmv1.ActionType(action.ActionType) != expected {
		return ErrWrongActionType
	}
	return nil
}

func rotationReason(reason pmv1.RotationReason) (string, bool) {
	switch reason {
	case pmv1.RotationReason_ROTATION_REASON_INITIAL:
		return "initial", true
	case pmv1.RotationReason_ROTATION_REASON_SCHEDULED:
		return "scheduled", true
	case pmv1.RotationReason_ROTATION_REASON_AUTH_GRACE:
		return "auth_grace", true
	default:
		return "", false
	}
}

func validID(id string) bool {
	_, err := ulid.ParseStrict(id)
	return err == nil
}

func agentOperation(deviceID, descriptor string) store.AuditOperation {
	return store.AuditOperation{
		Class: store.ClassMutation, ActorType: "agent", ActorID: deviceID, Origin: "agent_stream",
		RequestDescriptor:    "powermanage.v1.AgentService.Stream/" + descriptor,
		AuthorizationOutcome: store.AuthorizationAllowed, AuthorizationDetail: "device_mtls",
		Result: store.ResultSuccess, ResultCode: "OK",
	}
}

func agentSensitiveReadOperation(deviceID, descriptor string) store.AuditOperation {
	operation := agentOperation(deviceID, descriptor)
	operation.Class = store.ClassSensitiveRead
	return operation
}

func secretEffect(resourceType, id, action string, fields ...string) store.AuditEffect {
	return store.AuditEffect{
		ResourceType: resourceType, ResourceID: id, Action: action,
		Outcome: store.EffectApplied, ChangedFields: fields,
	}
}
