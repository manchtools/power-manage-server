package authoring

import (
	"fmt"

	"google.golang.org/protobuf/proto"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/actionparams"
	pmcrypto "github.com/manchtools/power-manage/server/internal/crypto"
)

func (h *Handlers) requestParams(message proto.Message, actionType pmv1.ActionType, actionID string, current []byte) ([]byte, error) {
	params := actionparams.ExtractParamsMsg(message)
	if params == nil {
		if actionType == pmv1.ActionType_ACTION_TYPE_ENCRYPTION || actionType == pmv1.ActionType_ACTION_TYPE_WIFI {
			return nil, ErrInvalidInput
		}
		return []byte("{}"), nil
	}
	if !actionparams.ParamsMatchType(message, actionType) {
		return nil, ErrInvalidInput
	}
	switch value := params.(type) {
	case *pmv1.EncryptionAuthoringParams:
		return h.prepareEncryptionParams(actionID, value, current)
	case *pmv1.WifiAuthoringParams:
		return h.prepareWifiParams(actionID, value, current)
	default:
		raw, err := actionparams.MarshalActionParams(params)
		if err != nil {
			return nil, ErrInvalidInput
		}
		return raw, nil
	}
}

func (h *Handlers) prepareEncryptionParams(actionID string, input *pmv1.EncryptionAuthoringParams, current []byte) ([]byte, error) {
	prepared := proto.Clone(input).(*pmv1.EncryptionAuthoringParams)
	if prepared.PresharedKey == nil {
		if len(current) == 0 {
			return nil, ErrInvalidInput
		}
		stored := &pmv1.EncryptionAuthoringParams{}
		if err := actionparams.UnmarshalActionParams(current, stored); err != nil || stored.PresharedKey == nil ||
			!pmcrypto.IsEncryptedValue(stored.GetPresharedKey()) {
			return nil, ErrInvalidInput
		}
		prepared.PresharedKey = stringPointer(stored.GetPresharedKey())
	} else {
		if prepared.GetPresharedKey() == "" {
			return nil, ErrInvalidInput
		}
		ciphertext, err := h.atRest.EncryptWithContext(prepared.GetPresharedKey(),
			pmcrypto.RowAAD(actionID, pmcrypto.PurposeActionEncryptionPresharedKey))
		if err != nil {
			return nil, fmt.Errorf("authoring: encrypt encryption pre-shared key: %w", err)
		}
		prepared.PresharedKey = stringPointer(ciphertext)
	}
	return actionparams.MarshalActionParams(prepared)
}

func (h *Handlers) prepareWifiParams(actionID string, input *pmv1.WifiAuthoringParams, current []byte) ([]byte, error) {
	prepared := proto.Clone(input).(*pmv1.WifiAuthoringParams)
	stored := &pmv1.WifiAuthoringParams{}
	if len(current) > 0 {
		if err := actionparams.UnmarshalActionParams(current, stored); err != nil {
			return nil, ErrInvalidInput
		}
	}

	switch prepared.AuthType {
	case pmv1.WifiAuthType_WIFI_AUTH_TYPE_PSK:
		prepared.ClientKey = nil
		secret, err := h.prepareOptionalSecret(actionID, prepared.Psk, stored.Psk,
			stored.AuthType == pmv1.WifiAuthType_WIFI_AUTH_TYPE_PSK, pmcrypto.PurposeActionWifiPSK)
		if err != nil {
			return nil, err
		}
		prepared.Psk = secret
	case pmv1.WifiAuthType_WIFI_AUTH_TYPE_EAP_TLS:
		prepared.Psk = nil
		secret, err := h.prepareOptionalSecret(actionID, prepared.ClientKey, stored.ClientKey,
			stored.AuthType == pmv1.WifiAuthType_WIFI_AUTH_TYPE_EAP_TLS, pmcrypto.PurposeActionWifiClientKey)
		if err != nil {
			return nil, err
		}
		prepared.ClientKey = secret
	default:
		return nil, ErrInvalidInput
	}
	return actionparams.MarshalActionParams(prepared)
}

func (h *Handlers) prepareOptionalSecret(actionID string, supplied, stored *string, mayPreserve bool, purpose string) (*string, error) {
	if supplied == nil {
		if !mayPreserve || stored == nil || !pmcrypto.IsEncryptedValue(*stored) {
			return nil, ErrInvalidInput
		}
		return stringPointer(*stored), nil
	}
	if *supplied == "" {
		return nil, ErrInvalidInput
	}
	ciphertext, err := h.atRest.EncryptWithContext(*supplied, pmcrypto.RowAAD(actionID, purpose))
	if err != nil {
		return nil, fmt.Errorf("authoring: encrypt action credential: %w", err)
	}
	return stringPointer(ciphertext), nil
}

func populateManagedParams(action *pmv1.ManagedAction, actionType pmv1.ActionType, raw []byte) error {
	switch actionType {
	case pmv1.ActionType_ACTION_TYPE_ENCRYPTION:
		stored := &pmv1.EncryptionAuthoringParams{}
		if err := actionparams.UnmarshalActionParams(raw, stored); err != nil {
			return err
		}
		action.Params = &pmv1.ManagedAction_Encryption{Encryption: &pmv1.ManagedEncryptionParams{
			PresharedKeyConfigured: stored.PresharedKey != nil && pmcrypto.IsEncryptedValue(stored.GetPresharedKey()),
			RotationIntervalDays:   stored.RotationIntervalDays, MinWords: stored.MinWords,
			DeviceBoundKeyType:       stored.DeviceBoundKeyType,
			UserPassphraseMinLength:  stored.UserPassphraseMinLength,
			UserPassphraseComplexity: stored.UserPassphraseComplexity,
		}}
		return nil
	case pmv1.ActionType_ACTION_TYPE_WIFI:
		stored := &pmv1.WifiAuthoringParams{}
		if err := actionparams.UnmarshalActionParams(raw, stored); err != nil {
			return err
		}
		action.Params = &pmv1.ManagedAction_Wifi{Wifi: &pmv1.ManagedWifiParams{
			Ssid: stored.Ssid, AuthType: stored.AuthType,
			PskConfigured: stored.Psk != nil && pmcrypto.IsEncryptedValue(stored.GetPsk()),
			CaCert:        stored.CaCert, ClientCert: stored.ClientCert,
			ClientKeyConfigured: stored.ClientKey != nil && pmcrypto.IsEncryptedValue(stored.GetClientKey()),
			Identity:            stored.Identity, AutoConnect: stored.AutoConnect,
			Hidden: stored.Hidden, Priority: stored.Priority,
		}}
		return nil
	default:
		return actionparams.PopulateManagedAction(action, actionType, raw)
	}
}

func stringPointer(value string) *string { return &value }
