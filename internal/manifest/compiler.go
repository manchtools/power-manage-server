// Package manifest compiles the authoring hierarchy into the flat, durable
// unit of work sent to an agent.
package manifest

import (
	"context"
	"crypto/ecdh"
	"errors"
	"fmt"

	"github.com/oklog/ulid/v2"

	sdkcrypto "github.com/manchtools/power-manage-sdk/crypto"
	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	sdkvalidate "github.com/manchtools/power-manage-sdk/validate"
	"github.com/manchtools/power-manage/server/internal/actionparams"
	pmcrypto "github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/store"
	"google.golang.org/protobuf/proto"
)

var (
	// ErrInvalidInput means the requested source identifier is not a ULID or
	// the caller supplied no context.
	ErrInvalidInput = errors.New("invalid manifest compiler input")
	// ErrEmptyManifest means an ActionSet or Definition member contains no
	// live actions and therefore cannot become executable work.
	ErrEmptyManifest = errors.New("manifest contains no actions")
)

var validator = sdkvalidate.NewValidator()

// Compiler turns an Action, ActionSet or Definition into complete manifests.
type Compiler struct {
	store  *store.Store
	atRest *pmcrypto.Encryptor
}

// New constructs a compiler. A missing store is a boot-time wiring error.
func New(st *store.Store, atRest ...*pmcrypto.Encryptor) *Compiler {
	if st == nil {
		panic("manifest: store is required")
	}
	compiler := &Compiler{store: st}
	if len(atRest) > 0 {
		compiler.atRest = atRest[0]
	}
	return compiler
}

// Action creates the singleton manifest for one authored Action.
func (c *Compiler) Action(ctx context.Context, id string) (*pmv1.Manifest, error) {
	return c.action(ctx, "", id)
}

// ActionForDevice creates an agent-ready manifest whose classified fields are
// sealed to deviceID before the caller can persist it.
func (c *Compiler) ActionForDevice(ctx context.Context, deviceID, id string) (*pmv1.Manifest, error) {
	return c.action(ctx, deviceID, id)
}

func (c *Compiler) action(ctx context.Context, deviceID, id string) (*pmv1.Manifest, error) {
	if !validInput(ctx, id) {
		return nil, ErrInvalidInput
	}
	row, err := c.store.GetManifestAction(ctx, id)
	if err != nil {
		return nil, err
	}
	action, err := c.compileAction(ctx, row, deviceID)
	if err != nil {
		return nil, err
	}
	schedule := action.Schedule
	if schedule == nil {
		schedule = &pmv1.ActionSchedule{}
	}
	return finish(&pmv1.Manifest{
		ManifestId:       ulid.Make().String(),
		Provenance:       &pmv1.ManifestProvenance{ActionId: id},
		Schedule:         schedule,
		DefaultOnFailure: pmv1.OnFailure_ON_FAILURE_CONTINUE,
		Occurrences:      []*pmv1.ManifestOccurrence{occurrence(action, pmv1.OnFailure_ON_FAILURE_CONTINUE)},
	})
}

// ActionSet flattens one set into a manifest in authored member order.
func (c *Compiler) ActionSet(ctx context.Context, id string) (*pmv1.Manifest, error) {
	return c.actionSet(ctx, "", id)
}

func (c *Compiler) ActionSetForDevice(ctx context.Context, deviceID, id string) (*pmv1.Manifest, error) {
	return c.actionSet(ctx, deviceID, id)
}

func (c *Compiler) actionSet(ctx context.Context, deviceID, id string) (*pmv1.Manifest, error) {
	if !validInput(ctx, id) {
		return nil, ErrInvalidInput
	}
	set, err := c.store.GetManifestActionSet(ctx, id)
	if err != nil {
		return nil, err
	}
	rows, err := c.store.ListManifestActionSetActions(ctx, id)
	if err != nil {
		return nil, err
	}
	return c.compileSet(ctx, deviceID, set, rows, &pmv1.ManifestProvenance{ActionSetId: id}, nil)
}

// Definition creates one manifest per contained ActionSet. The Definition
// schedule overrides each emitted manifest without rewriting its ActionSet.
func (c *Compiler) Definition(ctx context.Context, id string) ([]*pmv1.Manifest, error) {
	return c.definition(ctx, "", id)
}

func (c *Compiler) DefinitionForDevice(ctx context.Context, deviceID, id string) ([]*pmv1.Manifest, error) {
	return c.definition(ctx, deviceID, id)
}

func (c *Compiler) definition(ctx context.Context, deviceID, id string) ([]*pmv1.Manifest, error) {
	if !validInput(ctx, id) {
		return nil, ErrInvalidInput
	}
	definition, err := c.store.GetManifestDefinition(ctx, id)
	if err != nil {
		return nil, err
	}
	sets, err := c.store.ListManifestDefinitionActionSets(ctx, id)
	if err != nil {
		return nil, err
	}
	if len(sets) == 0 {
		return nil, ErrEmptyManifest
	}
	rows, err := c.store.ListManifestDefinitionActions(ctx, id)
	if err != nil {
		return nil, err
	}
	actionsBySet := make(map[string][]store.ActionRow, len(sets))
	for _, row := range rows {
		actionsBySet[row.ActionSetID] = append(actionsBySet[row.ActionSetID], row.Action)
	}

	manifests := make([]*pmv1.Manifest, 0, len(sets))
	for _, set := range sets {
		compiled, err := c.compileSet(ctx, deviceID, set, actionsBySet[set.ID], &pmv1.ManifestProvenance{
			DefinitionId: id,
			ActionSetId:  set.ID,
		}, definition.Schedule)
		if err != nil {
			return nil, fmt.Errorf("manifest: definition %s set %s: %w", id, set.ID, err)
		}
		manifests = append(manifests, compiled)
	}
	return manifests, nil
}

// OneShotAction creates the singleton manifest used by an explicit dispatch.
// The Action schedule remains authoring/display data; the manifest carries the
// structural one_shot flag, which is what makes the agent execute the delivery
// exactly once on durable receipt instead of scheduling it. An empty manifest
// schedule accompanies the flag but never stands in for it.
func OneShotAction(action *pmv1.Action) (*pmv1.Manifest, error) {
	if action == nil {
		return nil, ErrInvalidInput
	}
	cloned, ok := proto.Clone(action).(*pmv1.Action)
	if !ok || cloned.GetId() == nil || !validInput(context.Background(), cloned.Id.Value) {
		return nil, ErrInvalidInput
	}
	return finish(&pmv1.Manifest{
		ManifestId:       ulid.Make().String(),
		Provenance:       &pmv1.ManifestProvenance{ActionId: cloned.Id.Value},
		Schedule:         &pmv1.ActionSchedule{},
		DefaultOnFailure: pmv1.OnFailure_ON_FAILURE_CONTINUE,
		Occurrences:      []*pmv1.ManifestOccurrence{occurrence(cloned, pmv1.OnFailure_ON_FAILURE_CONTINUE)},
		OneShot:          true,
	})
}

// AsOneShot marks a manifest compiled from the catalog as an explicit dispatch.
// The structural one_shot flag is what makes the agent execute the delivery
// exactly once on durable receipt; clearing the compiled schedule stops the
// authored cadence from also being installed. The nested Actions keep their
// authoring/display schedules.
func AsOneShot(compiled *pmv1.Manifest) *pmv1.Manifest {
	if compiled == nil {
		return nil
	}
	compiled.Schedule = &pmv1.ActionSchedule{}
	compiled.OneShot = true
	return compiled
}

// FreshCopy preserves compiled semantics while reminting delivery-local
// manifest and occurrence identities for another target device.
func FreshCopy(compiled *pmv1.Manifest) (*pmv1.Manifest, error) {
	if compiled == nil {
		return nil, ErrInvalidInput
	}
	cloned, ok := proto.Clone(compiled).(*pmv1.Manifest)
	if !ok {
		return nil, ErrInvalidInput
	}
	cloned.ManifestId = ulid.Make().String()
	for _, occurrence := range cloned.Occurrences {
		if occurrence == nil {
			return nil, ErrInvalidInput
		}
		occurrence.OccurrenceId = ulid.Make().String()
	}
	return finish(cloned)
}

func (c *Compiler) compileSet(ctx context.Context, deviceID string, set store.ActionSetRow, rows []store.ActionRow, provenance *pmv1.ManifestProvenance, scheduleOverride []byte) (*pmv1.Manifest, error) {
	if len(rows) == 0 {
		return nil, ErrEmptyManifest
	}
	scheduleRaw := set.Schedule
	if scheduleOverride != nil {
		scheduleRaw = scheduleOverride
	}
	schedule, err := requiredSchedule(scheduleRaw)
	if err != nil {
		return nil, fmt.Errorf("manifest schedule: %w", err)
	}
	policy := pmv1.OnFailure(set.OnFailure)
	if policy != pmv1.OnFailure_ON_FAILURE_CONTINUE && policy != pmv1.OnFailure_ON_FAILURE_STOP {
		return nil, fmt.Errorf("action set %s has invalid failure policy %d", set.ID, set.OnFailure)
	}
	manifest := &pmv1.Manifest{
		ManifestId:       ulid.Make().String(),
		Provenance:       provenance,
		Schedule:         schedule,
		DefaultOnFailure: policy,
		Occurrences:      make([]*pmv1.ManifestOccurrence, 0, len(rows)),
	}
	for _, row := range rows {
		action, err := c.compileAction(ctx, row, deviceID)
		if err != nil {
			return nil, err
		}
		manifest.Occurrences = append(manifest.Occurrences, occurrence(action, policy))
	}
	return finish(manifest)
}

func (c *Compiler) compileAction(ctx context.Context, row store.ActionRow, deviceID string) (*pmv1.Action, error) {
	schedule, err := actionparams.ParseSchedule(row.Schedule)
	if err != nil {
		return nil, fmt.Errorf("manifest: action %s schedule: %w", row.ID, err)
	}
	action := &pmv1.Action{
		Id:             &pmv1.ActionId{Value: row.ID},
		Type:           pmv1.ActionType(row.ActionType),
		DesiredState:   pmv1.DesiredState(row.DesiredState),
		TimeoutSeconds: row.TimeoutSeconds,
		Schedule:       schedule,
	}
	switch action.Type {
	case pmv1.ActionType_ACTION_TYPE_ENCRYPTION:
		params, err := c.encryptionParams(ctx, deviceID, row)
		if err != nil {
			return nil, fmt.Errorf("manifest: action %s params: %w", row.ID, err)
		}
		action.Params = &pmv1.Action_Encryption{Encryption: params}
	case pmv1.ActionType_ACTION_TYPE_WIFI:
		params, err := c.wifiParams(ctx, deviceID, row)
		if err != nil {
			return nil, fmt.Errorf("manifest: action %s params: %w", row.ID, err)
		}
		action.Params = &pmv1.Action_Wifi{Wifi: params}
	default:
		if err := actionparams.PopulateAction(action, row.ActionType, row.Params); err != nil {
			return nil, fmt.Errorf("manifest: action %s params: %w", row.ID, err)
		}
	}
	if detail, ok := sdkvalidate.Struct(validator, action); !ok {
		return nil, fmt.Errorf("manifest: action %s invalid: %s", row.ID, detail)
	}
	return action, nil
}

func (c *Compiler) encryptionParams(ctx context.Context, deviceID string, row store.ActionRow) (*pmv1.EncryptionParams, error) {
	stored := &pmv1.EncryptionAuthoringParams{}
	if err := actionparams.UnmarshalActionParams(row.Params, stored); err != nil {
		return nil, err
	}
	sealed, err := c.sealActionField(ctx, deviceID, row.ID, "powermanage.v1.EncryptionParams",
		"preshared_key", stored.GetPresharedKey(), pmcrypto.PurposeActionEncryptionPresharedKey)
	if err != nil {
		return nil, err
	}
	return &pmv1.EncryptionParams{
		PresharedKey: sealed, RotationIntervalDays: stored.RotationIntervalDays,
		MinWords: stored.MinWords, DeviceBoundKeyType: stored.DeviceBoundKeyType,
		UserPassphraseMinLength:  stored.UserPassphraseMinLength,
		UserPassphraseComplexity: stored.UserPassphraseComplexity,
	}, nil
}

func (c *Compiler) wifiParams(ctx context.Context, deviceID string, row store.ActionRow) (*pmv1.WifiParams, error) {
	stored := &pmv1.WifiAuthoringParams{}
	if err := actionparams.UnmarshalActionParams(row.Params, stored); err != nil {
		return nil, err
	}
	params := &pmv1.WifiParams{
		Ssid: stored.Ssid, AuthType: stored.AuthType, CaCert: stored.CaCert,
		ClientCert: stored.ClientCert, Identity: stored.Identity,
		AutoConnect: stored.AutoConnect, Hidden: stored.Hidden, Priority: stored.Priority,
	}
	var err error
	switch stored.AuthType {
	case pmv1.WifiAuthType_WIFI_AUTH_TYPE_PSK:
		params.Psk, err = c.sealActionField(ctx, deviceID, row.ID, "powermanage.v1.WifiParams",
			"psk", stored.GetPsk(), pmcrypto.PurposeActionWifiPSK)
	case pmv1.WifiAuthType_WIFI_AUTH_TYPE_EAP_TLS:
		params.ClientKey, err = c.sealActionField(ctx, deviceID, row.ID, "powermanage.v1.WifiParams",
			"client_key", stored.GetClientKey(), pmcrypto.PurposeActionWifiClientKey)
	default:
		return nil, errors.New("unsupported WiFi authentication type")
	}
	return params, err
}

func (c *Compiler) sealActionField(ctx context.Context, deviceID, actionID, message, field, ciphertext, purpose string) (*pmv1.SealedValue, error) {
	if c.atRest == nil || !validInput(ctx, deviceID) || !pmcrypto.IsEncryptedValue(ciphertext) {
		return nil, errors.New("action secret compiler requires encrypted storage and a target device")
	}
	plaintext, err := c.atRest.DecryptWithContext(ciphertext, pmcrypto.RowAAD(actionID, purpose))
	if err != nil {
		return nil, fmt.Errorf("decrypt action credential: %w", err)
	}
	secret := []byte(plaintext)
	defer clear(secret)
	recipient, err := c.deviceRecipient(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	aad, info, err := sdkcrypto.FieldSealContext(sdkcrypto.DirectionControlToAgent,
		message, field, deviceID, actionID)
	if err != nil {
		return nil, err
	}
	sealed, err := sdkcrypto.SealToPublicKey(recipient, secret, aad, info)
	if err != nil {
		return nil, fmt.Errorf("seal action credential: %w", err)
	}
	return &pmv1.SealedValue{Version: 1, Ciphertext: sealed}, nil
}

func (c *Compiler) deviceRecipient(ctx context.Context, deviceID string) (*ecdh.PublicKey, error) {
	device, err := c.store.GetDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	return sdkcrypto.ParseX25519PublicKey(device.AgentSealingPublicKey)
}

func requiredSchedule(raw []byte) (*pmv1.ActionSchedule, error) {
	schedule, err := actionparams.ParseSchedule(raw)
	if err != nil {
		return nil, err
	}
	if schedule == nil {
		schedule = &pmv1.ActionSchedule{}
	}
	return schedule, nil
}

func occurrence(action *pmv1.Action, policy pmv1.OnFailure) *pmv1.ManifestOccurrence {
	return &pmv1.ManifestOccurrence{
		OccurrenceId: ulid.Make().String(),
		Action:       action,
		OnFailure:    policy,
	}
}

func finish(manifest *pmv1.Manifest) (*pmv1.Manifest, error) {
	if detail, ok := sdkvalidate.Struct(validator, manifest); !ok {
		return nil, fmt.Errorf("manifest: compiled output invalid: %s", detail)
	}
	return manifest, nil
}

func validInput(ctx context.Context, id string) bool {
	if ctx == nil {
		return false
	}
	_, err := ulid.ParseStrict(id)
	return err == nil
}
