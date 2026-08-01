// Package manifest compiles the authoring hierarchy into the flat, durable
// unit of work sent to an agent.
package manifest

import (
	"context"
	"errors"
	"fmt"

	"github.com/oklog/ulid/v2"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	sdkvalidate "github.com/manchtools/power-manage-sdk/validate"
	"github.com/manchtools/power-manage/server/internal/actionparams"
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
	store *store.Store
}

// New constructs a compiler. A missing store is a boot-time wiring error.
func New(st *store.Store) *Compiler {
	if st == nil {
		panic("manifest: store is required")
	}
	return &Compiler{store: st}
}


// Action creates the singleton manifest for one authored Action.
func (c *Compiler) Action(ctx context.Context, id string) (*pmv1.Manifest, error) {
	if !validInput(ctx, id) {
		return nil, ErrInvalidInput
	}
	row, err := c.store.GetManifestAction(ctx, id)
	if err != nil {
		return nil, err
	}
	action, err := compileAction(row)
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
	return compileSet(set, rows, &pmv1.ManifestProvenance{ActionSetId: id}, nil)
}

// Definition creates one manifest per contained ActionSet. The Definition
// schedule overrides each emitted manifest without rewriting its ActionSet.
func (c *Compiler) Definition(ctx context.Context, id string) ([]*pmv1.Manifest, error) {
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
		compiled, err := compileSet(set, actionsBySet[set.ID], &pmv1.ManifestProvenance{
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
// The Action schedule remains authoring/display data; the manifest schedule is
// empty because receipt of this delivery is the one-shot execution trigger.
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
	})
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


func compileSet(set store.ActionSetRow, rows []store.ActionRow, provenance *pmv1.ManifestProvenance, scheduleOverride []byte) (*pmv1.Manifest, error) {
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
		action, err := compileAction(row)
		if err != nil {
			return nil, err
		}
		manifest.Occurrences = append(manifest.Occurrences, occurrence(action, policy))
	}
	return finish(manifest)
}

func compileAction(row store.ActionRow) (*pmv1.Action, error) {
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
	if err := actionparams.PopulateAction(action, row.ActionType, row.Params); err != nil {
		return nil, fmt.Errorf("manifest: action %s params: %w", row.ID, err)
	}
	if detail, ok := sdkvalidate.Struct(validator, action); !ok {
		return nil, fmt.Errorf("manifest: action %s invalid: %s", row.ID, detail)
	}
	return action, nil
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
