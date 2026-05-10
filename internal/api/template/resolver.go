// Resolver implementation backed by the projection store. The
// renderer talks to this through the Resolver interface in render.go;
// tests substitute a static map.
//
// Three precedence layers (highest → lowest): device labels →
// device-group variables → user-group variables. Higher layers
// shadow lower layers silently because operators routinely override
// a group default with a device-specific value. Duplicate names
// WITHIN the same layer (two device groups defining the same name)
// return an error — the operator can't have intended both at once
// and silently picking one would be a footgun at action-dispatch
// time. See manchtools/power-manage-server#196.
package template

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	pmv1 "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// StoreResolver implements Resolver against the production store.
// Safe to share across goroutines — no mutable per-call state lives
// on the receiver.
type StoreResolver struct {
	store     *store.Store
	encryptor *crypto.Encryptor
	logger    *slog.Logger
}

// NewStoreResolver constructs a StoreResolver bound to the project's
// store + encryptor.
func NewStoreResolver(st *store.Store, enc *crypto.Encryptor, logger *slog.Logger) *StoreResolver {
	return &StoreResolver{store: st, encryptor: enc, logger: logger}
}

// Resolve walks the three precedence layers for deviceID. Returns a
// flat name → Value map with higher layers having already overwritten
// lower ones.
func (r *StoreResolver) Resolve(ctx context.Context, deviceID string) (Variables, error) {
	out := Variables{}

	if err := r.collectUserGroupVars(ctx, deviceID, out); err != nil {
		return nil, err
	}
	if err := r.collectDeviceGroupVars(ctx, deviceID, out); err != nil {
		return nil, err
	}
	if err := r.collectDeviceLabels(ctx, deviceID, out); err != nil {
		return nil, err
	}
	return out, nil
}

// collectUserGroupVars adds every variable defined on a user group
// directly assigned to the device. Lowest precedence layer.
func (r *StoreResolver) collectUserGroupVars(ctx context.Context, deviceID string, out Variables) error {
	groups, err := r.store.Queries().ListDeviceAssignedGroups(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("list user groups for device %s: %w", deviceID, err)
	}
	seen := map[string]string{}
	for _, g := range groups {
		raw, err := r.store.Queries().GetUserGroupVariables(ctx, g.GroupID)
		if err != nil {
			return fmt.Errorf("read variables for user group %s: %w", g.GroupID, err)
		}
		vars, err := decodeAndDecrypt(raw, r.encryptor)
		if err != nil {
			return fmt.Errorf("decode variables for user group %s: %w", g.GroupID, err)
		}
		for name, v := range vars {
			if other, dup := seen[name]; dup {
				return fmt.Errorf("variable %q is defined by multiple user groups reaching device %s (%s, %s)", name, deviceID, other, g.GroupID)
			}
			seen[name] = g.GroupID
			v.DefinedIn = []string{"user_group:" + g.GroupID}
			out[name] = v
		}
	}
	return nil
}

// collectDeviceGroupVars adds every variable defined on a device
// group the device belongs to. Shadows the user-group layer.
func (r *StoreResolver) collectDeviceGroupVars(ctx context.Context, deviceID string, out Variables) error {
	groups, err := r.store.Queries().ListGroupsForDevice(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("list device groups for device %s: %w", deviceID, err)
	}
	seen := map[string]string{}
	for _, g := range groups {
		raw, err := r.store.Queries().GetDeviceGroupVariables(ctx, g.ID)
		if err != nil {
			return fmt.Errorf("read variables for device group %s: %w", g.ID, err)
		}
		vars, err := decodeAndDecrypt(raw, r.encryptor)
		if err != nil {
			return fmt.Errorf("decode variables for device group %s: %w", g.ID, err)
		}
		for name, v := range vars {
			if other, dup := seen[name]; dup {
				return fmt.Errorf("variable %q is defined by multiple device groups reaching device %s (%s, %s)", name, deviceID, other, g.ID)
			}
			seen[name] = g.ID
			v.DefinedIn = []string{"device_group:" + g.ID}
			out[name] = v
		}
	}
	return nil
}

// collectDeviceLabels adds the device's labels as STRING-typed
// variables. Highest precedence layer — labels override any
// same-named group variable. Label values are always stringified;
// labels with names that don't match the variable grammar
// (`[a-z][a-z0-9_]*`) are still added to the map but are
// unreachable via the substitution regex.
func (r *StoreResolver) collectDeviceLabels(ctx context.Context, deviceID string, out Variables) error {
	dev, err := r.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: deviceID})
	if err != nil {
		return fmt.Errorf("read device %s: %w", deviceID, err)
	}
	if len(dev.Labels) == 0 {
		return nil
	}
	var labels map[string]string
	if err := json.Unmarshal(dev.Labels, &labels); err != nil {
		return fmt.Errorf("decode labels for device %s: %w", deviceID, err)
	}
	for name, val := range labels {
		out[name] = Value{
			Type:      pmv1.VariableType_VARIABLE_TYPE_STRING,
			Plaintext: val,
			DefinedIn: []string{"device"},
		}
	}
	return nil
}

// decodeAndDecrypt unmarshals a group's `variables` JSONB column into
// the renderer's flat name → Value map, decrypting SECRET-typed
// entries inline.
func decodeAndDecrypt(raw []byte, enc *crypto.Encryptor) (Variables, error) {
	if len(raw) == 0 {
		return Variables{}, nil
	}
	var stored []storedVariable
	if err := json.Unmarshal(raw, &stored); err != nil {
		return nil, err
	}
	out := make(Variables, len(stored))
	for _, sv := range stored {
		t := parseVariableType(sv.Type)
		plaintext := sv.Value
		if t == pmv1.VariableType_VARIABLE_TYPE_SECRET {
			pt, err := enc.Decrypt(sv.Value)
			if err != nil {
				return nil, fmt.Errorf("decrypt %s: %w", sv.Name, err)
			}
			plaintext = pt
		}
		out[sv.Name] = Value{
			Type:      t,
			Plaintext: plaintext,
		}
	}
	return out, nil
}

// storedVariable mirrors the api package's on-disk shape. Duplicated
// here to keep the import graph one-directional (api → template, not
// the reverse).
type storedVariable struct {
	Name         string   `json:"name"`
	Type         string   `json:"type"`
	Value        string   `json:"value"`
	Description  string   `json:"description,omitempty"`
	IntMin       int64    `json:"int_min,omitempty"`
	IntMax       int64    `json:"int_max,omitempty"`
	ChoiceValues []string `json:"choice_values,omitempty"`
}

// parseVariableType is the read-side mirror of the api package's
// variableTypeToString. Same duplication rationale as storedVariable.
func parseVariableType(s string) pmv1.VariableType {
	switch s {
	case "string":
		return pmv1.VariableType_VARIABLE_TYPE_STRING
	case "int":
		return pmv1.VariableType_VARIABLE_TYPE_INT
	case "bool":
		return pmv1.VariableType_VARIABLE_TYPE_BOOL
	case "hostname":
		return pmv1.VariableType_VARIABLE_TYPE_HOSTNAME
	case "path":
		return pmv1.VariableType_VARIABLE_TYPE_PATH
	case "choice":
		return pmv1.VariableType_VARIABLE_TYPE_CHOICE
	case "secret":
		return pmv1.VariableType_VARIABLE_TYPE_SECRET
	default:
		return pmv1.VariableType_VARIABLE_TYPE_UNSPECIFIED
	}
}
