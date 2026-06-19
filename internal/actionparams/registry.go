package actionparams

import (
	"fmt"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// paramsOneofName is the name of the params oneof shared — identically — by
// every message that carries action parameters: Action, SignedActionEnvelope,
// ManagedAction, CreateActionRequest, UpdateActionParamsRequest. The field
// names and wrapped message types are the same across all five; only the
// generated Go wrapper type differs. That shared shape is what lets one
// reflection helper replace the per-message switch tables.
const paramsOneofName protoreflect.Name = "params"

// paramsFieldByActionType is THE single source of truth mapping each
// params-carrying ActionType to the name of the field it occupies in the
// `params` oneof. Param-less types (REBOOT / SYNC / UNSPECIFIED) are absent —
// see isNoParamsActionType.
//
// This replaces the half-dozen hand-maintained ActionType→params-message
// switch tables that previously had to stay in lockstep across two files and
// three message types (PopulateAction / PopulateEnvelope / PopulateManagedAction,
// the extract* helpers, and actionParamsMatchType). A new ACTION_TYPE_* needs
// exactly one entry here (or classification as param-less in isNoParamsActionType);
// TestEveryActionTypeHandledInEveryParamsSwitch fails until it does.
//
// The field names are validated against the live proto descriptors of all
// three target messages by registryFieldsAreValid (exercised in the charter
// test), so a proto rename or a typo here is caught structurally rather than
// silently mis-routing params.
var paramsFieldByActionType = map[pm.ActionType]protoreflect.Name{
	pm.ActionType_ACTION_TYPE_PACKAGE:      "package",
	pm.ActionType_ACTION_TYPE_APP_IMAGE:    "app",
	pm.ActionType_ACTION_TYPE_DEB:          "app",
	pm.ActionType_ACTION_TYPE_RPM:          "app",
	pm.ActionType_ACTION_TYPE_FLATPAK:      "flatpak",
	pm.ActionType_ACTION_TYPE_SHELL:        "shell",
	pm.ActionType_ACTION_TYPE_SCRIPT_RUN:   "shell",
	pm.ActionType_ACTION_TYPE_SERVICE:      "service",
	pm.ActionType_ACTION_TYPE_FILE:         "file",
	pm.ActionType_ACTION_TYPE_UPDATE:       "update",
	pm.ActionType_ACTION_TYPE_REPOSITORY:   "repository",
	pm.ActionType_ACTION_TYPE_DIRECTORY:    "directory",
	pm.ActionType_ACTION_TYPE_USER:         "user",
	pm.ActionType_ACTION_TYPE_GROUP:        "group",
	pm.ActionType_ACTION_TYPE_SSH:          "ssh",
	pm.ActionType_ACTION_TYPE_SSHD:         "sshd",
	pm.ActionType_ACTION_TYPE_ADMIN_POLICY: "admin_policy",
	pm.ActionType_ACTION_TYPE_LPS:          "lps",
	pm.ActionType_ACTION_TYPE_ENCRYPTION:   "encryption",
	pm.ActionType_ACTION_TYPE_WIFI:         "wifi",
	pm.ActionType_ACTION_TYPE_AGENT_UPDATE: "agent_update",
}

// populateParamsOneof unmarshals paramsJSON into the params-oneof field of msg
// that corresponds to actionType, using the shared registry. msg must be a
// message that carries the standard `params` oneof (Action, SignedActionEnvelope,
// ManagedAction, …). It is the single implementation behind PopulateAction,
// PopulateEnvelope, and PopulateManagedAction.
//
// Fail-closed identically to the switches it replaced: a protojson parse
// failure OR an unhandled action type returns an error so callers never
// dispatch/sign an action with empty/nil params (#368). Param-less instant
// types and the zero value leave the oneof unset and return nil.
func populateParamsOneof(msg proto.Message, actionType pm.ActionType, paramsJSON []byte) error {
	if isNoParamsActionType(actionType) {
		return nil
	}
	fieldName, ok := paramsFieldByActionType[actionType]
	if !ok {
		return fmt.Errorf("actionparams: unhandled action type %d (%s)", int32(actionType), actionType)
	}
	m := msg.ProtoReflect()
	fd := m.Descriptor().Fields().ByName(fieldName)
	if fd == nil || fd.Message() == nil {
		return fmt.Errorf("actionparams: %s has no params message field %q for action type %s",
			m.Descriptor().FullName(), fieldName, actionType)
	}
	// NewField allocates a fresh, mutable sub-message of the field's concrete
	// generated type; unmarshal into it then set it on the oneof.
	sub := m.NewField(fd)
	if err := unmarshalOpts.Unmarshal(paramsJSON, sub.Message().Interface()); err != nil {
		return fmt.Errorf("actionparams: unmarshal %s params: %w", actionType, err)
	}
	m.Set(fd, sub)
	return nil
}

// ExtractParamsMsg returns the concrete params sub-message populated in the
// `params` oneof of msg (e.g. *pm.ShellParams), or nil if the oneof is unset or
// msg carries no such oneof. Replaces the per-message extract* switch tables
// (Action / CreateActionRequest / UpdateActionParamsRequest) with one reflective
// WhichOneof walk — the inverse of populateParamsOneof.
func ExtractParamsMsg(msg proto.Message) proto.Message {
	if msg == nil {
		return nil
	}
	m := msg.ProtoReflect()
	od := m.Descriptor().Oneofs().ByName(paramsOneofName)
	if od == nil {
		return nil
	}
	fd := m.WhichOneof(od)
	if fd == nil || fd.Message() == nil {
		return nil
	}
	return m.Get(fd).Message().Interface()
}

// ParamsMatchType reports whether the params oneof populated on msg matches the
// declared actionType. It replaces the hand-written actionParamsMatchType
// switch: the dispatch path trusts action.Type and action.Params independently,
// and without this guard a caller could route a Type=USER action through the
// Ssh oneof and have the agent receive a USER action whose params bytes are an
// Ssh proto.
//
// Truth table preserved from the original switch:
//   - a params-carrying type matches iff the set oneof field is its registered field;
//   - ACTION_TYPE_UPDATE additionally matches when the oneof is unset (an update
//     with no params kicks off whatever the agent considers an update);
//   - param-less / unknown types never match here (they don't carry a params oneof).
func ParamsMatchType(msg proto.Message, actionType pm.ActionType) bool {
	want, ok := paramsFieldByActionType[actionType]
	if !ok {
		return false
	}
	if msg == nil {
		return actionType == pm.ActionType_ACTION_TYPE_UPDATE
	}
	m := msg.ProtoReflect()
	od := m.Descriptor().Oneofs().ByName(paramsOneofName)
	if od == nil {
		return false
	}
	set := m.WhichOneof(od)
	if actionType == pm.ActionType_ACTION_TYPE_UPDATE && set == nil {
		return true
	}
	return set != nil && set.Name() == want
}

// registryFieldsAreValid reports whether every field name in
// paramsFieldByActionType exists as a message field in the params oneof of each
// of the given messages — i.e. the registry is consistent with the live proto
// descriptors. Used by the charter test to catch a proto rename or a typo in
// the registry structurally. Returns the first inconsistency for diagnosis.
func registryFieldsAreValid(msgs ...proto.Message) (ok bool, detail string) {
	for _, msg := range msgs {
		m := msg.ProtoReflect()
		fields := m.Descriptor().Fields()
		for at, name := range paramsFieldByActionType {
			fd := fields.ByName(name)
			if fd == nil {
				return false, fmt.Sprintf("%s missing params field %q (for %s)", m.Descriptor().FullName(), name, at)
			}
			if fd.Message() == nil {
				return false, fmt.Sprintf("%s field %q is not a message field (for %s)", m.Descriptor().FullName(), name, at)
			}
			if fd.ContainingOneof() == nil || fd.ContainingOneof().Name() != paramsOneofName {
				return false, fmt.Sprintf("%s field %q is not part of the %q oneof (for %s)", m.Descriptor().FullName(), name, paramsOneofName, at)
			}
		}
	}
	return true, ""
}
