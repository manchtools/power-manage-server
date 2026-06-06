package api

import (
	"context"
	"encoding/json"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// AuditHandler handles audit log RPCs.
type AuditHandler struct {
	store  *store.Store
	logger *slog.Logger
}

// NewAuditHandler creates a new audit handler.
func NewAuditHandler(st *store.Store, logger *slog.Logger) *AuditHandler {
	return &AuditHandler{store: st, logger: logger}
}

// ListAuditEvents returns a paginated list of audit events.
func (h *AuditHandler) ListAuditEvents(ctx context.Context, req *connect.Request[pm.ListAuditEventsRequest]) (*connect.Response[pm.ListAuditEventsResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	pageSize, offset, err := parsePagination(int32(req.Msg.PageSize), req.Msg.PageToken)
	if err != nil {
		return nil, err
	}

	events, err := h.store.Queries().ListAuditEvents(ctx, db.ListAuditEventsParams{
		Column1: req.Msg.ActorId,
		Column2: req.Msg.StreamType,
		Column3: req.Msg.EventType,
		Limit:   pageSize,
		Offset:  offset,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to list audit events")
	}

	count, err := h.store.Queries().CountAuditEvents(ctx, db.CountAuditEventsParams{
		Column1: req.Msg.ActorId,
		Column2: req.Msg.StreamType,
		Column3: req.Msg.EventType,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to count audit events")
	}

	nextPageToken := buildNextPageToken(int32(len(events)), offset, pageSize, count)

	protoEvents := make([]*pm.AuditEvent, len(events))
	for i, e := range events {
		protoEvents[i] = eventToProto(e)
	}

	return connect.NewResponse(&pm.ListAuditEventsResponse{
		Events:        protoEvents,
		NextPageToken: nextPageToken,
		TotalCount:    int32(count),
	}), nil
}

// redactionSchema describes which JSON paths inside an event payload
// must be scrubbed before the payload reaches ListAuditEvents.
//
// Schema-aware (per #project_2026_06_design_decisions): the redactor
// is dispatched on the event's StreamType + EventType (and, for action
// events, the embedded `params.type` action-type code) and applies
// only the known-secret paths for that exact event shape. A recursive
// "walk-and-match-by-key-name" strategy was REJECTED because (a) it
// fails open on every payload shape it doesn't recognise, (b) it
// scrubs unrelated keys that happen to share a name (e.g. a future
// `script:` field that's a script *name*, not contents), and (c) it
// admits the audit log to fields it was never designed to expose.
//
// Each schema entry is a simple JSON path (dot-separated keys). The
// redactor descends maps and replaces the leaf with "[REDACTED]". If
// any segment refers to an array, it scrubs every element of that
// array at the next path step.
type redactionSchema struct {
	// paths is the set of dot-separated paths to scrub. Empty entries
	// are skipped. Wildcard "[]" denotes "for every element of this
	// array, then continue with the remainder of the path".
	paths []string
}

// eventRedactionSchemas maps (StreamType, EventType) to its
// redactionSchema. EventTypes use the typed-constant strings from
// internal/eventtypes for compile-time-checked spelling.
//
// Action streams need additional dispatch on the action-type code
// (`params.type`); see actionRedactionSchemas below.
var eventRedactionSchemas = map[string]map[string]redactionSchema{
	"identity_provider": {
		string(eventtypes.IdentityProviderCreated): {paths: []string{"client_secret_encrypted"}},
		string(eventtypes.IdentityProviderUpdated): {paths: []string{"client_secret_encrypted"}},
	},
	"user": {
		string(eventtypes.UserPasswordChanged):  {paths: []string{"password_hash"}},
		string(eventtypes.UserCreatedWithRoles): {paths: []string{"password_hash"}},
	},
	"lps_password": {
		// LPS rotations carry an array of {username, password}
		// records under "rotations[].password".
		"LpsPasswordRotated": {paths: []string{"rotations[].password"}},
	},
	"luks_key": {
		// LUKS rotations are emitted via the internal handler with
		// `passphrase` at the top level.
		"LuksKeyRotated": {paths: []string{"passphrase"}},
	},
}

// actionRedactionSchemas maps an action's `params.type` value to the
// redactionSchema that should be applied to its `params:` subtree.
// The action-emit shape is `{ type: "...", name: "...", params: { ... } }`,
// and `params:` is produced by serializeProtoParams (protojson with
// UseProtoNames=false), so the path segments are camelCase to match
// the wire format — NOT the proto field's snake_case schema name.
// A path that uses snake_case here will silently miss the field in
// production (audit F-34 — the prior schema had this exact bug for
// every secret-bearing action type, leaking customConfig, gpgKey, and
// presharedKey through the audit log).
//
// One schema per action type that carries secret-bearing parameters:
//
//   - SHELL        -> params.script + params.detectionScript
//     (both can hold full shell bodies)
//   - FILE         -> params.content (file body, may contain secrets)
//   - ADMIN_POLICY -> params.customConfig (sudoers / doas.conf fragment;
//     proto field renamed from unit_content)
//   - REPOSITORY   -> params.gpgKey (GPG signing key material; URL form
//     params.gpgKeyUrl is intentionally NOT scrubbed)
//   - ENCRYPTION   -> params.presharedKey (LUKS bootstrap entropy)
//
// Action types not in this map have no params secrets to scrub
// (PACKAGE, UPDATE, REBOOT, SYNC, USER, GROUP, SSH, SSHD,
// SYSTEMD/SERVICE, DIRECTORY, APP_IMAGE, DEB, RPM, FLATPAK, LPS).
// LpsParams in particular looks like a hit but is not — the actual
// rotated password is generated agent-side and surfaces via the
// LpsPasswordRotated event (covered by eventRedactionSchemas), not
// via the dispatch action_params.
var actionRedactionSchemas = map[string]redactionSchema{
	"ACTION_TYPE_SHELL":        {paths: []string{"params.script", "params.detectionScript"}},
	"ACTION_TYPE_FILE":         {paths: []string{"params.content"}},
	"ACTION_TYPE_ADMIN_POLICY": {paths: []string{"params.customConfig"}},
	"ACTION_TYPE_REPOSITORY":   {paths: []string{"params.gpgKey"}},
	"ACTION_TYPE_ENCRYPTION":   {paths: []string{"params.presharedKey"}},
}

// redactEventData removes sensitive fields from a serialized event
// payload before returning it through the audit log API. The
// schema-aware dispatch (see eventRedactionSchemas /
// actionRedactionSchemas) is intentional: a recursive walk would
// overscrub legitimate fields and fail open on unknown shapes.
//
// The function is fail-closed: if the payload doesn't decode as a
// JSON object, the original bytes are returned (no payload to
// redact); if a known schema specifies a path that's not present in
// this particular event (e.g. an old IdentityProviderUpdated emitted
// before client_secret_encrypted was added), that path is silently
// skipped — there's nothing to scrub.
func redactEventData(streamType, eventType string, data []byte) string {
	if len(data) == 0 {
		return string(data)
	}

	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		return string(data)
	}

	schema, ok := schemaFor(streamType, eventType, payload)
	if !ok {
		return string(data)
	}

	changed := false
	for _, path := range schema.paths {
		if path == "" {
			continue
		}
		if redactPath(payload, path) {
			changed = true
		}
	}

	if !changed {
		return string(data)
	}

	out, err := json.Marshal(payload)
	if err != nil {
		return string(data)
	}
	return string(out)
}

// schemaFor selects the redactionSchema for an event. For action
// streams it dispatches on the action-type code embedded at
// `payload.type`; for every other stream it looks up
// (streamType, eventType) directly.
func schemaFor(streamType, eventType string, payload map[string]any) (redactionSchema, bool) {
	if streamType == "action" {
		typeCode, _ := payload["type"].(string)
		s, ok := actionRedactionSchemas[typeCode]
		return s, ok
	}
	if streamSchemas, ok := eventRedactionSchemas[streamType]; ok {
		s, ok := streamSchemas[eventType]
		return s, ok
	}
	return redactionSchema{}, false
}

// redactPath descends the dot-separated path inside a decoded JSON
// payload and replaces the leaf with "[REDACTED]". The "[]" segment
// applies the remainder of the path to every element of the array at
// that point. Returns true if at least one leaf was scrubbed.
//
// The implementation is iterative (not recursive on map keys) so it
// only touches the path the schema declares — sibling keys are never
// inspected. This is the design contract that makes schema-aware
// safer than a generic walker.
func redactPath(payload any, path string) bool {
	segments := splitPath(path)
	return applyRedaction(payload, segments)
}

// applyRedaction walks the segments and either redacts the leaf or
// recurses one level into the next map / array. Returns true if the
// leaf was reached and replaced.
func applyRedaction(node any, segments []string) bool {
	if len(segments) == 0 {
		return false
	}
	seg := segments[0]
	rest := segments[1:]

	if seg == "[]" {
		arr, ok := node.([]any)
		if !ok {
			return false
		}
		changed := false
		for _, item := range arr {
			if applyRedaction(item, rest) {
				changed = true
			}
		}
		return changed
	}

	m, ok := node.(map[string]any)
	if !ok {
		return false
	}
	if _, present := m[seg]; !present {
		return false
	}
	if len(rest) == 0 {
		m[seg] = "[REDACTED]"
		return true
	}
	return applyRedaction(m[seg], rest)
}

// splitPath turns "params.rotations[].password" into
// ["params", "rotations", "[]", "password"]. The "[]" suffix on a
// segment is split off and pushed as its own array-step.
func splitPath(path string) []string {
	var out []string
	start := 0
	for i := 0; i < len(path); i++ {
		switch path[i] {
		case '.':
			if i > start {
				out = append(out, splitArraySuffix(path[start:i])...)
			}
			start = i + 1
		}
	}
	if start < len(path) {
		out = append(out, splitArraySuffix(path[start:])...)
	}
	return out
}

// splitArraySuffix peels a trailing "[]" off a segment so the array
// step becomes its own segment.
func splitArraySuffix(seg string) []string {
	if len(seg) >= 2 && seg[len(seg)-2:] == "[]" {
		base := seg[:len(seg)-2]
		if base == "" {
			return []string{"[]"}
		}
		return []string{base, "[]"}
	}
	return []string{seg}
}

func eventToProto(e db.Event) *pm.AuditEvent {
	event := &pm.AuditEvent{
		Id:         ulid.ULID(e.ID).String(),
		EventType:  e.EventType,
		StreamType: e.StreamType,
		StreamId:   e.StreamID,
		ActorType:  e.ActorType,
		ActorId:    e.ActorID,
		Data:       redactEventData(e.StreamType, e.EventType, e.Data),
	}

	event.OccurredAt = timestamppb.New(e.OccurredAt)

	return event
}
