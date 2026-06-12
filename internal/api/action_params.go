// Package api file action_params.go — params serialization helper
// split out of action_handler.go (audit F005). The per-RPC oneof
// extraction that used to live here (extractActionParamsMsg and its
// Create/Update siblings) collapsed into the single reflective
// actionparams.ExtractParamsMsg walk — the params oneof is identical
// across Action / CreateActionRequest / UpdateActionParamsRequest, so
// one WhichOneof replaces three hand-maintained switches.
package api

import (
	"encoding/json"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/manchtools/power-manage/server/internal/actionparams"
)

// serializeProtoParams renders a params proto message into the
// map[string]any shape used by event-payload JSONB. A nil message
// (no params oneof set) serialises to an empty object, never a bare
// "null". Marshalling goes through actionparams.MarshalActionParams so
// the canonical protojson options (EmitUnpopulated) apply uniformly.
func serializeProtoParams(msg proto.Message) (map[string]any, error) {
	if msg == nil {
		return map[string]any{}, nil
	}
	data, err := actionparams.MarshalActionParams(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal params: %w", err)
	}
	var params map[string]any
	if err := json.Unmarshal(data, &params); err != nil {
		return nil, fmt.Errorf("unmarshal params to map: %w", err)
	}
	return params, nil
}

// rawParamsOrEmpty returns the stored params JSONB as a json.RawMessage,
// substituting `{}` for empty or malformed input. The stored column is JSONB
// so it is normally valid; the guard is defence-in-depth so the dispatch sign
// site never carries empty/invalid params into a signature the agent rejects.
func rawParamsOrEmpty(data []byte) json.RawMessage {
	if !json.Valid(data) {
		return json.RawMessage("{}")
	}
	return json.RawMessage(data)
}

// marshalInlineParams serialises an inline-action params oneof message into the
// json.RawMessage form carried by the signed envelope and the typed
// ExecutionCreated/Scheduled payload. A nil message (e.g. ACTION_TYPE_UPDATE
// with no params) marshals to `{}` rather than erroring — matching the
// historical empty-params shape — so the inline-update path stays valid.
func marshalInlineParams(msg proto.Message) (json.RawMessage, error) {
	if msg == nil {
		return json.RawMessage("{}"), nil
	}
	b, err := actionparams.MarshalActionParams(msg)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}
