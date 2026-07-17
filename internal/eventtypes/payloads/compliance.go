package payloads

import "encoding/json"

// ComplianceResultUpdated is the wire shape for the ComplianceResultUpdated
// event the inbox worker emits on the "compliance" stream when a compliance
// action's detection output comes back from a device.
//
// DetectionOutput rides as a JSONB blob in the same {stdout,stderr,exit_code}
// shape as the execution events, produced by RawCommandOutput. The emit site
// funnels it through commandOutputPayload, which caps each stream at
// maxCommandOutputBytes (audit F-33) — the legacy commandOutputToMap emit
// this replaced wrote the detection output verbatim, so a compromised or
// buggy agent could push an unbounded blob into events.data on this path.
//
// Field presence matches the historical map[string]any emit exactly:
// device_id / action_id / action_name / compliant are always written;
// detection_output is dropped only when the CommandOutput is nil (which the
// emit guard already precludes). The projector's decoder
// (complianceResultUpdatedRaw) reads these same keys.
type ComplianceResultUpdated struct {
	DeviceID        string          `json:"device_id"`
	ActionID        string          `json:"action_id"`
	ActionName      string          `json:"action_name"`
	Compliant       bool            `json:"compliant"`
	DetectionOutput json.RawMessage `json:"detection_output,omitempty"`
}
