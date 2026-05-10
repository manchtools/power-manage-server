package payloads

// GroupVariableSet is the wire shape for the non-secret variable
// create / update event. Full-replace semantics — the variable's
// post-write shape is captured in entirety so projectors / replays
// don't have to reach back to the queries layer to learn the
// authoritative value.
//
// GroupType is "device" or "user". The split between secret and
// non-secret event types (GroupVariableSet vs GroupSecretVariableSet)
// keeps the audit-redactor schema dispatch trivial: scrub the value
// field on the secret variant only, leave non-secret payloads visible
// for operator triage.
type GroupVariableSet struct {
	GroupType    string   `json:"group_type"`
	GroupID      string   `json:"group_id"`
	Name         string   `json:"name"`
	Type         string   `json:"type"`
	Value        string   `json:"value"`
	Description  string   `json:"description,omitempty"`
	IntMin       int64    `json:"int_min,omitempty"`
	IntMax       int64    `json:"int_max,omitempty"`
	ChoiceValues []string `json:"choice_values,omitempty"`
}

// GroupVariableDeleted is the wire shape for the non-secret variable
// delete event. Idempotent — emitted even when the variable was
// already absent so the audit log records the operator's intent.
type GroupVariableDeleted struct {
	GroupType string `json:"group_type"`
	GroupID   string `json:"group_id"`
	Name      string `json:"name"`
}

// GroupSecretVariableSet is the wire shape for the secret variable
// create / update / rotate event. Ciphertext is the AES-GCM payload
// produced by internal/crypto.Encrypt; the audit redactor scrubs it
// before the event reaches ListAuditEvents (see the
// eventRedactionSchemas map in audit_handler.go).
//
// No Type / IntMin / IntMax / ChoiceValues fields by design — secret
// variables are always plain strings (their type is implicitly
// VARIABLE_TYPE_SECRET as conveyed by the event-type constant
// GroupSecretVariableSet itself), and the per-type metadata that
// makes sense for INT / CHOICE doesn't apply. Consumers that need to
// surface "this row is a secret" can rely on the event-type discriminator
// rather than reading Type from the payload.
type GroupSecretVariableSet struct {
	GroupType   string `json:"group_type"`
	GroupID     string `json:"group_id"`
	Name        string `json:"name"`
	Ciphertext  string `json:"ciphertext"`
	Description string `json:"description,omitempty"`
}

// GroupSecretVariableDeleted is the wire shape for the secret variable
// delete event. Same shape as GroupVariableDeleted — duplicated to
// keep the secret-permission audit-trail path explicit.
type GroupSecretVariableDeleted struct {
	GroupType string `json:"group_type"`
	GroupID   string `json:"group_id"`
	Name      string `json:"name"`
}
