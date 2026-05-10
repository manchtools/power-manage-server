package payloads

// CompliancePolicyCreated is the wire shape for CompliancePolicyCreated.
type CompliancePolicyCreated struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// CompliancePolicyRenamed is the wire shape for CompliancePolicyRenamed.
type CompliancePolicyRenamed struct {
	Name string `json:"name"`
}

// CompliancePolicyDescriptionUpdated is the wire shape for
// CompliancePolicyDescriptionUpdated.
type CompliancePolicyDescriptionUpdated struct {
	Description string `json:"description"`
}

// CompliancePolicyRuleAdded is the wire shape for the AddRule event.
// action_name is denormalised onto the audit payload so the audit
// listing can render rules without a follow-up actions_projection
// lookup; the projector reads only action_id + grace_period_hours
// when re-applying the rule to the policy_rules_projection.
type CompliancePolicyRuleAdded struct {
	ActionID         string `json:"action_id"`
	ActionName       string `json:"action_name"`
	GracePeriodHours int32  `json:"grace_period_hours"`
}

// CompliancePolicyRuleRemoved is the wire shape for RemoveRule.
type CompliancePolicyRuleRemoved struct {
	ActionID string `json:"action_id"`
}

// CompliancePolicyRuleUpdated is the wire shape for UpdateRule. Only
// the grace_period_hours can change; action_id is the key.
type CompliancePolicyRuleUpdated struct {
	ActionID         string `json:"action_id"`
	GracePeriodHours int32  `json:"grace_period_hours"`
}
