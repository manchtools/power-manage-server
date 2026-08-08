package store_test

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/actionparams"
	"github.com/manchtools/power-manage/server/internal/authoring"
	"github.com/manchtools/power-manage/server/internal/compliance"
	"github.com/manchtools/power-manage/server/internal/delivery"
	"github.com/manchtools/power-manage/server/internal/execution"
)

// complianceIngestFixture drives the real ingestion path: an agent result
// arrives at the execution service and the answer is read back through the
// mounted compliance RPCs. No test in this package writes compliance_results
// or compliance_policy_evaluation itself, so a missing writer cannot be masked
// by a manufactured row. TestComplianceStateHasOneWriter guards that.
type complianceIngestFixture struct {
	*deviceHandlerFixture
	service *execution.Service
	ctx     context.Context
}

func newComplianceIngestFixture(t *testing.T) *complianceIngestFixture {
	t.Helper()
	f := newDeviceHandlerFixture(t)
	return &complianceIngestFixture{
		deviceHandlerFixture: f,
		service:              execution.New(execution.Config{Store: f.store, Now: func() time.Time { return f.now }}),
		ctx:                  f.actor("GetDeviceCompliance", "GetDeviceCompliancePolicyStatus"),
	}
}

// complianceAction authors a detection-only SHELL action exactly as the
// authoring layer would: is_compliance with a non-empty detection script.
func (f *complianceIngestFixture) complianceAction(t *testing.T, name string) string {
	t.Helper()
	return f.shellAction(t, name, &pmv1.ShellParams{DetectionScript: "test -f /etc/os-release", IsCompliance: true})
}

func (f *complianceIngestFixture) shellAction(t *testing.T, name string, shell *pmv1.ShellParams) string {
	t.Helper()
	id := newID()
	params, err := actionparams.MarshalActionParams(shell)
	require.NoError(t, err)
	_, err = f.raw.Exec(context.Background(), `
		INSERT INTO actions (id, name, action_type, params, created_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		id, name, int32(pmv1.ActionType_ACTION_TYPE_SHELL), string(params), f.now, f.actorID)
	require.NoError(t, err)
	return id
}

func (f *complianceIngestFixture) policy(t *testing.T, name string, rules map[string]int32) string {
	t.Helper()
	id := newID()
	_, err := f.raw.Exec(context.Background(), `
		INSERT INTO compliance_policies (id, name, created_at, created_by)
		VALUES ($1, $2, $3, $4)`, id, name, f.now, f.actorID)
	require.NoError(t, err)
	for actionID, grace := range rules {
		_, err = f.raw.Exec(context.Background(), `
			INSERT INTO compliance_policy_rules (policy_id, action_id, grace_period_hours, added_at)
			VALUES ($1, $2, $3, $4)`, id, actionID, grace, f.now)
		require.NoError(t, err)
	}
	return id
}

// report runs one occurrence of an action on a device end to end: a delivery
// the agent acknowledged, an execution row, and the agent's ActionResult
// applied through the real execution service.
func (f *complianceIngestFixture) report(
	t *testing.T, deviceID, actionID string,
	status pmv1.ExecutionStatus, compliant bool,
	detection *pmv1.CommandOutput, at time.Time,
) {
	t.Helper()
	occurrenceID, deliveryID, manifestID := newID(), newID(), newID()
	manifest, err := protojson.Marshal(&pmv1.Manifest{
		ManifestId: manifestID,
		Occurrences: []*pmv1.ManifestOccurrence{{
			OccurrenceId: occurrenceID,
			Action: &pmv1.Action{
				Id: &pmv1.ActionId{Value: actionID}, Type: pmv1.ActionType_ACTION_TYPE_SHELL,
			},
		}},
	})
	require.NoError(t, err)
	_, err = f.raw.Exec(context.Background(), `
		INSERT INTO deliveries (
			delivery_id, device_id, manifest_id, manifest, state,
			created_at, available_at, pushed_at, acked_receipt_at
		) VALUES ($1, $2, $3, $4, $5, $6, $6, $6, $6)`,
		deliveryID, deviceID, manifestID, string(manifest), delivery.StateAckedReceipt, f.now)
	require.NoError(t, err)
	_, err = f.raw.Exec(context.Background(), `
		INSERT INTO executions (
			id, delivery_id, device_id, action_id, action_type, desired_state, params,
			timeout_seconds, status, created_at, created_by_type, created_by_id
		) VALUES ($1, $2, $3, $4, $5, 0, '{}', 300, 'pending', $6, 'user', $7)`,
		occurrenceID, deliveryID, deviceID, actionID,
		int32(pmv1.ActionType_ACTION_TYPE_SHELL), f.now, f.actorID)
	require.NoError(t, err)

	result := &pmv1.ActionResult{
		ActionId: &pmv1.ActionId{Value: actionID}, Status: status,
		DeliveryId: deliveryID, OccurrenceId: occurrenceID,
		CompletedAt: timestamppb.New(at), Compliant: compliant, DetectionOutput: detection,
	}
	require.NoError(t, f.service.ApplyActionResult(context.Background(), deviceID, result))
}

func (f *complianceIngestFixture) compliance(t *testing.T, deviceID string) *pmv1.GetDeviceComplianceResponse {
	t.Helper()
	response, err := f.handlers.GetDeviceCompliance(f.ctx,
		connect.NewRequest(&pmv1.GetDeviceComplianceRequest{DeviceId: deviceID}))
	require.NoError(t, err)
	return response.Msg
}

func (f *complianceIngestFixture) policyStatus(t *testing.T, deviceID string) *pmv1.GetDeviceCompliancePolicyStatusResponse {
	t.Helper()
	response, err := f.handlers.GetDeviceCompliancePolicyStatus(f.ctx,
		connect.NewRequest(&pmv1.GetDeviceCompliancePolicyStatusRequest{DeviceId: deviceID}))
	require.NoError(t, err)
	return response.Msg
}

func (f *complianceIngestFixture) searchStatus(t *testing.T, deviceID string) string {
	t.Helper()
	var status string
	require.NoError(t, f.raw.QueryRow(context.Background(), `
		SELECT json_extract(fields, '$.compliance_status') FROM search_documents
		WHERE scope = 'devices' AND entity_id = $1`, deviceID).Scan(&status))
	return status
}

// A device that ran a compliance check and failed it must report failing —
// through the RPC an auditor reads, and in the search document the fleet list
// renders. Reporting UNKNOWN with zero checks is a confident wrong answer.
func TestComplianceIngest_FailedCheckIsReadableThroughTheRPCs(t *testing.T) {
	f := newComplianceIngestFixture(t)
	actionID := f.complianceAction(t, "os-release present")
	policyID := f.policy(t, "baseline", map[string]int32{actionID: 0})

	f.report(t, f.groupID, actionID, pmv1.ExecutionStatus_EXECUTION_STATUS_FAILED, false,
		&pmv1.CommandOutput{ExitCode: 1, Stderr: "missing"}, f.now)

	compliance := f.compliance(t, f.groupID)
	assert.Equal(t, pmv1.ComplianceStatus_COMPLIANCE_STATUS_NON_COMPLIANT, compliance.Status)
	require.Len(t, compliance.Checks, 1)
	assert.Equal(t, actionID, compliance.Checks[0].ActionId)
	assert.Equal(t, "os-release present", compliance.Checks[0].ActionName)
	assert.False(t, compliance.Checks[0].Compliant)
	require.NotNil(t, compliance.Checks[0].DetectionOutput)
	assert.Equal(t, int32(1), compliance.Checks[0].DetectionOutput.ExitCode)
	assert.True(t, compliance.Checks[0].CheckedAt.AsTime().Equal(f.now))

	status := f.policyStatus(t, f.groupID)
	assert.Equal(t, pmv1.ComplianceStatus_COMPLIANCE_STATUS_NON_COMPLIANT, status.OverallStatus)
	require.Len(t, status.Policies, 1)
	assert.Equal(t, policyID, status.Policies[0].PolicyId)
	assert.Equal(t, pmv1.ComplianceStatus_COMPLIANCE_STATUS_NON_COMPLIANT, status.Policies[0].Status)
	require.Len(t, status.Policies[0].Rules, 1)
	assert.Equal(t, pmv1.ComplianceStatus_COMPLIANCE_STATUS_NON_COMPLIANT, status.Policies[0].Rules[0].Status)
	assert.False(t, status.Policies[0].Rules[0].Compliant)
	require.NotNil(t, status.Policies[0].Rules[0].FirstFailedAt)
	assert.True(t, status.Policies[0].Rules[0].FirstFailedAt.AsTime().Equal(f.now))

	assert.Equal(t, "2", f.searchStatus(t, f.groupID),
		"the device search document must carry the real status, not a default")

	device, err := f.store.GetDevice(context.Background(), f.groupID)
	require.NoError(t, err)
	assert.Equal(t, int32(1), device.ComplianceTotal)
	assert.Equal(t, int32(0), device.CompliancePassing)
	require.NotNil(t, device.ComplianceCheckedAt)
	assert.True(t, device.ComplianceCheckedAt.Equal(f.now))

	assert.Contains(t, auditActions(t, f.raw, "device", f.groupID), "COMPLIANCE",
		"a compliance state change is a mutation and needs audit evidence")
}

// Never-checked and checked-and-failed must not collapse into the same answer.
func TestComplianceIngest_UncheckedDeviceStaysUnknown(t *testing.T) {
	f := newComplianceIngestFixture(t)
	actionID := f.complianceAction(t, "os-release present")
	f.policy(t, "baseline", map[string]int32{actionID: 0})

	unchecked := f.compliance(t, f.directID)
	assert.Equal(t, pmv1.ComplianceStatus_COMPLIANCE_STATUS_UNKNOWN, unchecked.Status)
	assert.Empty(t, unchecked.Checks)
	assert.Empty(t, f.policyStatus(t, f.directID).Policies)

	f.report(t, f.groupID, actionID, pmv1.ExecutionStatus_EXECUTION_STATUS_SUCCESS, true,
		&pmv1.CommandOutput{ExitCode: 0, Stdout: "ok"}, f.now)

	checked := f.compliance(t, f.groupID)
	assert.Equal(t, pmv1.ComplianceStatus_COMPLIANCE_STATUS_COMPLIANT, checked.Status)
	require.Len(t, checked.Checks, 1)
	assert.True(t, checked.Checks[0].Compliant)
	assert.Equal(t, "1", f.searchStatus(t, f.groupID))

	still := f.compliance(t, f.directID)
	assert.Equal(t, pmv1.ComplianceStatus_COMPLIANCE_STATUS_UNKNOWN, still.Status,
		"one device's finding must not be attributed to another")
	assert.Empty(t, still.Checks)
	assert.Equal(t, "0", f.searchStatus(t, f.directID))
}

// The grace period runs from the first failure, survives a re-check, and is
// discarded the moment the device comes back into compliance.
func TestComplianceIngest_GracePeriodTracksRecheckAndRecovery(t *testing.T) {
	f := newComplianceIngestFixture(t)
	actionID := f.complianceAction(t, "graced check")
	f.policy(t, "baseline", map[string]int32{actionID: 4})
	firstFailure := f.now.Add(-3 * time.Hour)

	f.report(t, f.groupID, actionID, pmv1.ExecutionStatus_EXECUTION_STATUS_FAILED, false,
		&pmv1.CommandOutput{ExitCode: 1}, firstFailure)
	rule := f.policyStatus(t, f.groupID).Policies[0].Rules[0]
	assert.Equal(t, pmv1.ComplianceStatus_COMPLIANCE_STATUS_IN_GRACE_PERIOD, rule.Status)
	require.NotNil(t, rule.FirstFailedAt)
	assert.True(t, rule.FirstFailedAt.AsTime().Equal(firstFailure))
	assert.Equal(t, pmv1.ComplianceStatus_COMPLIANCE_STATUS_IN_GRACE_PERIOD,
		f.compliance(t, f.groupID).Status)
	assert.Equal(t, "3", f.searchStatus(t, f.groupID))

	// Still failing two hours later: inside the four-hour grace, and the clock
	// must not restart on the re-check.
	f.report(t, f.groupID, actionID, pmv1.ExecutionStatus_EXECUTION_STATUS_FAILED, false,
		&pmv1.CommandOutput{ExitCode: 1}, firstFailure.Add(2*time.Hour))
	rule = f.policyStatus(t, f.groupID).Policies[0].Rules[0]
	assert.Equal(t, pmv1.ComplianceStatus_COMPLIANCE_STATUS_IN_GRACE_PERIOD, rule.Status)
	assert.True(t, rule.FirstFailedAt.AsTime().Equal(firstFailure))

	// Still failing after the grace expires.
	f.report(t, f.groupID, actionID, pmv1.ExecutionStatus_EXECUTION_STATUS_FAILED, false,
		&pmv1.CommandOutput{ExitCode: 1}, firstFailure.Add(5*time.Hour))
	rule = f.policyStatus(t, f.groupID).Policies[0].Rules[0]
	assert.Equal(t, pmv1.ComplianceStatus_COMPLIANCE_STATUS_NON_COMPLIANT, rule.Status)
	assert.True(t, rule.FirstFailedAt.AsTime().Equal(firstFailure))
	assert.Equal(t, pmv1.ComplianceStatus_COMPLIANCE_STATUS_NON_COMPLIANT,
		f.compliance(t, f.groupID).Status)

	// Recovery clears the failure entirely.
	f.report(t, f.groupID, actionID, pmv1.ExecutionStatus_EXECUTION_STATUS_SUCCESS, true,
		&pmv1.CommandOutput{ExitCode: 0}, firstFailure.Add(6*time.Hour))
	rule = f.policyStatus(t, f.groupID).Policies[0].Rules[0]
	assert.Equal(t, pmv1.ComplianceStatus_COMPLIANCE_STATUS_COMPLIANT, rule.Status)
	assert.Nil(t, rule.FirstFailedAt)
	compliance := f.compliance(t, f.groupID)
	assert.Equal(t, pmv1.ComplianceStatus_COMPLIANCE_STATUS_COMPLIANT, compliance.Status)
	require.Len(t, compliance.Checks, 1)
	assert.True(t, compliance.Checks[0].Compliant)
	assert.Equal(t, "1", f.searchStatus(t, f.groupID))
}

// Detection-only means the only evidence of compliance is a detection script
// that ran and passed. Every other terminal outcome fails closed.
func TestComplianceIngest_FailsClosedWhenDetectionNeverRan(t *testing.T) {
	f := newComplianceIngestFixture(t)
	actionID := f.complianceAction(t, "unrunnable check")
	f.policy(t, "baseline", map[string]int32{actionID: 24})

	// The agent could not run the detection script at all: no detection output,
	// and the compliance flag it reports is the zero value.
	f.report(t, f.groupID, actionID, pmv1.ExecutionStatus_EXECUTION_STATUS_FAILED, false, nil, f.now)

	compliance := f.compliance(t, f.groupID)
	assert.Equal(t, pmv1.ComplianceStatus_COMPLIANCE_STATUS_IN_GRACE_PERIOD, compliance.Status)
	require.Len(t, compliance.Checks, 1)
	assert.False(t, compliance.Checks[0].Compliant)
	assert.Nil(t, compliance.Checks[0].DetectionOutput)

	// A timeout is not evidence of compliance either, even if the agent's
	// compliant flag were somehow set.
	other := f.complianceAction(t, "timed out check")
	f.policy(t, "second", map[string]int32{other: 0})
	f.report(t, f.groupID, other, pmv1.ExecutionStatus_EXECUTION_STATUS_TIMEOUT, true,
		&pmv1.CommandOutput{ExitCode: 0}, f.now)
	checks := f.compliance(t, f.groupID).Checks
	require.Len(t, checks, 2)
	for _, check := range checks {
		assert.False(t, check.Compliant, "no terminal outcome but success proves compliance")
	}
	assert.Equal(t, pmv1.ComplianceStatus_COMPLIANCE_STATUS_NON_COMPLIANT, f.compliance(t, f.groupID).Status)
}

// Deleting the check or the policy it belongs to removes the evidence, so the
// device summary derived from that evidence has to follow. A device left
// reporting NON_COMPLIANT with nothing to point at is the same confident wrong
// answer in the other direction.
func TestComplianceIngest_RemovingTheEvidenceClearsTheDeviceStatus(t *testing.T) {
	f := newComplianceIngestFixture(t)
	actions := authoring.New(authoring.Config{Store: f.store, Now: func() time.Time { return f.now }})
	policies := compliance.NewState(compliance.StateConfig{Store: f.store, Now: func() time.Time { return f.now }})

	policyActionID := f.complianceAction(t, "policy check")
	directActionID := f.complianceAction(t, "direct check")
	policyID := f.policy(t, "baseline", map[string]int32{policyActionID: 0})
	f.report(t, f.groupID, policyActionID, pmv1.ExecutionStatus_EXECUTION_STATUS_FAILED, false,
		&pmv1.CommandOutput{ExitCode: 1}, f.now)
	f.report(t, f.groupID, directActionID, pmv1.ExecutionStatus_EXECUTION_STATUS_SUCCESS, true,
		&pmv1.CommandOutput{ExitCode: 0}, f.now)
	require.Equal(t, pmv1.ComplianceStatus_COMPLIANCE_STATUS_NON_COMPLIANT, f.compliance(t, f.groupID).Status)

	require.NoError(t, policies.Delete(context.Background(), mutationOp(), policyID))
	afterPolicy := f.compliance(t, f.groupID)
	assert.Equal(t, pmv1.ComplianceStatus_COMPLIANCE_STATUS_NON_COMPLIANT, afterPolicy.Status,
		"the failing check itself survives its policy")
	assert.Len(t, afterPolicy.Checks, 2)
	assert.Empty(t, f.policyStatus(t, f.groupID).Policies)

	require.NoError(t, actions.DeleteAction(context.Background(), mutationOp(), policyActionID, false))
	afterAction := f.compliance(t, f.groupID)
	assert.Equal(t, pmv1.ComplianceStatus_COMPLIANCE_STATUS_COMPLIANT, afterAction.Status,
		"the only failing check is gone, so the device is not failing")
	require.Len(t, afterAction.Checks, 1)
	assert.Equal(t, directActionID, afterAction.Checks[0].ActionId)
	assert.Equal(t, "1", f.searchStatus(t, f.groupID))

	require.NoError(t, actions.DeleteAction(context.Background(), mutationOp(), directActionID, false))
	afterAll := f.compliance(t, f.groupID)
	assert.Equal(t, pmv1.ComplianceStatus_COMPLIANCE_STATUS_UNKNOWN, afterAll.Status,
		"no checks left is not-checked, which is UNKNOWN")
	assert.Empty(t, afterAll.Checks)
	assert.Equal(t, "0", f.searchStatus(t, f.groupID))

	device, err := f.store.GetDevice(context.Background(), f.groupID)
	require.NoError(t, err)
	assert.Equal(t, int32(0), device.ComplianceTotal)
	assert.Equal(t, int32(0), device.CompliancePassing)
	assert.Nil(t, device.ComplianceCheckedAt, "a device with no check has no check time")
}

// Detaching a rule from its policy retires that evaluation. Leaving the row
// behind would let a stale status reappear the moment the rule is reattached.
func TestComplianceIngest_DetachingARuleRetiresItsEvaluation(t *testing.T) {
	f := newComplianceIngestFixture(t)
	policies := compliance.NewState(compliance.StateConfig{Store: f.store, Now: func() time.Time { return f.now }})
	actionID := f.complianceAction(t, "graced check")
	policyID := f.policy(t, "baseline", map[string]int32{actionID: 24})

	f.report(t, f.groupID, actionID, pmv1.ExecutionStatus_EXECUTION_STATUS_FAILED, false,
		&pmv1.CommandOutput{ExitCode: 1}, f.now)
	require.Equal(t, pmv1.ComplianceStatus_COMPLIANCE_STATUS_IN_GRACE_PERIOD, f.compliance(t, f.groupID).Status)

	require.NoError(t, policies.RemoveRule(context.Background(), mutationOp(), policyID, actionID))
	detached := f.compliance(t, f.groupID)
	assert.Equal(t, pmv1.ComplianceStatus_COMPLIANCE_STATUS_NON_COMPLIANT, detached.Status,
		"a failing check with no rule has no grace period to sit in")
	require.Len(t, detached.Checks, 1)
	assert.Empty(t, f.policyStatus(t, f.groupID).Policies)
	assert.Equal(t, "2", f.searchStatus(t, f.groupID))

	var orphans int
	require.NoError(t, f.raw.QueryRow(context.Background(), `
		SELECT COUNT(*) FROM compliance_policy_evaluation
		WHERE device_id = $1 AND action_id = $2`, f.groupID, actionID).Scan(&orphans))
	assert.Equal(t, 0, orphans, "the detached rule leaves no evaluation behind")
}

// The ingestion path recognises exactly the actions the policy layer accepts:
// an ordinary shell action never becomes compliance evidence, and a check that
// belongs to no rule still reports through the direct surface.
func TestComplianceIngest_OnlyDetectionOnlyActionsProduceFindings(t *testing.T) {
	f := newComplianceIngestFixture(t)
	ordinary := f.shellAction(t, "ordinary shell", &pmv1.ShellParams{Script: "true"})
	f.report(t, f.groupID, ordinary, pmv1.ExecutionStatus_EXECUTION_STATUS_SUCCESS, false,
		nil, f.now)
	assert.Empty(t, f.compliance(t, f.groupID).Checks,
		"a non-compliance action must not manufacture a compliance finding")
	assert.Equal(t, pmv1.ComplianceStatus_COMPLIANCE_STATUS_UNKNOWN, f.compliance(t, f.groupID).Status)

	// A policy with no rules evaluates nothing and must not claim otherwise.
	unattached := f.complianceAction(t, "unattached check")
	f.policy(t, "empty", nil)
	f.report(t, f.groupID, unattached, pmv1.ExecutionStatus_EXECUTION_STATUS_FAILED, false,
		&pmv1.CommandOutput{ExitCode: 3}, f.now)

	compliance := f.compliance(t, f.groupID)
	assert.Equal(t, pmv1.ComplianceStatus_COMPLIANCE_STATUS_NON_COMPLIANT, compliance.Status)
	require.Len(t, compliance.Checks, 1)
	assert.Equal(t, unattached, compliance.Checks[0].ActionId)

	status := f.policyStatus(t, f.groupID)
	assert.Equal(t, pmv1.ComplianceStatus_COMPLIANCE_STATUS_NON_COMPLIANT, status.OverallStatus)
	assert.Empty(t, status.Policies, "a rule-less policy evaluates nothing")
}
