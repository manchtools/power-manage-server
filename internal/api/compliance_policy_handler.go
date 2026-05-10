package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// CompliancePolicyHandler handles compliance policy RPCs.
type CompliancePolicyHandler struct {
	searchIndexHolder
	store  *store.Store
	logger *slog.Logger
}

// NewCompliancePolicyHandler creates a new compliance policy handler.
func NewCompliancePolicyHandler(st *store.Store, logger *slog.Logger) *CompliancePolicyHandler {
	return &CompliancePolicyHandler{
		store:  st,
		logger: logger,
	}
}

// CreateCompliancePolicy creates a new compliance policy.
func (h *CompliancePolicyHandler) CreateCompliancePolicy(ctx context.Context, req *connect.Request[pm.CreateCompliancePolicyRequest]) (*connect.Response[pm.CreateCompliancePolicyResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	id := ulid.Make().String()

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "compliance_policy",
		StreamID:   id,
		EventType:  string(eventtypes.CompliancePolicyCreated),
		Data: payloads.CompliancePolicyCreated{
			Name:        req.Msg.Name,
			Description: req.Msg.Description,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to create compliance policy"); err != nil {
		return nil, err
	}

	policy, err := h.store.Queries().GetCompliancePolicyByID(ctx, id)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get compliance policy")
	}

	return connect.NewResponse(&pm.CreateCompliancePolicyResponse{
		Policy: h.policyToProto(policy, nil),
	}), nil
}

// GetCompliancePolicy returns a compliance policy by ID.
func (h *CompliancePolicyHandler) GetCompliancePolicy(ctx context.Context, req *connect.Request[pm.GetCompliancePolicyRequest]) (*connect.Response[pm.GetCompliancePolicyResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	policy, err := h.store.Queries().GetCompliancePolicyByID(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrCompliancePolicyNotFound, "compliance policy not found")
	}

	rules, err := h.store.Queries().ListCompliancePolicyRules(ctx, req.Msg.Id)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get compliance policy rules")
	}

	return connect.NewResponse(&pm.GetCompliancePolicyResponse{
		Policy: h.policyToProto(policy, rules),
	}), nil
}

// ListCompliancePolicies returns a paginated list of compliance policies.
func (h *CompliancePolicyHandler) ListCompliancePolicies(ctx context.Context, req *connect.Request[pm.ListCompliancePoliciesRequest]) (*connect.Response[pm.ListCompliancePoliciesResponse], error) {
	pageSize, offset, err := parsePagination(int32(req.Msg.PageSize), req.Msg.PageToken)
	if err != nil {
		return nil, err
	}

	policies, err := h.store.Queries().ListCompliancePolicies(ctx, db.ListCompliancePoliciesParams{
		Limit:  pageSize,
		Offset: offset,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to list compliance policies")
	}

	count, err := h.store.Queries().CountCompliancePolicies(ctx)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to count compliance policies")
	}

	nextPageToken := buildNextPageToken(int32(len(policies)), offset, pageSize, count)

	protoPolicies := make([]*pm.CompliancePolicy, len(policies))
	for i, p := range policies {
		protoPolicies[i] = h.policyToProto(p, nil)
	}

	return connect.NewResponse(&pm.ListCompliancePoliciesResponse{
		Policies:      protoPolicies,
		NextPageToken: nextPageToken,
		TotalCount:    int32(count),
	}), nil
}

// RenameCompliancePolicy renames a compliance policy.
func (h *CompliancePolicyHandler) RenameCompliancePolicy(ctx context.Context, req *connect.Request[pm.RenameCompliancePolicyRequest]) (*connect.Response[pm.UpdateCompliancePolicyResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Verify policy exists before emitting event
	_, err = h.store.Queries().GetCompliancePolicyByID(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrCompliancePolicyNotFound, "compliance policy not found")
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "compliance_policy",
		StreamID:   req.Msg.Id,
		EventType:  string(eventtypes.CompliancePolicyRenamed),
		Data: payloads.CompliancePolicyRenamed{
			Name: req.Msg.Name,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to rename compliance policy"); err != nil {
		return nil, err
	}

	policy, err := h.store.Queries().GetCompliancePolicyByID(ctx, req.Msg.Id)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get compliance policy")
	}

	return connect.NewResponse(&pm.UpdateCompliancePolicyResponse{
		Policy: h.policyToProto(policy, nil),
	}), nil
}

// UpdateCompliancePolicyDescription updates a compliance policy's description.
func (h *CompliancePolicyHandler) UpdateCompliancePolicyDescription(ctx context.Context, req *connect.Request[pm.UpdateCompliancePolicyDescriptionRequest]) (*connect.Response[pm.UpdateCompliancePolicyResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Verify policy exists before emitting event
	_, err = h.store.Queries().GetCompliancePolicyByID(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrCompliancePolicyNotFound, "compliance policy not found")
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "compliance_policy",
		StreamID:   req.Msg.Id,
		EventType:  string(eventtypes.CompliancePolicyDescriptionUpdated),
		Data: payloads.CompliancePolicyDescriptionUpdated{
			Description: req.Msg.Description,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to update description"); err != nil {
		return nil, err
	}

	policy, err := h.store.Queries().GetCompliancePolicyByID(ctx, req.Msg.Id)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get compliance policy")
	}

	return connect.NewResponse(&pm.UpdateCompliancePolicyResponse{
		Policy: h.policyToProto(policy, nil),
	}), nil
}

// DeleteCompliancePolicy deletes a compliance policy.
func (h *CompliancePolicyHandler) DeleteCompliancePolicy(ctx context.Context, req *connect.Request[pm.DeleteCompliancePolicyRequest]) (*connect.Response[pm.DeleteCompliancePolicyResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Verify policy exists before emitting delete event
	_, err = h.store.Queries().GetCompliancePolicyByID(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrCompliancePolicyNotFound, "compliance policy not found")
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "compliance_policy",
		StreamID:   req.Msg.Id,
		EventType:  string(eventtypes.CompliancePolicyDeleted),
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	}, "failed to delete compliance policy"); err != nil {
		return nil, err
	}

	// Search index removal is handled by api.SearchListener (Phase 2e
	// of #81): the listener fires on CompliancePolicyDeleted.

	return connect.NewResponse(&pm.DeleteCompliancePolicyResponse{}), nil
}

// AddCompliancePolicyRule adds a rule to a compliance policy.
func (h *CompliancePolicyHandler) AddCompliancePolicyRule(ctx context.Context, req *connect.Request[pm.AddCompliancePolicyRuleRequest]) (*connect.Response[pm.AddCompliancePolicyRuleResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Verify policy exists
	_, err = h.store.Queries().GetCompliancePolicyByID(ctx, req.Msg.PolicyId)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrCompliancePolicyNotFound, "compliance policy not found")
	}

	// Verify action exists and is a compliance action
	action, err := h.store.Queries().GetActionByID(ctx, req.Msg.ActionId)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrActionNotFound, "action not found")
	}

	// Check action type is SHELL and is_compliance is true
	if action.ActionType != 200 { // ACTION_TYPE_SHELL
		return nil, apiErrorCtx(ctx, ErrActionNotCompliance, connect.CodeInvalidArgument, "action must be a shell script type")
	}

	var params map[string]any
	if json.Unmarshal(action.Params, &params) == nil {
		isCompliance, _ := params["isCompliance"].(bool)
		if !isCompliance {
			return nil, apiErrorCtx(ctx, ErrActionNotCompliance, connect.CodeInvalidArgument, "action must have is_compliance enabled")
		}
	} else {
		return nil, apiErrorCtx(ctx, ErrActionNotCompliance, connect.CodeInvalidArgument, "action must have is_compliance enabled")
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "compliance_policy",
		StreamID:   req.Msg.PolicyId,
		EventType:  string(eventtypes.CompliancePolicyRuleAdded),
		Data: payloads.CompliancePolicyRuleAdded{
			ActionID:         req.Msg.ActionId,
			ActionName:       action.Name,
			GracePeriodHours: req.Msg.GracePeriodHours,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to add rule"); err != nil {
		return nil, err
	}

	policy, err := h.store.Queries().GetCompliancePolicyByID(ctx, req.Msg.PolicyId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get compliance policy")
	}

	rules, err := h.store.Queries().ListCompliancePolicyRules(ctx, req.Msg.PolicyId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get compliance policy rules")
	}

	return connect.NewResponse(&pm.AddCompliancePolicyRuleResponse{
		Policy: h.policyToProto(policy, rules),
	}), nil
}

// RemoveCompliancePolicyRule removes a rule from a compliance policy.
func (h *CompliancePolicyHandler) RemoveCompliancePolicyRule(ctx context.Context, req *connect.Request[pm.RemoveCompliancePolicyRuleRequest]) (*connect.Response[pm.RemoveCompliancePolicyRuleResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Verify policy exists before emitting event
	_, err = h.store.Queries().GetCompliancePolicyByID(ctx, req.Msg.PolicyId)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrCompliancePolicyNotFound, "compliance policy not found")
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "compliance_policy",
		StreamID:   req.Msg.PolicyId,
		EventType:  string(eventtypes.CompliancePolicyRuleRemoved),
		Data: payloads.CompliancePolicyRuleRemoved{
			ActionID: req.Msg.ActionId,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to remove rule"); err != nil {
		return nil, err
	}

	policy, err := h.store.Queries().GetCompliancePolicyByID(ctx, req.Msg.PolicyId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get compliance policy")
	}

	rules, err := h.store.Queries().ListCompliancePolicyRules(ctx, req.Msg.PolicyId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get compliance policy rules")
	}

	return connect.NewResponse(&pm.RemoveCompliancePolicyRuleResponse{
		Policy: h.policyToProto(policy, rules),
	}), nil
}

// UpdateCompliancePolicyRule updates the grace period of a rule.
func (h *CompliancePolicyHandler) UpdateCompliancePolicyRule(ctx context.Context, req *connect.Request[pm.UpdateCompliancePolicyRuleRequest]) (*connect.Response[pm.UpdateCompliancePolicyRuleResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Verify policy exists before emitting event
	_, err = h.store.Queries().GetCompliancePolicyByID(ctx, req.Msg.PolicyId)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrCompliancePolicyNotFound, "compliance policy not found")
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "compliance_policy",
		StreamID:   req.Msg.PolicyId,
		EventType:  string(eventtypes.CompliancePolicyRuleUpdated),
		Data: payloads.CompliancePolicyRuleUpdated{
			ActionID:         req.Msg.ActionId,
			GracePeriodHours: req.Msg.GracePeriodHours,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to update rule"); err != nil {
		return nil, err
	}

	policy, err := h.store.Queries().GetCompliancePolicyByID(ctx, req.Msg.PolicyId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get compliance policy")
	}

	rules, err := h.store.Queries().ListCompliancePolicyRules(ctx, req.Msg.PolicyId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get compliance policy rules")
	}

	return connect.NewResponse(&pm.UpdateCompliancePolicyRuleResponse{
		Policy: h.policyToProto(policy, rules),
	}), nil
}

// GetDeviceCompliancePolicyStatus returns the per-policy compliance status for a device.
func (h *CompliancePolicyHandler) GetDeviceCompliancePolicyStatus(ctx context.Context, req *connect.Request[pm.GetDeviceCompliancePolicyStatusRequest]) (*connect.Response[pm.GetDeviceCompliancePolicyStatusResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	evals, err := h.store.Queries().GetDeviceCompliancePolicyEvaluations(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get compliance evaluations")
	}

	// Also get compliance results for detection output
	results, err := h.store.Queries().GetDeviceComplianceResults(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get compliance results")
	}
	resultMap := make(map[string]db.ComplianceResultsProjection)
	for _, r := range results {
		resultMap[r.ActionID] = r
	}

	// Get device compliance summary
	summary, err := h.store.Queries().GetDeviceComplianceSummary(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrDeviceNotFound, "device not found")
	}

	// Group evaluations by policy
	policyMap := make(map[string]*pm.DevicePolicyEvaluation)
	policyOrder := make([]string, 0)
	for _, e := range evals {
		if _, ok := policyMap[e.PolicyID]; !ok {
			policyMap[e.PolicyID] = &pm.DevicePolicyEvaluation{
				PolicyId:   e.PolicyID,
				PolicyName: e.PolicyName,
				Status:     pm.ComplianceStatus_COMPLIANCE_STATUS_COMPLIANT, // will be updated
			}
			policyOrder = append(policyOrder, e.PolicyID)
		}

		ruleEval := &pm.DevicePolicyRuleEvaluation{
			ActionId:         e.ActionID,
			ActionName:       e.ActionName,
			Status:           pm.ComplianceStatus(e.Status),
			Compliant:        e.Compliant,
			GracePeriodHours: e.GracePeriodHours,
		}
		if e.CheckedAt != nil {
			ruleEval.CheckedAt = timestamppb.New(*e.CheckedAt)
		}
		if e.FirstFailedAt != nil {
			ruleEval.FirstFailedAt = timestamppb.New(*e.FirstFailedAt)
			if e.GracePeriodHours > 0 {
				graceExpires := e.FirstFailedAt.Add(time.Duration(e.GracePeriodHours) * time.Hour)
				ruleEval.GraceExpiresAt = timestamppb.New(graceExpires)
			}
		}

		// Add detection output if available
		if r, ok := resultMap[e.ActionID]; ok && len(r.DetectionOutput) > 0 {
			var output struct {
				Stdout   string `json:"stdout"`
				Stderr   string `json:"stderr"`
				ExitCode int32  `json:"exit_code"`
			}
			if json.Unmarshal(r.DetectionOutput, &output) == nil {
				ruleEval.DetectionOutput = &pm.CommandOutput{
					Stdout:   output.Stdout,
					Stderr:   output.Stderr,
					ExitCode: output.ExitCode,
				}
			}
		}

		pe := policyMap[e.PolicyID]
		pe.Rules = append(pe.Rules, ruleEval)

		// Update policy-level status (worst wins)
		ruleStatus := pm.ComplianceStatus(e.Status)
		if ruleStatus == pm.ComplianceStatus_COMPLIANCE_STATUS_NON_COMPLIANT {
			pe.Status = pm.ComplianceStatus_COMPLIANCE_STATUS_NON_COMPLIANT
		} else if ruleStatus == pm.ComplianceStatus_COMPLIANCE_STATUS_IN_GRACE_PERIOD && pe.Status != pm.ComplianceStatus_COMPLIANCE_STATUS_NON_COMPLIANT {
			pe.Status = pm.ComplianceStatus_COMPLIANCE_STATUS_IN_GRACE_PERIOD
		} else if ruleStatus == pm.ComplianceStatus_COMPLIANCE_STATUS_UNKNOWN && pe.Status == pm.ComplianceStatus_COMPLIANCE_STATUS_COMPLIANT {
			pe.Status = pm.ComplianceStatus_COMPLIANCE_STATUS_UNKNOWN
		}
	}

	policies := make([]*pm.DevicePolicyEvaluation, 0, len(policyOrder))
	for _, id := range policyOrder {
		policies = append(policies, policyMap[id])
	}

	return connect.NewResponse(&pm.GetDeviceCompliancePolicyStatusResponse{
		OverallStatus: pm.ComplianceStatus(summary.ComplianceStatus),
		Policies:      policies,
	}), nil
}

func (h *CompliancePolicyHandler) policyToProto(p db.CompliancePoliciesProjection, rules []db.CompliancePolicyRulesProjection) *pm.CompliancePolicy {
	policy := &pm.CompliancePolicy{
		Id:          p.ID,
		Name:        p.Name,
		Description: p.Description,
		RuleCount:   p.RuleCount,
		CreatedBy:   p.CreatedBy,
	}

	if p.CreatedAt != nil {
		policy.CreatedAt = timestamppb.New(*p.CreatedAt)
	}

	if rules != nil {
		policy.Rules = make([]*pm.CompliancePolicyRule, len(rules))
		for i, r := range rules {
			policy.Rules[i] = &pm.CompliancePolicyRule{
				ActionId:         r.ActionID,
				ActionName:       r.ActionName,
				GracePeriodHours: r.GracePeriodHours,
			}
		}
	}

	return policy
}
