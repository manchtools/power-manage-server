package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/search"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

// CompliancePolicyHandler handles compliance policy RPCs.
type CompliancePolicyHandler struct {
	store     *store.Store
	searchIdx *search.Index
}

// NewCompliancePolicyHandler creates a new compliance policy handler.
func NewCompliancePolicyHandler(st *store.Store) *CompliancePolicyHandler {
	return &CompliancePolicyHandler{
		store: st,
	}
}

// SetSearchIndex sets the search index for enqueuing index updates.
func (h *CompliancePolicyHandler) SetSearchIndex(idx *search.Index) {
	h.searchIdx = idx
}

// enqueueCompliancePolicyReindex enqueues a search index update for a compliance policy.
// When rules is non-nil, action_names is included in the update. When nil, it is skipped
// (HSET is additive, so existing action_names stays unchanged).
func (h *CompliancePolicyHandler) enqueueCompliancePolicyReindex(ctx context.Context, p db.CompliancePoliciesProjection, rules []db.CompliancePolicyRulesProjection) {
	if h.searchIdx == nil {
		return
	}
	data := &taskqueue.SearchEntityData{
		Name:        p.Name,
		Description: p.Description,
	}
	if rules != nil {
		var actionNames []string
		for _, r := range rules {
			if r.ActionName != "" {
				actionNames = append(actionNames, r.ActionName)
			}
		}
		data.ActionNames = strings.Join(actionNames, " ")
		data.HasActionNames = true
	}
	if err := h.searchIdx.EnqueueReindex(ctx, search.ScopeCompliancePolicy, p.ID, data); err != nil {
		slog.Warn("failed to enqueue compliance policy reindex", "id", p.ID, "error", err)
	}
}

// CreateCompliancePolicy creates a new compliance policy.
func (h *CompliancePolicyHandler) CreateCompliancePolicy(ctx context.Context, req *connect.Request[pm.CreateCompliancePolicyRequest]) (*connect.Response[pm.CreateCompliancePolicyResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	id := ulid.Make().String()

	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "compliance_policy",
		StreamID:   id,
		EventType:  "CompliancePolicyCreated",
		Data: map[string]any{
			"name":        req.Msg.Name,
			"description": req.Msg.Description,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to create compliance policy")
	}

	policy, err := h.store.Queries().GetCompliancePolicyByID(ctx, id)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get compliance policy")
	}

	h.enqueueCompliancePolicyReindex(ctx, policy, []db.CompliancePolicyRulesProjection{})

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
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrCompliancePolicyNotFound, connect.CodeNotFound, "compliance policy not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get compliance policy")
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
	pageSize := int32(req.Msg.PageSize)
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 50
	}

	offset := int32(0)
	if req.Msg.PageToken != "" {
		offset64, err := parsePageToken(req.Msg.PageToken)
		if err != nil {
			return nil, apiErrorCtx(ctx, ErrInvalidPageToken, connect.CodeInvalidArgument, "invalid page token")
		}
		offset = int32(offset64)
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

	var nextPageToken string
	if int32(len(policies)) == pageSize && int64(offset)+int64(pageSize) < count {
		nextPageToken = formatPageToken(int64(offset) + int64(pageSize))
	}

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

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "compliance_policy",
		StreamID:   req.Msg.Id,
		EventType:  "CompliancePolicyRenamed",
		Data: map[string]any{
			"name": req.Msg.Name,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to rename compliance policy")
	}

	policy, err := h.store.Queries().GetCompliancePolicyByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrCompliancePolicyNotFound, connect.CodeNotFound, "compliance policy not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get compliance policy")
	}

	h.enqueueCompliancePolicyReindex(ctx, policy, nil)

	return connect.NewResponse(&pm.UpdateCompliancePolicyResponse{
		Policy: h.policyToProto(policy, nil),
	}), nil
}

// UpdateCompliancePolicyDescription updates a compliance policy's description.
func (h *CompliancePolicyHandler) UpdateCompliancePolicyDescription(ctx context.Context, req *connect.Request[pm.UpdateCompliancePolicyDescriptionRequest]) (*connect.Response[pm.UpdateCompliancePolicyResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "compliance_policy",
		StreamID:   req.Msg.Id,
		EventType:  "CompliancePolicyDescriptionUpdated",
		Data: map[string]any{
			"description": req.Msg.Description,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to update description")
	}

	policy, err := h.store.Queries().GetCompliancePolicyByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrCompliancePolicyNotFound, connect.CodeNotFound, "compliance policy not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get compliance policy")
	}

	h.enqueueCompliancePolicyReindex(ctx, policy, nil)

	return connect.NewResponse(&pm.UpdateCompliancePolicyResponse{
		Policy: h.policyToProto(policy, nil),
	}), nil
}

// DeleteCompliancePolicy deletes a compliance policy.
func (h *CompliancePolicyHandler) DeleteCompliancePolicy(ctx context.Context, req *connect.Request[pm.DeleteCompliancePolicyRequest]) (*connect.Response[pm.DeleteCompliancePolicyResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "compliance_policy",
		StreamID:   req.Msg.Id,
		EventType:  "CompliancePolicyDeleted",
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to delete compliance policy")
	}

	if h.searchIdx != nil {
		if err := h.searchIdx.EnqueueRemove(ctx, search.ScopeCompliancePolicy, req.Msg.Id, nil); err != nil {
			slog.Warn("failed to enqueue compliance policy removal from search", "id", req.Msg.Id, "error", err)
		}
	}

	return connect.NewResponse(&pm.DeleteCompliancePolicyResponse{}), nil
}

// AddCompliancePolicyRule adds a rule to a compliance policy.
func (h *CompliancePolicyHandler) AddCompliancePolicyRule(ctx context.Context, req *connect.Request[pm.AddCompliancePolicyRuleRequest]) (*connect.Response[pm.AddCompliancePolicyRuleResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	// Verify policy exists
	_, err := h.store.Queries().GetCompliancePolicyByID(ctx, req.Msg.PolicyId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrCompliancePolicyNotFound, connect.CodeNotFound, "compliance policy not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get compliance policy")
	}

	// Verify action exists and is a compliance action
	action, err := h.store.Queries().GetActionByID(ctx, req.Msg.ActionId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrActionNotFound, connect.CodeNotFound, "action not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get action")
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

	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "compliance_policy",
		StreamID:   req.Msg.PolicyId,
		EventType:  "CompliancePolicyRuleAdded",
		Data: map[string]any{
			"action_id":          req.Msg.ActionId,
			"action_name":        action.Name,
			"grace_period_hours": req.Msg.GracePeriodHours,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to add rule")
	}

	policy, err := h.store.Queries().GetCompliancePolicyByID(ctx, req.Msg.PolicyId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get compliance policy")
	}

	rules, err := h.store.Queries().ListCompliancePolicyRules(ctx, req.Msg.PolicyId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get compliance policy rules")
	}

	h.enqueueCompliancePolicyReindex(ctx, policy, rules)

	return connect.NewResponse(&pm.AddCompliancePolicyRuleResponse{
		Policy: h.policyToProto(policy, rules),
	}), nil
}

// RemoveCompliancePolicyRule removes a rule from a compliance policy.
func (h *CompliancePolicyHandler) RemoveCompliancePolicyRule(ctx context.Context, req *connect.Request[pm.RemoveCompliancePolicyRuleRequest]) (*connect.Response[pm.RemoveCompliancePolicyRuleResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "compliance_policy",
		StreamID:   req.Msg.PolicyId,
		EventType:  "CompliancePolicyRuleRemoved",
		Data: map[string]any{
			"action_id": req.Msg.ActionId,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to remove rule")
	}

	policy, err := h.store.Queries().GetCompliancePolicyByID(ctx, req.Msg.PolicyId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrCompliancePolicyNotFound, connect.CodeNotFound, "compliance policy not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get compliance policy")
	}

	rules, err := h.store.Queries().ListCompliancePolicyRules(ctx, req.Msg.PolicyId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get compliance policy rules")
	}

	h.enqueueCompliancePolicyReindex(ctx, policy, rules)

	return connect.NewResponse(&pm.RemoveCompliancePolicyRuleResponse{
		Policy: h.policyToProto(policy, rules),
	}), nil
}

// UpdateCompliancePolicyRule updates the grace period of a rule.
func (h *CompliancePolicyHandler) UpdateCompliancePolicyRule(ctx context.Context, req *connect.Request[pm.UpdateCompliancePolicyRuleRequest]) (*connect.Response[pm.UpdateCompliancePolicyRuleResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "compliance_policy",
		StreamID:   req.Msg.PolicyId,
		EventType:  "CompliancePolicyRuleUpdated",
		Data: map[string]any{
			"action_id":          req.Msg.ActionId,
			"grace_period_hours": req.Msg.GracePeriodHours,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to update rule")
	}

	policy, err := h.store.Queries().GetCompliancePolicyByID(ctx, req.Msg.PolicyId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrCompliancePolicyNotFound, connect.CodeNotFound, "compliance policy not found")
		}
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
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrDeviceNotFound, connect.CodeNotFound, "device not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get compliance summary")
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
		if e.CheckedAt.Valid {
			ruleEval.CheckedAt = timestamppb.New(e.CheckedAt.Time)
		}
		if e.FirstFailedAt.Valid {
			ruleEval.FirstFailedAt = timestamppb.New(e.FirstFailedAt.Time)
			if e.GracePeriodHours > 0 {
				graceExpires := e.FirstFailedAt.Time.Add(time.Duration(e.GracePeriodHours) * time.Hour)
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

	if p.CreatedAt.Valid {
		policy.CreatedAt = timestamppb.New(p.CreatedAt.Time)
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
