package compliance

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"github.com/go-playground/validator/v10"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	sdkvalidate "github.com/manchtools/power-manage-sdk/validate"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/authoring"
	"github.com/manchtools/power-manage/server/internal/middleware"
	"github.com/manchtools/power-manage/server/internal/store"
)

const (
	defaultPageSize = int32(50)

	errNotAuthenticated    = "not_authenticated"
	errPermissionDenied    = "permission_denied"
	errValidationFailed    = "validation_failed"
	errInvalidPageToken    = "invalid_page_token"
	errInternal            = "internal_error"
	errPolicyNotFound      = "compliance_policy_not_found"
	errActionNotFound      = "action_not_found"
	errActionNotCompliance = "action_not_compliance"
	errActionNoDetection   = "compliance_action_needs_detection"
	errRuleExists          = "compliance_policy_rule_exists"
	errPolicyRuleNotFound  = "compliance_policy_rule_not_found"
)

// HandlersConfig supplies the direct store and process-local seams.
type HandlersConfig struct {
	Store  *store.Store
	Logger *slog.Logger
	Now    func() time.Time
}

// Handlers implements the explicit compliance-policy CRUD procedures.
type Handlers struct {
	store     *store.Store
	state     *State
	logger    *slog.Logger
	validator *validator.Validate
}

// NewHandlers constructs direct compliance-policy handlers.
func NewHandlers(cfg HandlersConfig) *Handlers {
	if cfg.Store == nil {
		panic("compliance: handler store is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Handlers{
		store: cfg.Store, state: NewState(StateConfig{Store: cfg.Store, Now: cfg.Now}),
		logger: cfg.Logger, validator: sdkvalidate.NewValidator(),
	}
}

func validateRequest[T any](h *Handlers, ctx context.Context, req *connect.Request[T]) error {
	if req == nil || req.Msg == nil {
		return rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument, "request is required")
	}
	if detail, ok := sdkvalidate.Struct(h.validator, req.Msg); !ok {
		return rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument, detail)
	}
	return nil
}

func (h *Handlers) actor(ctx context.Context) (*auth.UserContext, error) {
	actor, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, rpcError(ctx, errNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}
	return actor, nil
}

func (h *Handlers) authorize(ctx context.Context, permission, resourceID string) error {
	if !auth.AuthorizeContext(ctx, permission, resourceID) {
		return rpcError(ctx, errPermissionDenied, connect.CodePermissionDenied, "permission denied")
	}
	return nil
}

func (h *Handlers) internal(ctx context.Context, operation string, err error) *connect.Error {
	h.logger.Error("compliance-policy RPC failed", "operation", operation, "error", err)
	return rpcError(ctx, errInternal, connect.CodeInternal, "internal error")
}

func (h *Handlers) operation(req connect.AnyRequest, actor *auth.UserContext, procedure, permission string) store.AuditOperation {
	op := store.AuditOperation{
		Class: store.ClassMutation, ActorType: string(actor.Kind), Origin: auth.ControlRPCOrigin,
		RequestDescriptor: procedure, AuthorizationOutcome: store.AuthorizationAllowed,
		AuthorizationDetail: permission, Result: store.ResultSuccess, ResultCode: "OK",
	}
	if actor.CanOwnResources() {
		op.ActorID = actor.ID
	}
	if ip := auth.ClientIP(req); ip != "" {
		op.OriginFingerprint = auth.Fingerprint(ip)
	}
	return op
}

// CreateCompliancePolicy creates one empty policy.
func (h *Handlers) CreateCompliancePolicy(ctx context.Context, req *connect.Request[pmv1.CreateCompliancePolicyRequest]) (*connect.Response[pmv1.CreateCompliancePolicyResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "CreateCompliancePolicy", ""); err != nil {
		return nil, err
	}
	row, err := h.state.Create(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceCreateCompliancePolicyProcedure, "CreateCompliancePolicy"), CreateParams{
		Name: req.Msg.Name, Description: req.Msg.Description, CreatedBy: actor.ID,
	})
	if err != nil {
		return nil, h.policyError(ctx, "create policy", err)
	}
	return connect.NewResponse(&pmv1.CreateCompliancePolicyResponse{Policy: policyToProto(row, 0, nil)}), nil
}

// GetCompliancePolicy returns one visible policy with its live rules.
func (h *Handlers) GetCompliancePolicy(ctx context.Context, req *connect.Request[pmv1.GetCompliancePolicyRequest]) (*connect.Response[pmv1.GetCompliancePolicyResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	if _, err := h.actor(ctx); err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "GetCompliancePolicy", req.Msg.Id); err != nil {
		return nil, err
	}
	row, err := h.operatorPolicy(ctx, req.Msg.Id)
	if err != nil {
		return nil, err
	}
	if err := h.enforcePolicyReadScope(ctx, req.Msg.Id); err != nil {
		return nil, err
	}
	rules, err := h.store.ListCompliancePolicyRules(ctx, req.Msg.Id)
	if err != nil {
		return nil, h.internal(ctx, "list policy rules", err)
	}
	return connect.NewResponse(&pmv1.GetCompliancePolicyResponse{
		Policy: policyToProto(row, int64(len(rules)), rules),
	}), nil
}

// ListCompliancePolicies returns a deterministic SQLite keyset page.
func (h *Handlers) ListCompliancePolicies(ctx context.Context, req *connect.Request[pmv1.ListCompliancePoliciesRequest]) (*connect.Response[pmv1.ListCompliancePoliciesResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	if _, err := h.actor(ctx); err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "ListCompliancePolicies", ""); err != nil {
		return nil, err
	}
	if !validPageToken(req.Msg.PageToken) {
		return nil, rpcError(ctx, errInvalidPageToken, connect.CodeInvalidArgument, "invalid page token")
	}
	limit := req.Msg.PageSize
	if limit == 0 {
		limit = defaultPageSize
	}
	groupIDs, restricted := auth.ObjectScopeListFilter(ctx)
	filter := store.CompliancePolicyListFilter{
		AfterID: req.Msg.PageToken, Limit: limit + 1,
		ScopeRestricted: restricted, ScopeGroupIDs: groupIDs,
	}
	views, err := h.store.ListAuthoringCompliancePolicies(ctx, filter)
	if err != nil {
		return nil, h.internal(ctx, "list policies", err)
	}
	hasMore := len(views) > int(limit)
	if hasMore {
		views = views[:limit]
	}
	total, err := h.store.CountAuthoringCompliancePolicies(ctx, filter)
	if err != nil {
		return nil, h.internal(ctx, "count policies", err)
	}
	policies := make([]*pmv1.CompliancePolicy, len(views))
	for i, view := range views {
		policies[i] = policyToProto(view.CompliancePolicyRow, view.LiveRuleCount, nil)
	}
	next := ""
	if hasMore {
		next = views[len(views)-1].ID
	}
	return connect.NewResponse(&pmv1.ListCompliancePoliciesResponse{
		Policies: policies, NextPageToken: next, TotalCount: boundedCount(total),
	}), nil
}

// RenameCompliancePolicy replaces a policy name.
func (h *Handlers) RenameCompliancePolicy(ctx context.Context, req *connect.Request[pmv1.RenameCompliancePolicyRequest]) (*connect.Response[pmv1.UpdateCompliancePolicyResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.mutationActor(ctx, req.Msg.Id, "RenameCompliancePolicy")
	if err != nil {
		return nil, err
	}
	row, err := h.state.Rename(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceRenameCompliancePolicyProcedure, "RenameCompliancePolicy"), req.Msg.Id, req.Msg.Name)
	return h.updatedPolicy(ctx, "rename policy", row, err)
}

// UpdateCompliancePolicyDescription replaces a policy description.
func (h *Handlers) UpdateCompliancePolicyDescription(ctx context.Context, req *connect.Request[pmv1.UpdateCompliancePolicyDescriptionRequest]) (*connect.Response[pmv1.UpdateCompliancePolicyResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.mutationActor(ctx, req.Msg.Id, "UpdateCompliancePolicyDescription")
	if err != nil {
		return nil, err
	}
	row, err := h.state.UpdateDescription(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceUpdateCompliancePolicyDescriptionProcedure, "UpdateCompliancePolicyDescription"),
		req.Msg.Id, req.Msg.Description)
	return h.updatedPolicy(ctx, "update policy description", row, err)
}

// DeleteCompliancePolicy deletes one policy and its ordinary dependent state.
func (h *Handlers) DeleteCompliancePolicy(ctx context.Context, req *connect.Request[pmv1.DeleteCompliancePolicyRequest]) (*connect.Response[pmv1.DeleteCompliancePolicyResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.mutationActor(ctx, req.Msg.Id, "DeleteCompliancePolicy")
	if err != nil {
		return nil, err
	}
	if err := h.state.Delete(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceDeleteCompliancePolicyProcedure, "DeleteCompliancePolicy"), req.Msg.Id); err != nil {
		return nil, h.policyError(ctx, "delete policy", err)
	}
	return connect.NewResponse(&pmv1.DeleteCompliancePolicyResponse{}), nil
}

// AddCompliancePolicyRule adds one visible compliance Action.
func (h *Handlers) AddCompliancePolicyRule(ctx context.Context, req *connect.Request[pmv1.AddCompliancePolicyRuleRequest]) (*connect.Response[pmv1.AddCompliancePolicyRuleResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.mutationActor(ctx, req.Msg.PolicyId, "AddCompliancePolicyRule")
	if err != nil {
		return nil, err
	}
	visible, err := authoring.ActionVisibleToCaller(ctx, h.store, req.Msg.ActionId)
	if err != nil {
		return nil, h.internal(ctx, "resolve compliance action scope", err)
	}
	if !visible {
		h.logger.Warn("out-of-scope compliance action read denied", "action_id", req.Msg.ActionId)
		return nil, notFound(ctx, errActionNotFound, "action not found")
	}
	if _, err := h.operatorAction(ctx, req.Msg.ActionId); err != nil {
		return nil, err
	}
	if err := h.state.AddRule(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceAddCompliancePolicyRuleProcedure, "AddCompliancePolicyRule"),
		req.Msg.PolicyId, req.Msg.ActionId, req.Msg.GracePeriodHours); err != nil {
		return nil, h.addRuleError(ctx, req.Msg.PolicyId, req.Msg.ActionId, err)
	}
	policy, err := h.policyResponse(ctx, req.Msg.PolicyId)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&pmv1.AddCompliancePolicyRuleResponse{Policy: policy}), nil
}

// RemoveCompliancePolicyRule removes one Action edge.
func (h *Handlers) RemoveCompliancePolicyRule(ctx context.Context, req *connect.Request[pmv1.RemoveCompliancePolicyRuleRequest]) (*connect.Response[pmv1.RemoveCompliancePolicyRuleResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.mutationActor(ctx, req.Msg.PolicyId, "RemoveCompliancePolicyRule")
	if err != nil {
		return nil, err
	}
	if err := h.state.RemoveRule(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceRemoveCompliancePolicyRuleProcedure, "RemoveCompliancePolicyRule"),
		req.Msg.PolicyId, req.Msg.ActionId); err != nil {
		return nil, h.policyError(ctx, "remove policy rule", err)
	}
	policy, err := h.policyResponse(ctx, req.Msg.PolicyId)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&pmv1.RemoveCompliancePolicyRuleResponse{Policy: policy}), nil
}

// UpdateCompliancePolicyRule replaces one rule grace period.
func (h *Handlers) UpdateCompliancePolicyRule(ctx context.Context, req *connect.Request[pmv1.UpdateCompliancePolicyRuleRequest]) (*connect.Response[pmv1.UpdateCompliancePolicyRuleResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.mutationActor(ctx, req.Msg.PolicyId, "UpdateCompliancePolicyRule")
	if err != nil {
		return nil, err
	}
	if err := h.state.UpdateRule(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceUpdateCompliancePolicyRuleProcedure, "UpdateCompliancePolicyRule"),
		req.Msg.PolicyId, req.Msg.ActionId, req.Msg.GracePeriodHours); err != nil {
		return nil, h.policyError(ctx, "update policy rule", err)
	}
	policy, err := h.policyResponse(ctx, req.Msg.PolicyId)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&pmv1.UpdateCompliancePolicyRuleResponse{Policy: policy}), nil
}

func (h *Handlers) operatorPolicy(ctx context.Context, id string) (store.CompliancePolicyRow, error) {
	row, err := h.store.GetAuthoringCompliancePolicy(ctx, id)
	if err != nil {
		if store.IsNotFound(err) {
			return store.CompliancePolicyRow{}, notFound(ctx, errPolicyNotFound, "compliance policy not found")
		}
		return store.CompliancePolicyRow{}, h.internal(ctx, "read policy", err)
	}
	return row, nil
}

func (h *Handlers) operatorAction(ctx context.Context, id string) (store.ActionRow, error) {
	row, err := h.store.GetManifestAction(ctx, id)
	if err != nil {
		if store.IsNotFound(err) {
			return store.ActionRow{}, notFound(ctx, errActionNotFound, "action not found")
		}
		return store.ActionRow{}, h.internal(ctx, "read compliance action", err)
	}
	if row.IsSystem {
		return store.ActionRow{}, notFound(ctx, errActionNotFound, "action not found")
	}
	return row, nil
}

func (h *Handlers) mutationActor(ctx context.Context, id, permission string) (*auth.UserContext, error) {
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, permission, id); err != nil {
		return nil, err
	}
	if err := h.enforcePolicyWriteScope(ctx, id); err != nil {
		return nil, err
	}
	if _, err := h.operatorPolicy(ctx, id); err != nil {
		return nil, err
	}
	return actor, nil
}

func (h *Handlers) enforcePolicyReadScope(ctx context.Context, id string) error {
	callerGroups, restricted := auth.ObjectScopeListFilter(ctx)
	if !restricted {
		return nil
	}
	objectGroups, err := h.directScopeGroups(ctx, id)
	if err != nil {
		return h.internal(ctx, "resolve policy read scope", err)
	}
	if !groupsOverlap(callerGroups, objectGroups) {
		h.logger.Warn("out-of-scope compliance policy read denied", "policy_id", id)
		return notFound(ctx, errPolicyNotFound, "compliance policy not found")
	}
	return nil
}

func (h *Handlers) enforcePolicyWriteScope(ctx context.Context, id string) error {
	callerGroups, restricted := auth.ObjectScopeListFilter(ctx)
	if !restricted {
		return nil
	}
	objectGroups, err := h.directScopeGroups(ctx, id)
	if err != nil {
		return h.internal(ctx, "resolve policy write scope", err)
	}
	if !groupsOverlap(callerGroups, objectGroups) {
		h.logger.Warn("out-of-scope compliance policy mutation denied", "policy_id", id)
		return rpcError(ctx, errPermissionDenied, connect.CodePermissionDenied, "permission denied")
	}
	return nil
}

func (h *Handlers) directScopeGroups(ctx context.Context, id string) ([]string, error) {
	targets, err := h.store.ListAuthoringAssignmentTargets(ctx, "compliance_policy", id)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		var ids []string
		switch target.TargetType {
		case "device_group", "user_group":
			ids = []string{target.TargetID}
		case "device":
			ids, err = h.store.ListDeviceGroupIDs(ctx, target.TargetID)
		case "user":
			ids, err = h.store.ListUserGroupIDsForUser(ctx, target.TargetID)
		default:
			return nil, fmt.Errorf("compliance: unknown assignment target type %q", target.TargetType)
		}
		if err != nil {
			return nil, err
		}
		for _, groupID := range ids {
			if groupID != "" {
				seen[groupID] = struct{}{}
			}
		}
	}
	groups := make([]string, 0, len(seen))
	for id := range seen {
		groups = append(groups, id)
	}
	return groups, nil
}

func groupsOverlap(left, right []string) bool {
	seen := make(map[string]struct{}, len(left))
	for _, id := range left {
		seen[id] = struct{}{}
	}
	for _, id := range right {
		if _, ok := seen[id]; ok {
			return true
		}
	}
	return false
}

func (h *Handlers) updatedPolicy(ctx context.Context, operation string, row store.CompliancePolicyRow, err error) (*connect.Response[pmv1.UpdateCompliancePolicyResponse], error) {
	if err != nil {
		return nil, h.policyError(ctx, operation, err)
	}
	rules, err := h.store.ListCompliancePolicyRules(ctx, row.ID)
	if err != nil {
		return nil, h.internal(ctx, "list updated policy rules", err)
	}
	return connect.NewResponse(&pmv1.UpdateCompliancePolicyResponse{
		Policy: policyToProto(row, int64(len(rules)), rules),
	}), nil
}

func (h *Handlers) policyResponse(ctx context.Context, id string) (*pmv1.CompliancePolicy, error) {
	row, err := h.store.GetAuthoringCompliancePolicy(ctx, id)
	if err != nil {
		return nil, h.policyError(ctx, "read changed policy", err)
	}
	rules, err := h.store.ListCompliancePolicyRules(ctx, id)
	if err != nil {
		return nil, h.internal(ctx, "list changed policy rules", err)
	}
	return policyToProto(row, int64(len(rules)), rules), nil
}

func (h *Handlers) policyError(ctx context.Context, operation string, err error) error {
	switch {
	case errors.Is(err, ErrInvalidInput):
		return rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument, "invalid compliance policy")
	case errors.Is(err, ErrActionNotCompliance):
		return rpcError(ctx, errActionNotCompliance, connect.CodeInvalidArgument, "action must be a compliance shell action")
	case errors.Is(err, ErrComplianceActionNeedsDetection):
		return rpcError(ctx, errActionNoDetection, connect.CodeInvalidArgument, "compliance action must carry a detection script")
	case errors.Is(err, ErrRuleExists):
		return rpcError(ctx, errRuleExists, connect.CodeAlreadyExists, "compliance policy rule already exists")
	case errors.Is(err, ErrRuleNotFound):
		return notFound(ctx, errPolicyRuleNotFound, "compliance policy rule not found")
	case store.IsNotFound(err):
		return notFound(ctx, errPolicyNotFound, "compliance policy not found")
	default:
		return h.internal(ctx, operation, err)
	}
}

func (h *Handlers) addRuleError(ctx context.Context, policyID, actionID string, err error) error {
	if !store.IsNotFound(err) {
		return h.policyError(ctx, "add policy rule", err)
	}
	if _, policyErr := h.store.GetAuthoringCompliancePolicy(ctx, policyID); policyErr != nil {
		if store.IsNotFound(policyErr) {
			return notFound(ctx, errPolicyNotFound, "compliance policy not found")
		}
		return h.internal(ctx, "classify missing policy", policyErr)
	}
	if _, actionErr := h.store.GetManifestAction(ctx, actionID); actionErr != nil {
		if store.IsNotFound(actionErr) {
			return notFound(ctx, errActionNotFound, "action not found")
		}
		return h.internal(ctx, "classify missing compliance action", actionErr)
	}
	return h.internal(ctx, "add policy rule", err)
}

func policyToProto(row store.CompliancePolicyRow, ruleCount int64, rules []store.CompliancePolicyRuleView) *pmv1.CompliancePolicy {
	policy := &pmv1.CompliancePolicy{
		Id: row.ID, Name: row.Name, Description: row.Description,
		RuleCount: boundedCount(ruleCount), CreatedBy: row.CreatedBy,
	}
	if row.CreatedAt != nil {
		policy.CreatedAt = timestamppb.New(*row.CreatedAt)
	}
	if rules != nil {
		policy.Rules = make([]*pmv1.CompliancePolicyRule, len(rules))
		for i, rule := range rules {
			policy.Rules[i] = &pmv1.CompliancePolicyRule{
				ActionId: rule.ActionID, ActionName: rule.ActionName,
				GracePeriodHours: rule.GracePeriodHours,
			}
		}
	}
	return policy
}

func validPageToken(token string) bool {
	if token == "" {
		return true
	}
	_, err := ulid.ParseStrict(token)
	return err == nil
}

func boundedCount(n int64) int32 {
	if n > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(n)
}

func rpcError(ctx context.Context, code string, connectCode connect.Code, message string) *connect.Error {
	err := connect.NewError(connectCode, errors.New(message))
	detail, detailErr := connect.NewErrorDetail(&pmv1.ErrorDetail{
		Code: code, RequestId: middleware.RequestIDFromContext(ctx),
	})
	if detailErr == nil {
		err.AddDetail(detail)
	}
	return err
}

func notFound(ctx context.Context, code, message string) *connect.Error {
	return rpcError(ctx, code, connect.CodeNotFound, message)
}

// MountPolicies registers exactly the explicit compliance-policy CRUD surface.
func (h *Handlers) MountPolicies(mux *http.ServeMux, opts ...connect.HandlerOption) []string {
	if mux == nil {
		panic("compliance: mux is required")
	}
	mounted := make([]string, 0, 9)
	register := func(procedure string, handler http.Handler) {
		mux.Handle(procedure, handler)
		mounted = append(mounted, procedure)
	}
	register(powermanagev1connect.ControlServiceCreateCompliancePolicyProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceCreateCompliancePolicyProcedure, h.CreateCompliancePolicy, opts...))
	register(powermanagev1connect.ControlServiceGetCompliancePolicyProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceGetCompliancePolicyProcedure, h.GetCompliancePolicy, opts...))
	register(powermanagev1connect.ControlServiceListCompliancePoliciesProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceListCompliancePoliciesProcedure, h.ListCompliancePolicies, opts...))
	register(powermanagev1connect.ControlServiceRenameCompliancePolicyProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceRenameCompliancePolicyProcedure, h.RenameCompliancePolicy, opts...))
	register(powermanagev1connect.ControlServiceUpdateCompliancePolicyDescriptionProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceUpdateCompliancePolicyDescriptionProcedure, h.UpdateCompliancePolicyDescription, opts...))
	register(powermanagev1connect.ControlServiceDeleteCompliancePolicyProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceDeleteCompliancePolicyProcedure, h.DeleteCompliancePolicy, opts...))
	register(powermanagev1connect.ControlServiceAddCompliancePolicyRuleProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceAddCompliancePolicyRuleProcedure, h.AddCompliancePolicyRule, opts...))
	register(powermanagev1connect.ControlServiceRemoveCompliancePolicyRuleProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceRemoveCompliancePolicyRuleProcedure, h.RemoveCompliancePolicyRule, opts...))
	register(powermanagev1connect.ControlServiceUpdateCompliancePolicyRuleProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceUpdateCompliancePolicyRuleProcedure, h.UpdateCompliancePolicyRule, opts...))
	return mounted
}

// MutationProcedures is the exact audited compliance-policy mutation surface.
func MutationProcedures() []string {
	return []string{
		powermanagev1connect.ControlServiceCreateCompliancePolicyProcedure,
		powermanagev1connect.ControlServiceRenameCompliancePolicyProcedure,
		powermanagev1connect.ControlServiceUpdateCompliancePolicyDescriptionProcedure,
		powermanagev1connect.ControlServiceDeleteCompliancePolicyProcedure,
		powermanagev1connect.ControlServiceAddCompliancePolicyRuleProcedure,
		powermanagev1connect.ControlServiceRemoveCompliancePolicyRuleProcedure,
		powermanagev1connect.ControlServiceUpdateCompliancePolicyRuleProcedure,
	}
}

// ReadProcedures is the exact non-mutating compliance-policy CRUD surface.
func ReadProcedures() []string {
	return []string{
		powermanagev1connect.ControlServiceGetCompliancePolicyProcedure,
		powermanagev1connect.ControlServiceListCompliancePoliciesProcedure,
	}
}
