package searchrpc

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/go-playground/validator/v10"
	"github.com/oklog/ulid/v2"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	sdkvalidate "github.com/manchtools/power-manage-sdk/validate"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
)

const (
	defaultSearchPageSize = int32(50)
	maxSearchOffset       = int32(100_000)
)

type facet struct {
	name       string
	wire       pmv1.SearchScope
	permission string
}

var searchFacets = []facet{
	{name: "actions", wire: pmv1.SearchScope_SEARCH_SCOPE_ACTIONS, permission: "ListActions"},
	{name: "action_sets", wire: pmv1.SearchScope_SEARCH_SCOPE_ACTION_SETS, permission: "ListActionSets"},
	{name: "definitions", wire: pmv1.SearchScope_SEARCH_SCOPE_DEFINITIONS, permission: "ListDefinitions"},
	{name: "compliance_policies", wire: pmv1.SearchScope_SEARCH_SCOPE_COMPLIANCE_POLICIES, permission: "ListCompliancePolicies"},
	{name: "devices", wire: pmv1.SearchScope_SEARCH_SCOPE_DEVICES, permission: "ListDevices"},
	{name: "users", wire: pmv1.SearchScope_SEARCH_SCOPE_USERS, permission: "ListUsers"},
	{name: "device_groups", wire: pmv1.SearchScope_SEARCH_SCOPE_DEVICE_GROUPS, permission: "ListDeviceGroups"},
	{name: "user_groups", wire: pmv1.SearchScope_SEARCH_SCOPE_USER_GROUPS, permission: "ListUserGroups"},
	{name: "executions", wire: pmv1.SearchScope_SEARCH_SCOPE_EXECUTIONS, permission: "ListExecutions"},
	{name: "audit_events", wire: pmv1.SearchScope_SEARCH_SCOPE_AUDIT_EVENTS, permission: "ListAuditEvents"},
}

var sortFields = map[pmv1.SortField]string{
	pmv1.SortField_SORT_FIELD_NAME:              "name",
	pmv1.SortField_SORT_FIELD_TYPE:              "type",
	pmv1.SortField_SORT_FIELD_HOSTNAME:          "hostname",
	pmv1.SortField_SORT_FIELD_COMPLIANCE_STATUS: "compliance_status",
	pmv1.SortField_SORT_FIELD_EMAIL:             "email",
	pmv1.SortField_SORT_FIELD_DISPLAY_NAME:      "display_name",
	pmv1.SortField_SORT_FIELD_DISABLED:          "disabled",
	pmv1.SortField_SORT_FIELD_MEMBER_COUNT:      "member_count",
	pmv1.SortField_SORT_FIELD_STATUS:            "status",
	pmv1.SortField_SORT_FIELD_ACTION_TYPE:       "action_type",
	pmv1.SortField_SORT_FIELD_DEVICE_HOSTNAME:   "device_hostname",
	pmv1.SortField_SORT_FIELD_ACTOR_TYPE:        "actor_type",
	pmv1.SortField_SORT_FIELD_STREAM_TYPE:       "stream_type",
	pmv1.SortField_SORT_FIELD_EVENT_TYPE:        "event_type",
	pmv1.SortField_SORT_FIELD_RULE_COUNT:        "rule_count",
	pmv1.SortField_SORT_FIELD_LAST_LOGIN_AT:     "last_login_at",
	pmv1.SortField_SORT_FIELD_CREATED_AT:        "created_at",
	pmv1.SortField_SORT_FIELD_UPDATED_AT:        "updated_at",
	pmv1.SortField_SORT_FIELD_LAST_SEEN_AT:      "last_seen_at",
	pmv1.SortField_SORT_FIELD_REGISTERED_AT:     "registered_at",
	pmv1.SortField_SORT_FIELD_OCCURRED_AT:       "occurred_at",
}

// Handlers implements PostgreSQL-backed search and its maintenance RPC.
type Handlers struct {
	store     *store.Store
	logger    *slog.Logger
	now       func() time.Time
	validator *validator.Validate
}

// NewHandlers constructs search handlers over authoritative PostgreSQL state.
func NewHandlers(st *store.Store, logger *slog.Logger, now func() time.Time) *Handlers {
	if st == nil {
		panic("search: store is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	if now == nil {
		now = time.Now
	}
	return &Handlers{store: st, logger: logger, now: now, validator: sdkvalidate.NewValidator()}
}

func (h *Handlers) validate(ctx context.Context, message any) error {
	if detail, ok := sdkvalidate.Struct(h.validator, message); !ok {
		return rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument, detail)
	}
	return nil
}

func validateRequest[T any](h *Handlers, ctx context.Context, req *connect.Request[T]) error {
	if req == nil || req.Msg == nil {
		return rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument, "request is required")
	}
	return h.validate(ctx, req.Msg)
}

func (h *Handlers) actor(ctx context.Context) (*auth.UserContext, error) {
	actor, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, rpcError(ctx, errNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}
	return actor, nil
}

func (h *Handlers) authorize(ctx context.Context, permission string) error {
	if !auth.AuthorizeContext(ctx, permission, "") {
		return rpcError(ctx, errPermissionDenied, connect.CodePermissionDenied, "permission denied")
	}
	return nil
}

func (h *Handlers) internal(ctx context.Context, operation string, err error) *connect.Error {
	h.logger.Error("search RPC failed", "operation", operation, "error", err)
	return rpcError(ctx, errInternal, connect.CodeInternal, "internal error")
}

func (h *Handlers) operation(req connect.AnyRequest, actor *auth.UserContext, class store.OperationClass, procedure, permission string) store.AuditOperation {
	op := store.AuditOperation{
		Class: class, ActorType: string(actor.Kind), Origin: auth.ControlRPCOrigin,
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

// Search returns one deterministic PostgreSQL FTS page per requested facet.
func (h *Handlers) Search(ctx context.Context, req *connect.Request[pmv1.SearchRequest]) (*connect.Response[pmv1.SearchResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "Search"); err != nil {
		return nil, err
	}

	query := strings.TrimSpace(req.Msg.Query)
	if query == "" && req.Msg.Scope == pmv1.SearchScope_SEARCH_SCOPE_UNSPECIFIED && len(req.Msg.DateFilters) == 0 && len(req.Msg.TagFilters) == 0 {
		return connect.NewResponse(&pmv1.SearchResponse{}), nil
	}
	pageSize := req.Msg.PageSize
	if pageSize == 0 {
		pageSize = defaultSearchPageSize
	}
	offset, err := searchOffset(req.Msg.PageToken)
	if err != nil {
		return nil, rpcError(ctx, errInvalidPageToken, connect.CodeInvalidArgument, "invalid page token")
	}
	selected, err := selectedFacets(req.Msg.Scope)
	if err != nil {
		return nil, rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument, "invalid search scope")
	}

	dateRanges := make([]store.SearchDateRange, 0, len(req.Msg.DateFilters))
	for _, filter := range req.Msg.DateFilters {
		if filter == nil {
			return nil, rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument, "invalid date filter")
		}
		dateRanges = append(dateRanges, store.SearchDateRange{Field: filter.Field, Start: filter.Start, End: filter.End})
	}
	tagFilters := make(map[string][]string, len(req.Msg.TagFilters))
	for field, value := range req.Msg.TagFilters {
		tagFilters[field] = strings.Split(value, "|")
	}
	sortField := ""
	if req.Msg.SortField != pmv1.SortField_SORT_FIELD_UNSPECIFIED {
		var ok bool
		sortField, ok = sortFields[req.Msg.SortField]
		if !ok {
			return nil, rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument, "invalid sort field")
		}
	}

	response := &pmv1.SearchResponse{}
	var total int64
	var auditCount int64
	more := false
	for _, current := range selected {
		if !h.facetAllowed(ctx, actor, current) {
			if req.Msg.Scope != pmv1.SearchScope_SEARCH_SCOPE_UNSPECIFIED {
				return nil, rpcError(ctx, errPermissionDenied, connect.CodePermissionDenied, "permission denied")
			}
			continue
		}
		params := store.SearchParams{
			Scope: current.name, Query: query, Offset: offset, Limit: pageSize,
			DateRanges: dateRanges, TagFilters: tagFilters, SortField: sortField,
			Descending:  req.Msg.SortDirection != pmv1.SortDirection_SORT_DIRECTION_ASC,
			OnlineSince: h.now().UTC().Add(-5 * time.Minute),
		}
		h.applyScope(ctx, actor, current.name, &params)
		rows, count, searchErr := h.store.Search(ctx, params)
		if searchErr != nil {
			if errors.Is(searchErr, store.ErrInvalidSearch) {
				return nil, rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument, "invalid search filter or sort")
			}
			return nil, h.internal(ctx, "query postgres", searchErr)
		}
		for _, row := range rows {
			response.Results = append(response.Results, &pmv1.SearchResult{
				Id: row.ID, Name: row.Name, Description: row.Description, Scope: current.wire,
				MemberCount: boundedInt32(row.MemberCount), Fields: row.Fields,
			})
		}
		total += count
		if int64(offset)+int64(pageSize) < count {
			more = true
		}
		if current.name == "audit_events" {
			auditCount = int64(len(rows))
		}
	}

	if req.Msg.Scope == pmv1.SearchScope_SEARCH_SCOPE_AUDIT_EVENTS {
		op := h.operation(req, actor, store.ClassSensitiveRead,
			powermanagev1connect.ControlServiceSearchProcedure, "ListAuditEvents")
		op.OperationID = ulid.Make().String()
		if _, err := h.store.RecordOperation(ctx, op, store.AuditEffect{
			ResourceType: "audit_log", ResourceID: op.OperationID,
			Action: "SEARCH", Outcome: store.EffectApplied, AfterCount: &auditCount,
		}); err != nil {
			return nil, h.internal(ctx, "record audit search", err)
		}
	}
	response.TotalCount = boundedInt32(total)
	if more {
		response.NextPageToken = strconv.FormatInt(int64(offset)+int64(pageSize), 10)
	}
	return connect.NewResponse(response), nil
}

// RebuildSearchIndex performs explicit physical maintenance on the generated
// PostgreSQL search indexes and records the operation atomically.
func (h *Handlers) RebuildSearchIndex(ctx context.Context, req *connect.Request[pmv1.RebuildSearchIndexRequest]) (*connect.Response[pmv1.RebuildSearchIndexResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "RebuildSearchIndex"); err != nil {
		return nil, err
	}
	op := h.operation(req, actor, store.ClassMutation,
		powermanagev1connect.ControlServiceRebuildSearchIndexProcedure, "RebuildSearchIndex")
	if err := h.store.RebuildSearchIndexes(ctx, op); err != nil {
		return nil, h.internal(ctx, "rebuild postgres indexes", err)
	}
	return connect.NewResponse(&pmv1.RebuildSearchIndexResponse{}), nil
}

func selectedFacets(scope pmv1.SearchScope) ([]facet, error) {
	if scope == pmv1.SearchScope_SEARCH_SCOPE_UNSPECIFIED {
		return searchFacets[:8], nil
	}
	for _, current := range searchFacets {
		if current.wire == scope {
			return []facet{current}, nil
		}
	}
	return nil, store.ErrInvalidSearch
}

func (h *Handlers) facetAllowed(ctx context.Context, actor *auth.UserContext, current facet) bool {
	if current.name == "devices" && auth.HasPermission(ctx, "ListDevices:assigned") && actor.CanOwnResources() {
		return true
	}
	return auth.HasPermission(ctx, current.permission)
}

func (h *Handlers) applyScope(ctx context.Context, actor *auth.UserContext, name string, params *store.SearchParams) {
	switch name {
	case "actions", "action_sets", "definitions", "compliance_policies":
		params.ScopeGroupIDs, params.ScopeRestricted = auth.ObjectScopeListFilter(ctx)
	case "devices":
		if !auth.HasPermission(ctx, "ListDevices") {
			params.AssignedUserID = &actor.ID
			return
		}
		params.ScopeGroupIDs, params.ScopeRestricted = auth.DeviceScopeListFilter(ctx, "ListDevices")
	case "device_groups":
		params.ScopeGroupIDs, params.ScopeRestricted = auth.DeviceScopeListFilter(ctx, "ListDeviceGroups")
	case "users":
		params.ScopeGroupIDs, params.ScopeRestricted = auth.UserScopeListFilter(ctx, "ListUsers")
	case "user_groups":
		params.ScopeGroupIDs, params.ScopeRestricted = auth.UserScopeListFilter(ctx, "ListUserGroups")
	case "executions":
		params.ScopeGroupIDs, params.ScopeRestricted = auth.DeviceScopeListFilter(ctx, "ListExecutions")
	}
}

func searchOffset(token string) (int32, error) {
	if token == "" {
		return 0, nil
	}
	offset, err := strconv.ParseInt(token, 10, 32)
	if err != nil || offset < 0 || offset > int64(maxSearchOffset) {
		return 0, store.ErrInvalidSearch
	}
	return int32(offset), nil
}

func boundedInt32(value int64) int32 {
	if value > math.MaxInt32 {
		return math.MaxInt32
	}
	if value < math.MinInt32 {
		return math.MinInt32
	}
	return int32(value)
}
