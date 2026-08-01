package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// Reads are exported one at a time rather than by handing out the
// generated query surface. A read method cannot become a write by
// accident, and the set of things a caller can do to the database
// stays enumerable: this file plus WithAudit.

// AuditOperationRow is one stored operation row.
type AuditOperationRow = generated.AuditOperation

// AuditEffectRow is one stored effect row.
type AuditEffectRow = generated.AuditEffect

// AuditEventRow is one safe read-side projection of the append-only audit
// evidence. Its query deliberately cannot select either sealed-detail column.
type AuditEventRow = generated.ListAuditEventRowsRow

// AuditEventFilter is the common keyset/filter surface used by list and
// export. Empty bounds cover the full supported PostgreSQL timestamp range.
type AuditEventFilter struct {
	ActorID      string
	StreamTypes  []string
	EventType    string
	OccurredFrom time.Time
	OccurredTo   time.Time
	BeforeSeq    int64
	Limit        int32
}

// DeviceRow is one stored device.
type DeviceRow = generated.Device

// DeliveryRow is one durable manifest delivery.
type DeliveryRow = generated.Delivery

// JobRow is one durable scheduled job.
type JobRow = generated.Job

// ActionRow is one live authored action used to compile agent manifests.
type ActionRow = generated.Action

// ActionListFilter contains the keyset, type, assignment and object-scope
// narrowing shared by the Action list and count reads.
type ActionListFilter struct {
	AfterID         string
	Limit           int32
	Type            int32
	UnassignedOnly  bool
	ScopeRestricted bool
	ScopeGroupIDs   []string
}

// AssignmentTarget is one live target reached from an authored source.
type AssignmentTarget = generated.ListAuthoringAssignmentsForSourceRow

// AssignmentView is one live assignment with operator-facing source and
// target names resolved from live rows.
type AssignmentView struct {
	ID         string
	SourceType string
	SourceID   string
	TargetType string
	TargetID   string
	Mode       int32
	CreatedAt  *time.Time
	CreatedBy  string
	SourceName string
	TargetName string
}

// ResolvedAssignmentSource is one live source/mode path that reaches a device,
// with its current optional selection state.
type ResolvedAssignmentSource = generated.ListResolvedAssignmentSourcesForDeviceRow

// UserSelectionRow is one device/source selection.
type UserSelectionRow = generated.UserSelection

// AssignmentListFilter is the deterministic keyset and exact-match filter
// shared by assignment list and count reads.
type AssignmentListFilter struct {
	AfterID    string
	Limit      int32
	SourceType string
	SourceID   string
	TargetType string
	TargetID   string
}

// DeviceGroupView is one live device group with a member count derived from
// live membership rows.
type DeviceGroupView = generated.GetDeviceGroupRow

// DeviceGroupMemberView is one live member device.
type DeviceGroupMemberView = generated.ListDeviceGroupMembersRow

// DynamicDeviceView is the current device state consumed by the in-process
// dynamic-group evaluator.
type DynamicDeviceView = generated.ListDevicesForDynamicEvaluationRow

// DeviceGroupListFilter contains the keyset and device-group scope shared by
// the list and count reads.
type DeviceGroupListFilter struct {
	AfterID         string
	Limit           int32
	ScopeRestricted bool
	ScopeGroupIDs   []string
}

// GetDeviceGroupID returns one live device-group identifier.
func (s *Store) GetDeviceGroupID(ctx context.Context, id string) (string, error) {
	rowID, err := s.queries.GetDeviceGroupID(ctx, id)
	if err != nil {
		return "", fmt.Errorf("device group: get: %w", translateNotFound(err))
	}
	return rowID, nil
}

// GetDeviceGroup returns one live device group.
func (s *Store) GetDeviceGroup(ctx context.Context, id string) (DeviceGroupView, error) {
	row, err := s.queries.GetDeviceGroup(ctx, id)
	if err != nil {
		return DeviceGroupView{}, fmt.Errorf("device group: get: %w", translateNotFound(err))
	}
	return row, nil
}

// ListDeviceGroupMembers returns live devices in stable identifier order.
func (s *Store) ListDeviceGroupMembers(ctx context.Context, id string) ([]DeviceGroupMemberView, error) {
	rows, err := s.queries.ListDeviceGroupMembers(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("device group: list members: %w", err)
	}
	return rows, nil
}

// ListDevicesForDynamicEvaluation returns every live device with the labels,
// inventory and group names understood by the retained query language.
func (s *Store) ListDevicesForDynamicEvaluation(ctx context.Context) ([]DynamicDeviceView, error) {
	rows, err := s.queries.ListDevicesForDynamicEvaluation(ctx)
	if err != nil {
		return nil, fmt.Errorf("device group: list evaluation devices: %w", err)
	}
	return rows, nil
}

// ListDeviceGroups returns a deterministic keyset page.
func (s *Store) ListDeviceGroups(ctx context.Context, filter DeviceGroupListFilter) ([]DeviceGroupView, error) {
	if filter.Limit < 0 || filter.Limit > 101 {
		return nil, fmt.Errorf("device group: list limit must be between 0 and 101")
	}
	if filter.Limit == 0 {
		filter.Limit = 50
	}
	rows, err := s.queries.ListDeviceGroups(ctx, generated.ListDeviceGroupsParams{
		AfterID: filter.AfterID, RowLimit: filter.Limit,
		ScopeRestricted: filter.ScopeRestricted, ScopeGroupIds: filter.ScopeGroupIDs,
	})
	if err != nil {
		return nil, fmt.Errorf("device group: list: %w", err)
	}
	groups := make([]DeviceGroupView, len(rows))
	for i, row := range rows {
		groups[i] = DeviceGroupView(row)
	}
	return groups, nil
}

// CountDeviceGroups counts the same scope selected by ListDeviceGroups.
func (s *Store) CountDeviceGroups(ctx context.Context, filter DeviceGroupListFilter) (int64, error) {
	n, err := s.queries.CountDeviceGroups(ctx, generated.CountDeviceGroupsParams{
		ScopeRestricted: filter.ScopeRestricted, ScopeGroupIds: filter.ScopeGroupIDs,
	})
	if err != nil {
		return 0, fmt.Errorf("device group: count: %w", err)
	}
	return n, nil
}

// ListDeviceGroupsForDevice returns the visible live groups containing one
// device.
func (s *Store) ListDeviceGroupsForDevice(ctx context.Context, deviceID string, filter DeviceGroupListFilter) ([]DeviceGroupView, error) {
	rows, err := s.queries.ListDeviceGroupsForDevice(ctx, generated.ListDeviceGroupsForDeviceParams{
		DeviceID: deviceID, ScopeRestricted: filter.ScopeRestricted, ScopeGroupIds: filter.ScopeGroupIDs,
	})
	if err != nil {
		return nil, fmt.Errorf("device group: list for device: %w", err)
	}
	groups := make([]DeviceGroupView, len(rows))
	for i, row := range rows {
		groups[i] = DeviceGroupView(row)
	}
	return groups, nil
}

// ActionSetRow is one live authored action set used to compile agent manifests.
type ActionSetRow = generated.ActionSet

// ActionSetListFilter contains the keyset, assignment and object-scope
// narrowing shared by the ActionSet list and count reads.
type ActionSetListFilter struct {
	AfterID         string
	Limit           int32
	UnassignedOnly  bool
	ScopeRestricted bool
	ScopeGroupIDs   []string
}

// ActionSetView is one authored set with its member count derived from the
// live edge rows rather than stored projector state.
type ActionSetView struct {
	ActionSetRow
	MemberCount int64
}

// ActionSetMemberView is one live action edge in authored execution order.
type ActionSetMemberView = generated.ListActionSetMembersRow

// DefinitionRow is one live authored definition used to compile agent manifests.
type DefinitionRow = generated.Definition

// DefinitionListFilter contains the keyset and object-scope narrowing shared
// by the Definition list and count reads.
type DefinitionListFilter struct {
	AfterID         string
	Limit           int32
	ScopeRestricted bool
	ScopeGroupIDs   []string
}

// DefinitionView is one authored definition with its member count derived
// from live ActionSets rather than the legacy stored counter.
type DefinitionView struct {
	DefinitionRow
	LiveMemberCount int64
}

// DefinitionMemberView is one live ActionSet edge in authored order.
type DefinitionMemberView = generated.ListDefinitionMembersRow

// DefinitionManifestAction pairs one authored action with the set through
// which the containing definition reaches it.
type DefinitionManifestAction struct {
	ActionSetID string
	Action      ActionRow
}

// CompliancePolicyRow is one live authored compliance policy.
type CompliancePolicyRow = generated.CompliancePolicy

// CompliancePolicyListFilter contains the keyset and object-scope narrowing
// shared by the policy list and count reads.
type CompliancePolicyListFilter struct {
	AfterID         string
	Limit           int32
	ScopeRestricted bool
	ScopeGroupIDs   []string
}

// CompliancePolicyView derives its rule count from live Actions.
type CompliancePolicyView struct {
	CompliancePolicyRow
	LiveRuleCount int64
}

// CompliancePolicyRuleView is one live policy rule.
type CompliancePolicyRuleView = generated.ListCompliancePolicyRulesRow

// DeviceStatusFilter selects the server-derived online state for a device
// listing. Zero keeps both states.
type DeviceStatusFilter int32

const (
	DeviceStatusAny     DeviceStatusFilter = 0
	DeviceStatusOnline  DeviceStatusFilter = 1
	DeviceStatusOffline DeviceStatusFilter = 2
)

// DeviceListFilter contains every narrowing rule shared by ListDeviceViews
// and CountDeviceViews. OnlineSince is normally now minus five minutes.
type DeviceListFilter struct {
	AfterID         string
	Limit           int32
	Status          DeviceStatusFilter
	OnlineSince     time.Time
	Labels          map[string]string
	AssignedUserID  *string
	ScopeRestricted bool
	ScopeGroupIDs   []string
}

// DeviceView is the complete device read model exposed to handlers.
type DeviceView struct {
	DeviceRow
	Labels                           map[string]string
	AssignedUserIDs                  []string
	AssignedGroupIDs                 []string
	LastInventoryAt                  *time.Time
	ResolvedInventoryIntervalMinutes int32
}

// DeviceAssigneeView is one live user or user group assigned to a device.
type DeviceAssigneeView struct {
	ID   string
	Kind string
	Name string
}

// DeviceInventoryTable is one latest collected osquery table for a device.
type DeviceInventoryTable = generated.ListDeviceInventoryRow

// OSQueryResult is one current on-demand query result.
type OSQueryResult = generated.GetOSQueryResultRow

// DeviceLogResult is one current remote log query result.
type DeviceLogResult = generated.GetDeviceLogResultRow

// DeviceComplianceResult is one current action check for a device.
type DeviceComplianceResult = generated.ListDeviceComplianceResultsRow

// DeviceComplianceEvaluation is one current policy-rule evaluation for a
// device.
type DeviceComplianceEvaluation = generated.ListDeviceComplianceEvaluationsRow

// DefaultInventoryIntervalMinutes is the server cadence used when neither a
// device nor any live device group supplies an inventory interval.
const DefaultInventoryIntervalMinutes int32 = 1440

// UserRow is one stored user.
type UserRow = generated.User

// AuditChainTip is a stream's current chain position.
type AuditChainTip struct {
	Stream   string
	HeadHash []byte
	Height   int64
}

// GetAuditOperation returns one operation row. ErrNotFound when the
// operation is unknown or has been archived away by retention.
func (s *Store) GetAuditOperation(ctx context.Context, operationID string) (AuditOperationRow, error) {
	row, err := s.queries.GetAuditOperation(ctx, operationID)
	if err != nil {
		return AuditOperationRow{}, fmt.Errorf("audit: get operation: %w", translateNotFound(err))
	}
	return row, nil
}

// ListAuditEffects returns an operation's effects in the order they
// were recorded, including any appended long after the operation
// itself.
func (s *Store) ListAuditEffects(ctx context.Context, operationID string) ([]AuditEffectRow, error) {
	rows, err := s.queries.ListAuditEffectsForOperation(ctx, operationID)
	if err != nil {
		return nil, fmt.Errorf("audit: list effects: %w", err)
	}
	return rows, nil
}

// ListAuditEventRows returns newest-first effect evidence plus operation-only
// evidence. The SQL projection is allowlisted and never reads sealed detail.
func (s *Store) ListAuditEventRows(ctx context.Context, filter AuditEventFilter) ([]AuditEventRow, error) {
	if filter.Limit < 1 || filter.Limit > 1001 {
		return nil, fmt.Errorf("audit: list limit must be between 1 and 1001")
	}
	if filter.BeforeSeq < 0 {
		return nil, fmt.Errorf("audit: list cursor must not be negative")
	}
	if filter.OccurredFrom.IsZero() {
		filter.OccurredFrom = time.Unix(0, 0).UTC()
	}
	if filter.OccurredTo.IsZero() {
		filter.OccurredTo = time.Date(9999, 12, 31, 23, 59, 59, 999999000, time.UTC)
	}
	if filter.OccurredFrom.After(filter.OccurredTo) {
		return nil, fmt.Errorf("audit: occurred-from must not follow occurred-to")
	}
	if filter.StreamTypes == nil {
		filter.StreamTypes = []string{}
	}
	rows, err := s.queries.ListAuditEventRows(ctx, generated.ListAuditEventRowsParams{
		ActorID:      filter.ActorID,
		StreamTypes:  filter.StreamTypes,
		EventType:    filter.EventType,
		OccurredFrom: pgtype.Timestamptz{Time: filter.OccurredFrom, Valid: true},
		OccurredTo:   pgtype.Timestamptz{Time: filter.OccurredTo, Valid: true},
		BeforeSeq:    filter.BeforeSeq,
		RowLimit:     filter.Limit,
	})
	if err != nil {
		return nil, fmt.Errorf("audit: list event rows: %w", err)
	}
	return rows, nil
}

// CountAuditEventRows counts the same actor/resource/action selection as the
// list RPC. Export does not need a count and applies its date range directly.
func (s *Store) CountAuditEventRows(ctx context.Context, filter AuditEventFilter) (int64, error) {
	if filter.StreamTypes == nil {
		filter.StreamTypes = []string{}
	}
	n, err := s.queries.CountAuditEventRows(ctx, generated.CountAuditEventRowsParams{
		ActorID: filter.ActorID, StreamTypes: filter.StreamTypes, EventType: filter.EventType,
	})
	if err != nil {
		return 0, fmt.Errorf("audit: count event rows: %w", err)
	}
	return n, nil
}

// AuditChainTipOf returns the stream's current head without locking it.
func (s *Store) AuditChainTipOf(ctx context.Context, stream string) (AuditChainTip, error) {
	if stream == "" {
		stream = DefaultAuditStream
	}
	row, err := s.queries.GetAuditChainHead(ctx, stream)
	if err != nil {
		return AuditChainTip{}, fmt.Errorf("audit: chain head: %w", translateNotFound(err))
	}
	return AuditChainTip{Stream: row.Stream, HeadHash: row.HeadHash, Height: row.Height}, nil
}

// CountAuditOperations returns how many operation rows a stream
// currently holds.
func (s *Store) CountAuditOperations(ctx context.Context, stream string) (int64, error) {
	if stream == "" {
		stream = DefaultAuditStream
	}
	n, err := s.queries.CountAuditOperations(ctx, stream)
	if err != nil {
		return 0, fmt.Errorf("audit: count operations: %w", err)
	}
	return n, nil
}

// GetDevice returns one live device. ErrNotFound when it is unknown or
// deleted.
func (s *Store) GetDevice(ctx context.Context, id string) (DeviceRow, error) {
	row, err := s.queries.GetDevice(ctx, id)
	if err != nil {
		return DeviceRow{}, fmt.Errorf("device: get: %w", translateNotFound(err))
	}
	return row, nil
}

// CountDevices returns the number of live devices.
func (s *Store) CountDevices(ctx context.Context) (int64, error) {
	n, err := s.queries.CountDevices(ctx)
	if err != nil {
		return 0, fmt.Errorf("device: count: %w", err)
	}
	return n, nil
}

// CountActions returns the number of live, operator-authored actions.
func (s *Store) CountActions(ctx context.Context) (int64, error) {
	return s.CountAuthoringActions(ctx, ActionListFilter{})
}

// ListAuthoringActions returns a deterministic keyset page of live,
// operator-visible Actions. System actions never enter this read surface.
func (s *Store) ListAuthoringActions(ctx context.Context, filter ActionListFilter) ([]ActionRow, error) {
	rows, err := s.queries.ListAuthoringActions(ctx, generated.ListAuthoringActionsParams{
		AfterID: filter.AfterID, TypeFilter: filter.Type,
		UnassignedOnly: filter.UnassignedOnly, ScopeRestricted: filter.ScopeRestricted,
		RowLimit: filter.Limit, ScopeGroupIds: filter.ScopeGroupIDs,
	})
	if err != nil {
		return nil, fmt.Errorf("action: list: %w", err)
	}
	return rows, nil
}

// CountAuthoringActions counts the same Action population selected by the
// list filter, ignoring its keyset and limit.
func (s *Store) CountAuthoringActions(ctx context.Context, filter ActionListFilter) (int64, error) {
	n, err := s.queries.CountAuthoringActions(ctx, generated.CountAuthoringActionsParams{
		TypeFilter: filter.Type, UnassignedOnly: filter.UnassignedOnly,
		ScopeRestricted: filter.ScopeRestricted, ScopeGroupIds: filter.ScopeGroupIDs,
	})
	if err != nil {
		return 0, fmt.Errorf("action: count: %w", err)
	}
	return n, nil
}

// ListAuthoringAssignmentTargets returns the live assignment targets for one
// Action, ActionSet, Definition, or compliance-policy source.
func (s *Store) ListAuthoringAssignmentTargets(ctx context.Context, sourceType, sourceID string) ([]AssignmentTarget, error) {
	rows, err := s.queries.ListAuthoringAssignmentsForSource(ctx, generated.ListAuthoringAssignmentsForSourceParams{
		SourceType: sourceType, SourceID: sourceID,
	})
	if err != nil {
		return nil, fmt.Errorf("authoring: list assignment targets: %w", err)
	}
	return rows, nil
}

// GetAssignment returns one live assignment whose source and target still
// exist.
func (s *Store) GetAssignment(ctx context.Context, id string) (AssignmentView, error) {
	row, err := s.queries.GetAssignmentByID(ctx, id)
	if err != nil {
		return AssignmentView{}, fmt.Errorf("assignment: get: %w", translateNotFound(err))
	}
	return AssignmentView{
		ID: row.ID, SourceType: row.SourceType, SourceID: row.SourceID,
		TargetType: row.TargetType, TargetID: row.TargetID, Mode: row.Mode,
		CreatedAt: row.CreatedAt, CreatedBy: row.CreatedBy,
		SourceName: row.ResolvedSourceName, TargetName: row.ResolvedTargetName,
	}, nil
}

// FindAssignment returns the live row for one source-target tuple.
func (s *Store) FindAssignment(ctx context.Context, sourceType, sourceID, targetType, targetID string) (AssignmentView, error) {
	row, err := s.queries.GetAssignmentByTuple(ctx, generated.GetAssignmentByTupleParams{
		SourceType: sourceType, SourceID: sourceID, TargetType: targetType, TargetID: targetID,
	})
	if err != nil {
		return AssignmentView{}, fmt.Errorf("assignment: find: %w", translateNotFound(err))
	}
	return AssignmentView{
		ID: row.ID, SourceType: row.SourceType, SourceID: row.SourceID,
		TargetType: row.TargetType, TargetID: row.TargetID, Mode: row.Mode,
		CreatedAt: row.CreatedAt, CreatedBy: row.CreatedBy,
		SourceName: row.SourceName, TargetName: row.TargetName,
	}, nil
}

// ListAssignments returns a stable keyset page of live assignments.
func (s *Store) ListAssignments(ctx context.Context, filter AssignmentListFilter) ([]AssignmentView, error) {
	if filter.Limit < 0 || filter.Limit > 101 {
		return nil, fmt.Errorf("assignment: list limit must be between 0 and 101")
	}
	if filter.Limit == 0 {
		filter.Limit = 50
	}
	rows, err := s.queries.ListAssignmentViews(ctx, generated.ListAssignmentViewsParams{
		AfterID: filter.AfterID, SourceType: filter.SourceType, SourceID: filter.SourceID,
		TargetType: filter.TargetType, TargetID: filter.TargetID, RowLimit: filter.Limit,
	})
	if err != nil {
		return nil, fmt.Errorf("assignment: list: %w", err)
	}
	views := make([]AssignmentView, len(rows))
	for i, row := range rows {
		views[i] = AssignmentView{
			ID: row.ID, SourceType: row.SourceType, SourceID: row.SourceID,
			TargetType: row.TargetType, TargetID: row.TargetID, Mode: row.Mode,
			CreatedAt: row.CreatedAt, CreatedBy: row.CreatedBy,
			SourceName: row.ResolvedSourceName, TargetName: row.ResolvedTargetName,
		}
	}
	return views, nil
}

// CountAssignments counts the same population selected by ListAssignments.
func (s *Store) CountAssignments(ctx context.Context, filter AssignmentListFilter) (int64, error) {
	n, err := s.queries.CountAssignmentViews(ctx, generated.CountAssignmentViewsParams{
		SourceType: filter.SourceType, SourceID: filter.SourceID,
		TargetType: filter.TargetType, TargetID: filter.TargetID,
	})
	if err != nil {
		return 0, fmt.Errorf("assignment: count: %w", err)
	}
	return n, nil
}

// ListAssignmentsForUser returns live direct and group-targeted assignments in
// stable identifier order.
func (s *Store) ListAssignmentsForUser(ctx context.Context, userID string) ([]AssignmentView, error) {
	rows, err := s.queries.ListAssignmentViewsForUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("assignment: list for user: %w", err)
	}
	views := make([]AssignmentView, len(rows))
	for i, row := range rows {
		views[i] = AssignmentView{
			ID: row.ID, SourceType: row.SourceType, SourceID: row.SourceID,
			TargetType: row.TargetType, TargetID: row.TargetID, Mode: row.Mode,
			CreatedAt: row.CreatedAt, CreatedBy: row.CreatedBy,
			SourceName: row.ResolvedSourceName, TargetName: row.ResolvedTargetName,
		}
	}
	return views, nil
}

// ListAvailableSources resolves direct, device-group, assigned-user and
// assigned-user-group targets to one source list for a device.
func (s *Store) ListAvailableSources(ctx context.Context, deviceID string) ([]ResolvedAssignmentSource, error) {
	rows, err := s.ListResolvedSources(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	// A source reached through a stronger mode is not an optional choice,
	// even if another target path reaches it as AVAILABLE.
	nonOptional := make(map[string]bool, len(rows))
	for _, row := range rows {
		if row.Mode != 1 {
			nonOptional[row.SourceType+":"+row.SourceID] = true
		}
	}
	available := make([]ResolvedAssignmentSource, 0, len(rows))
	for _, row := range rows {
		if row.Mode == 1 && !nonOptional[row.SourceType+":"+row.SourceID] {
			available = append(available, row)
		}
	}
	return available, nil
}

// ListResolvedSources returns every live source/mode path that reaches a
// device. Callers decide how the assignment modes combine for their response.
func (s *Store) ListResolvedSources(ctx context.Context, deviceID string) ([]ResolvedAssignmentSource, error) {
	rows, err := s.queries.ListResolvedAssignmentSourcesForDevice(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("assignment: list resolved sources: %w", err)
	}
	return rows, nil
}

// ListContainingActionSetIDs returns the live sets that directly contain an
// Action.
func (s *Store) ListContainingActionSetIDs(ctx context.Context, actionID string) ([]string, error) {
	ids, err := s.queries.ListContainingActionSetIDs(ctx, actionID)
	if err != nil {
		return nil, fmt.Errorf("authoring: list containing action sets: %w", err)
	}
	return ids, nil
}

// ListContainingDefinitionIDs returns the live Definitions that directly
// contain an ActionSet.
func (s *Store) ListContainingDefinitionIDs(ctx context.Context, actionSetID string) ([]string, error) {
	ids, err := s.queries.ListContainingDefinitionIDs(ctx, actionSetID)
	if err != nil {
		return nil, fmt.Errorf("authoring: list containing definitions: %w", err)
	}
	return ids, nil
}

// ListCompliancePolicyIDsForAction returns the live policies that directly
// contain an Action.
func (s *Store) ListCompliancePolicyIDsForAction(ctx context.Context, actionID string) ([]string, error) {
	ids, err := s.queries.ListContainingCompliancePolicyIDs(ctx, actionID)
	if err != nil {
		return nil, fmt.Errorf("compliance policy: list containing policies: %w", err)
	}
	return ids, nil
}

// CountActionSets returns the number of live authored sets.
func (s *Store) CountActionSets(ctx context.Context) (int64, error) {
	return s.CountAuthoringActionSets(ctx, ActionSetListFilter{})
}

// ListAuthoringActionSets returns a deterministic keyset page of live sets
// with member counts derived from live Actions.
func (s *Store) ListAuthoringActionSets(ctx context.Context, filter ActionSetListFilter) ([]ActionSetView, error) {
	rows, err := s.queries.ListAuthoringActionSets(ctx, generated.ListAuthoringActionSetsParams{
		AfterID: filter.AfterID, UnassignedOnly: filter.UnassignedOnly,
		ScopeRestricted: filter.ScopeRestricted, RowLimit: filter.Limit,
		ScopeGroupIds: filter.ScopeGroupIDs,
	})
	if err != nil {
		return nil, fmt.Errorf("action set: list: %w", err)
	}
	views := make([]ActionSetView, len(rows))
	for i, row := range rows {
		views[i] = ActionSetView{ActionSetRow: ActionSetRow{
			ID: row.ID, Name: row.Name, Description: row.Description,
			Schedule: row.Schedule, OnFailure: row.OnFailure,
			CreatedAt: row.CreatedAt, CreatedBy: row.CreatedBy, UpdatedAt: row.UpdatedAt,
			IsDeleted: row.IsDeleted, SearchTsv: row.SearchTsv,
		}, MemberCount: row.MemberCount}
	}
	return views, nil
}

// CountAuthoringActionSets counts the same set population selected by the
// list filter, ignoring its keyset and limit.
func (s *Store) CountAuthoringActionSets(ctx context.Context, filter ActionSetListFilter) (int64, error) {
	n, err := s.queries.CountAuthoringActionSets(ctx, generated.CountAuthoringActionSetsParams{
		UnassignedOnly: filter.UnassignedOnly, ScopeRestricted: filter.ScopeRestricted,
		ScopeGroupIds: filter.ScopeGroupIDs,
	})
	if err != nil {
		return 0, fmt.Errorf("action set: count: %w", err)
	}
	return n, nil
}

// ListActionSetMembers returns live action members in authored order.
func (s *Store) ListActionSetMembers(ctx context.Context, id string) ([]ActionSetMemberView, error) {
	rows, err := s.queries.ListActionSetMembers(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("action set: list members: %w", err)
	}
	return rows, nil
}

// CountDefinitions returns the number of live authored definitions.
func (s *Store) CountDefinitions(ctx context.Context) (int64, error) {
	return s.CountAuthoringDefinitions(ctx, DefinitionListFilter{})
}

// ListAuthoringDefinitions returns a deterministic keyset page of live
// definitions with member counts derived from live ActionSets.
func (s *Store) ListAuthoringDefinitions(ctx context.Context, filter DefinitionListFilter) ([]DefinitionView, error) {
	rows, err := s.queries.ListAuthoringDefinitions(ctx, generated.ListAuthoringDefinitionsParams{
		AfterID: filter.AfterID, ScopeRestricted: filter.ScopeRestricted,
		ScopeGroupIds: filter.ScopeGroupIDs, RowLimit: filter.Limit,
	})
	if err != nil {
		return nil, fmt.Errorf("definition: list: %w", err)
	}
	views := make([]DefinitionView, len(rows))
	for i, row := range rows {
		views[i] = DefinitionView{DefinitionRow: DefinitionRow{
			ID: row.ID, Name: row.Name, Description: row.Description,
			Schedule: row.Schedule, CreatedAt: row.CreatedAt, CreatedBy: row.CreatedBy,
			UpdatedAt: row.UpdatedAt, IsDeleted: row.IsDeleted, SearchTsv: row.SearchTsv,
		}, LiveMemberCount: row.MemberCount}
	}
	return views, nil
}

// CountAuthoringDefinitions counts the same Definition population selected by
// the list filter, ignoring its keyset and limit.
func (s *Store) CountAuthoringDefinitions(ctx context.Context, filter DefinitionListFilter) (int64, error) {
	n, err := s.queries.CountAuthoringDefinitions(ctx, generated.CountAuthoringDefinitionsParams{
		ScopeRestricted: filter.ScopeRestricted, ScopeGroupIds: filter.ScopeGroupIDs,
	})
	if err != nil {
		return 0, fmt.Errorf("definition: count: %w", err)
	}
	return n, nil
}

// ListDefinitionMembers returns live ActionSet members in authored order.
func (s *Store) ListDefinitionMembers(ctx context.Context, id string) ([]DefinitionMemberView, error) {
	rows, err := s.queries.ListDefinitionMembers(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("definition: list members: %w", err)
	}
	return rows, nil
}

// GetAuthoringCompliancePolicy returns one live compliance policy.
func (s *Store) GetAuthoringCompliancePolicy(ctx context.Context, id string) (CompliancePolicyRow, error) {
	row, err := s.queries.GetAuthoringCompliancePolicy(ctx, id)
	if err != nil {
		return CompliancePolicyRow{}, fmt.Errorf("compliance policy: get: %w", translateNotFound(err))
	}
	return row, nil
}

// ListAuthoringCompliancePolicies returns a deterministic keyset page with
// rule counts derived from live Actions.
func (s *Store) ListAuthoringCompliancePolicies(ctx context.Context, filter CompliancePolicyListFilter) ([]CompliancePolicyView, error) {
	rows, err := s.queries.ListAuthoringCompliancePolicies(ctx, generated.ListAuthoringCompliancePoliciesParams{
		AfterID: filter.AfterID, ScopeRestricted: filter.ScopeRestricted,
		ScopeGroupIds: filter.ScopeGroupIDs, RowLimit: filter.Limit,
	})
	if err != nil {
		return nil, fmt.Errorf("compliance policy: list: %w", err)
	}
	views := make([]CompliancePolicyView, len(rows))
	for i, row := range rows {
		views[i] = CompliancePolicyView{CompliancePolicyRow: CompliancePolicyRow{
			ID: row.ID, Name: row.Name, Description: row.Description,
			CreatedAt: row.CreatedAt, CreatedBy: row.CreatedBy,
			IsDeleted: row.IsDeleted, SearchTsv: row.SearchTsv,
		}, LiveRuleCount: row.RuleCount}
	}
	return views, nil
}

// CountAuthoringCompliancePolicies counts the same population selected by the
// policy list filter.
func (s *Store) CountAuthoringCompliancePolicies(ctx context.Context, filter CompliancePolicyListFilter) (int64, error) {
	n, err := s.queries.CountAuthoringCompliancePolicies(ctx, generated.CountAuthoringCompliancePoliciesParams{
		ScopeRestricted: filter.ScopeRestricted, ScopeGroupIds: filter.ScopeGroupIDs,
	})
	if err != nil {
		return 0, fmt.Errorf("compliance policy: count: %w", err)
	}
	return n, nil
}

// ListCompliancePolicyRules returns live rules ordered by Action id.
func (s *Store) ListCompliancePolicyRules(ctx context.Context, policyID string) ([]CompliancePolicyRuleView, error) {
	rows, err := s.queries.ListCompliancePolicyRules(ctx, policyID)
	if err != nil {
		return nil, fmt.Errorf("compliance policy: list rules: %w", err)
	}
	return rows, nil
}

// GetDelivery returns one durable manifest delivery. ErrNotFound when the
// delivery id is unknown.
func (s *Store) GetDelivery(ctx context.Context, id string) (DeliveryRow, error) {
	row, err := s.queries.GetDelivery(ctx, id)
	if err != nil {
		return DeliveryRow{}, fmt.Errorf("delivery: get: %w", translateNotFound(err))
	}
	return row, nil
}

// ListDueDeliveries returns due, non-terminal deliveries for the
// currently connected devices, oldest first.
func (s *Store) ListDueDeliveries(ctx context.Context, deviceIDs []string, at time.Time, limit int32) ([]DeliveryRow, error) {
	rows, err := s.queries.ListDueDeliveriesForDevices(ctx, generated.ListDueDeliveriesForDevicesParams{
		DeviceIds: deviceIDs, AvailableAt: at, PageSize: limit,
	})
	if err != nil {
		return nil, fmt.Errorf("delivery: list due for connected devices: %w", err)
	}
	return rows, nil
}

// ListDeviceDeliveries returns manifest deliveries that have not
// reached durable agent receipt, oldest first.
func (s *Store) ListDeviceDeliveries(ctx context.Context, deviceID string, limit int32) ([]DeliveryRow, error) {
	rows, err := s.queries.ListSendableDeliveriesForDevice(ctx, generated.ListSendableDeliveriesForDeviceParams{
		DeviceID: deviceID, Limit: limit,
	})
	if err != nil {
		return nil, fmt.Errorf("delivery: list sendable for device: %w", err)
	}
	return rows, nil
}

// GetJob returns one durable scheduled job. ErrNotFound when it is unknown.
func (s *Store) GetJob(ctx context.Context, id string) (JobRow, error) {
	row, err := s.queries.GetJob(ctx, id)
	if err != nil {
		return JobRow{}, fmt.Errorf("job: get: %w", translateNotFound(err))
	}
	return row, nil
}

// ListClaimableJobs returns due pending jobs and expired leases, oldest first.
func (s *Store) ListClaimableJobs(ctx context.Context, at time.Time, limit int32) ([]JobRow, error) {
	rows, err := s.queries.ListClaimableJobs(ctx, generated.ListClaimableJobsParams{DueAt: at, Limit: limit})
	if err != nil {
		return nil, fmt.Errorf("job: list claimable: %w", err)
	}
	return rows, nil
}

// GetManifestAction returns one live action for manifest compilation.
func (s *Store) GetManifestAction(ctx context.Context, id string) (ActionRow, error) {
	row, err := s.queries.GetManifestAction(ctx, id)
	if err != nil {
		return ActionRow{}, fmt.Errorf("manifest: get action: %w", translateNotFound(err))
	}
	return row, nil
}

// GetManifestActionSet returns one live action set for manifest compilation.
func (s *Store) GetManifestActionSet(ctx context.Context, id string) (ActionSetRow, error) {
	row, err := s.queries.GetManifestActionSet(ctx, id)
	if err != nil {
		return ActionSetRow{}, fmt.Errorf("manifest: get action set: %w", translateNotFound(err))
	}
	return row, nil
}

// ListManifestActionSetActions returns a set's live actions in authored order.
func (s *Store) ListManifestActionSetActions(ctx context.Context, id string) ([]ActionRow, error) {
	rows, err := s.queries.ListManifestActionSetActions(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("manifest: list action set actions: %w", err)
	}
	return rows, nil
}

// GetManifestDefinition returns one live definition for manifest compilation.
func (s *Store) GetManifestDefinition(ctx context.Context, id string) (DefinitionRow, error) {
	row, err := s.queries.GetManifestDefinition(ctx, id)
	if err != nil {
		return DefinitionRow{}, fmt.Errorf("manifest: get definition: %w", translateNotFound(err))
	}
	return row, nil
}

// ListManifestDefinitionActionSets returns a definition's live sets in
// authored order.
func (s *Store) ListManifestDefinitionActionSets(ctx context.Context, id string) ([]ActionSetRow, error) {
	rows, err := s.queries.ListManifestDefinitionActionSets(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("manifest: list definition action sets: %w", err)
	}
	return rows, nil
}

// ListManifestDefinitionActions returns every live action for a definition in
// set order and then action order, without one query per contained set.
func (s *Store) ListManifestDefinitionActions(ctx context.Context, id string) ([]DefinitionManifestAction, error) {
	rows, err := s.queries.ListManifestDefinitionActions(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("manifest: list definition actions: %w", err)
	}
	out := make([]DefinitionManifestAction, 0, len(rows))
	for _, row := range rows {
		out = append(out, DefinitionManifestAction{
			ActionSetID: row.ActionSetID,
			Action: ActionRow{
				ID: row.ID, Name: row.Name, Description: row.Description,
				ActionType: row.ActionType, DesiredState: row.DesiredState,
				Params: row.Params, ParamsCanonical: row.ParamsCanonical,
				TimeoutSeconds: row.TimeoutSeconds, Schedule: row.Schedule,
				IsSystem: row.IsSystem, CreatedAt: row.CreatedAt,
				CreatedBy: row.CreatedBy, UpdatedAt: row.UpdatedAt,
				IsDeleted: row.IsDeleted, SearchTsv: row.SearchTsv,
			},
		})
	}
	return out, nil
}

// GetDeviceView returns one live device with its labels and assignees.
func (s *Store) GetDeviceView(ctx context.Context, id string) (DeviceView, error) {
	row, err := s.GetDevice(ctx, id)
	if err != nil {
		return DeviceView{}, err
	}
	labels, err := s.queries.ListDeviceLabels(ctx, id)
	if err != nil {
		return DeviceView{}, fmt.Errorf("device: list labels: %w", err)
	}
	users, err := s.queries.ListDeviceAssignedUserIDs(ctx, id)
	if err != nil {
		return DeviceView{}, fmt.Errorf("device: list assigned users: %w", err)
	}
	groups, err := s.queries.ListDeviceAssignedGroupIDs(ctx, id)
	if err != nil {
		return DeviceView{}, fmt.Errorf("device: list assigned groups: %w", err)
	}
	view := DeviceView{
		DeviceRow:        row,
		Labels:           make(map[string]string, len(labels)),
		AssignedUserIDs:  users,
		AssignedGroupIDs: groups,
	}
	for _, label := range labels {
		view.Labels[label.Key] = label.Value
	}
	views := []DeviceView{view}
	if err := s.addDeviceFreshness(ctx, []string{id}, views); err != nil {
		return DeviceView{}, err
	}
	view = views[0]
	return view, nil
}

type normalizedDeviceFilter struct {
	afterID         string
	limit           int32
	status          int32
	onlineSince     time.Time
	labels          []byte
	assignedUserID  *string
	scopeRestricted bool
	scopeGroupIDs   []string
}

func (s *Store) normalizeDeviceFilter(filter DeviceListFilter) (normalizedDeviceFilter, error) {
	// Handlers request one look-ahead row to produce an exact keyset next-page
	// token. The wire page remains capped at 100 rows.
	if filter.Limit < 0 || filter.Limit > 101 {
		return normalizedDeviceFilter{}, fmt.Errorf("device: list limit must be between 0 and 101")
	}
	if filter.Status < DeviceStatusAny || filter.Status > DeviceStatusOffline {
		return normalizedDeviceFilter{}, fmt.Errorf("device: invalid status filter %d", filter.Status)
	}
	limit := filter.Limit
	if limit == 0 {
		limit = 50
	}
	onlineSince := filter.OnlineSince
	if onlineSince.IsZero() {
		onlineSince = s.clock().Add(-5 * time.Minute)
	}
	labels := filter.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	encodedLabels, err := json.Marshal(labels)
	if err != nil {
		return normalizedDeviceFilter{}, fmt.Errorf("device: encode label filter: %w", err)
	}
	return normalizedDeviceFilter{
		afterID: filter.AfterID, limit: limit, status: int32(filter.Status),
		onlineSince: onlineSince, labels: encodedLabels,
		assignedUserID:  filter.AssignedUserID,
		scopeRestricted: filter.ScopeRestricted, scopeGroupIDs: filter.ScopeGroupIDs,
	}, nil
}

// ListDeviceViews returns a stable keyset page with labels and assignees
// loaded in three bounded batch reads.
func (s *Store) ListDeviceViews(ctx context.Context, filter DeviceListFilter) ([]DeviceView, error) {
	f, err := s.normalizeDeviceFilter(filter)
	if err != nil {
		return nil, err
	}
	rows, err := s.queries.ListDevices(ctx, generated.ListDevicesParams{
		AfterID: f.afterID, AssignedUserID: f.assignedUserID,
		ScopeRestricted: f.scopeRestricted, ScopeGroupIds: f.scopeGroupIDs,
		LabelFilter: f.labels, StatusFilter: f.status,
		OnlineSince: &f.onlineSince, RowLimit: f.limit,
	})
	if err != nil {
		return nil, fmt.Errorf("device: list: %w", err)
	}
	if len(rows) == 0 {
		return []DeviceView{}, nil
	}

	ids := make([]string, len(rows))
	views := make([]DeviceView, len(rows))
	byID := make(map[string]int, len(rows))
	for i, row := range rows {
		ids[i] = row.ID
		byID[row.ID] = i
		views[i] = DeviceView{DeviceRow: row, Labels: map[string]string{}}
	}
	labels, err := s.queries.ListDeviceLabelsBatch(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("device: list labels: %w", err)
	}
	for _, label := range labels {
		i := byID[label.DeviceID]
		views[i].Labels[label.Key] = label.Value
	}
	users, err := s.queries.ListDeviceAssignedUserIDsBatch(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("device: list assigned users: %w", err)
	}
	for _, assignment := range users {
		i := byID[assignment.DeviceID]
		views[i].AssignedUserIDs = append(views[i].AssignedUserIDs, assignment.UserID)
	}
	groups, err := s.queries.ListDeviceAssignedGroupIDsBatch(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("device: list assigned groups: %w", err)
	}
	for _, assignment := range groups {
		i := byID[assignment.DeviceID]
		views[i].AssignedGroupIDs = append(views[i].AssignedGroupIDs, assignment.GroupID)
	}
	if err := s.addDeviceFreshness(ctx, ids, views); err != nil {
		return nil, err
	}
	return views, nil
}

func (s *Store) addDeviceFreshness(ctx context.Context, ids []string, views []DeviceView) error {
	rows, err := s.queries.ListDeviceInventoryFreshness(ctx, generated.ListDeviceInventoryFreshnessParams{
		DefaultIntervalMinutes: DefaultInventoryIntervalMinutes,
		DeviceIds:              ids,
	})
	if err != nil {
		return fmt.Errorf("device: list inventory freshness: %w", err)
	}
	byID := make(map[string]int, len(views))
	for i := range views {
		byID[views[i].ID] = i
	}
	for _, row := range rows {
		i, ok := byID[row.DeviceID]
		if !ok {
			continue
		}
		if row.LastInventoryAt.Valid {
			collectedAt := row.LastInventoryAt.Time
			views[i].LastInventoryAt = &collectedAt
		}
		views[i].ResolvedInventoryIntervalMinutes = row.ResolvedIntervalMinutes
	}
	return nil
}

// CountDeviceViews counts the same filtered set as ListDeviceViews without a
// page cursor or limit.
func (s *Store) CountDeviceViews(ctx context.Context, filter DeviceListFilter) (int64, error) {
	f, err := s.normalizeDeviceFilter(filter)
	if err != nil {
		return 0, err
	}
	n, err := s.queries.CountDeviceViews(ctx, generated.CountDeviceViewsParams{
		AssignedUserID: f.assignedUserID, ScopeRestricted: f.scopeRestricted,
		ScopeGroupIds: f.scopeGroupIDs, LabelFilter: f.labels,
		StatusFilter: f.status, OnlineSince: &f.onlineSince,
	})
	if err != nil {
		return 0, fmt.Errorf("device: count filtered: %w", err)
	}
	return n, nil
}

// ListDeviceGroupIDs returns the device groups containing a live device.
func (s *Store) ListDeviceGroupIDs(ctx context.Context, deviceID string) ([]string, error) {
	if _, err := s.GetDevice(ctx, deviceID); err != nil {
		return nil, err
	}
	ids, err := s.queries.ListDeviceGroupIDs(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("device: list group ids: %w", err)
	}
	return ids, nil
}

// IsDeviceAssignedToUser reports whether a live device is assigned directly
// to a user or through one of the user's live groups.
func (s *Store) IsDeviceAssignedToUser(ctx context.Context, deviceID, userID string) (bool, error) {
	assigned, err := s.queries.IsDeviceAssignedToUser(ctx, generated.IsDeviceAssignedToUserParams{
		DeviceID: deviceID,
		UserID:   userID,
	})
	if err != nil {
		return false, fmt.Errorf("device: check user assignment: %w", err)
	}
	return assigned, nil
}

// ListDeviceAssignees returns all live user and group assignees in one read.
func (s *Store) ListDeviceAssignees(ctx context.Context, deviceID string) ([]DeviceAssigneeView, error) {
	if _, err := s.GetDevice(ctx, deviceID); err != nil {
		return nil, err
	}
	rows, err := s.queries.ListDeviceAssignees(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("device: list assignees: %w", err)
	}
	out := make([]DeviceAssigneeView, len(rows))
	for i, row := range rows {
		out[i] = DeviceAssigneeView{ID: row.AssigneeID, Kind: row.AssigneeKind, Name: row.AssigneeName}
	}
	return out, nil
}

// ListDeviceInventory returns the requested latest tables in stable name
// order. An empty name list selects every table for the device.
func (s *Store) ListDeviceInventory(ctx context.Context, deviceID string, tableNames []string) ([]DeviceInventoryTable, error) {
	rows, err := s.queries.ListDeviceInventory(ctx, generated.ListDeviceInventoryParams{
		DeviceID: deviceID, TableNames: tableNames,
	})
	if err != nil {
		return nil, fmt.Errorf("device: list inventory: %w", err)
	}
	return rows, nil
}

// GetOSQueryResult returns one on-demand query result by identifier.
func (s *Store) GetOSQueryResult(ctx context.Context, queryID string) (OSQueryResult, error) {
	row, err := s.queries.GetOSQueryResult(ctx, queryID)
	if err != nil {
		return OSQueryResult{}, fmt.Errorf("osquery: get result: %w", translateNotFound(err))
	}
	return row, nil
}

// GetDeviceLogResult returns one remote log query result by identifier.
func (s *Store) GetDeviceLogResult(ctx context.Context, queryID string) (DeviceLogResult, error) {
	row, err := s.queries.GetDeviceLogResult(ctx, queryID)
	if err != nil {
		return DeviceLogResult{}, fmt.Errorf("device logs: get result: %w", translateNotFound(err))
	}
	return row, nil
}

// ListDeviceComplianceResults returns current action checks in stable order.
func (s *Store) ListDeviceComplianceResults(ctx context.Context, deviceID string) ([]DeviceComplianceResult, error) {
	rows, err := s.queries.ListDeviceComplianceResults(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("compliance: list device results: %w", err)
	}
	return rows, nil
}

// ListDeviceComplianceEvaluations returns current policy-rule evaluations in
// stable policy and action order.
func (s *Store) ListDeviceComplianceEvaluations(ctx context.Context, deviceID string) ([]DeviceComplianceEvaluation, error) {
	rows, err := s.queries.ListDeviceComplianceEvaluations(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("compliance: list device evaluations: %w", err)
	}
	return rows, nil
}

// GetUser returns one live user. ErrNotFound when unknown or deleted.
func (s *Store) GetUser(ctx context.Context, id string) (UserRow, error) {
	row, err := s.queries.GetUser(ctx, id)
	if err != nil {
		return UserRow{}, fmt.Errorf("user: get: %w", translateNotFound(err))
	}
	return row, nil
}

// CountUsers returns the number of live users.
func (s *Store) CountUsers(ctx context.Context) (int64, error) {
	n, err := s.queries.CountUsers(ctx)
	if err != nil {
		return 0, fmt.Errorf("user: count: %w", err)
	}
	return n, nil
}

// GetUserEncryptionKey returns a subject's wrapped DEK. ErrNotFound
// when the subject has no key, which for an erased subject IS the
// expected state.
func (s *Store) GetUserEncryptionKey(ctx context.Context, userID string) (generated.UserEncryptionKey, error) {
	row, err := s.queries.GetUserEncryptionKey(ctx, userID)
	if err != nil {
		return generated.UserEncryptionKey{}, fmt.Errorf("user_encryption_key: get: %w", translateNotFound(err))
	}
	return row, nil
}
