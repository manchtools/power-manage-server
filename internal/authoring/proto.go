package authoring

import (
	"fmt"

	"google.golang.org/protobuf/types/known/timestamppb"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/actionparams"
	"github.com/manchtools/power-manage/server/internal/store"
)

func actionToProto(row store.ActionRow) (*pmv1.ManagedAction, error) {
	action := &pmv1.ManagedAction{
		Id: row.ID, Name: row.Name, Type: pmv1.ActionType(row.ActionType),
		DesiredState: pmv1.DesiredState(row.DesiredState), TimeoutSeconds: row.TimeoutSeconds,
		CreatedBy: row.CreatedBy,
	}
	if row.Description != nil {
		action.Description = *row.Description
	}
	if row.CreatedAt != nil {
		action.CreatedAt = timestamppb.New(*row.CreatedAt)
	}
	if row.UpdatedAt != nil {
		action.UpdatedAt = timestamppb.New(*row.UpdatedAt)
	}
	if err := actionparams.PopulateManagedAction(action, action.Type, row.Params); err != nil {
		return nil, fmt.Errorf("authoring: decode stored action params: %w", err)
	}
	schedule, err := actionparams.ParseSchedule(row.Schedule)
	if err != nil {
		return nil, fmt.Errorf("authoring: decode stored action schedule: %w", err)
	}
	action.Schedule = schedule
	return action, nil
}

func actionSetToProto(row store.ActionSetRow, memberCount int64) (*pmv1.ActionSet, error) {
	if !validFailurePolicy(pmv1.OnFailure(row.OnFailure)) {
		return nil, fmt.Errorf("authoring: invalid stored action set failure policy %d", row.OnFailure)
	}
	schedule, err := actionparams.ParseSchedule(row.Schedule)
	if err != nil {
		return nil, fmt.Errorf("authoring: decode stored action set schedule: %w", err)
	}
	if schedule == nil {
		return nil, fmt.Errorf("authoring: stored action set schedule is empty")
	}
	set := &pmv1.ActionSet{
		Id: row.ID, Name: row.Name, Description: row.Description,
		MemberCount: boundedCount(memberCount), CreatedBy: row.CreatedBy,
		Schedule: schedule, OnFailure: pmv1.OnFailure(row.OnFailure),
	}
	if row.CreatedAt != nil {
		set.CreatedAt = timestamppb.New(*row.CreatedAt)
	}
	if row.UpdatedAt != nil {
		set.UpdatedAt = timestamppb.New(*row.UpdatedAt)
	}
	return set, nil
}

func actionSetMembersToProto(rows []store.ActionSetMemberView) []*pmv1.ActionSetMember {
	members := make([]*pmv1.ActionSetMember, len(rows))
	for i, row := range rows {
		members[i] = &pmv1.ActionSetMember{
			ActionId: row.ActionID, SortOrder: row.SortOrder,
			ActionName: row.ActionName, ActionType: pmv1.ActionType(row.ActionType),
		}
	}
	return members
}

func definitionToProto(row store.DefinitionRow, memberCount int64) (*pmv1.Definition, error) {
	schedule, err := actionparams.ParseSchedule(row.Schedule)
	if err != nil {
		return nil, fmt.Errorf("authoring: decode stored definition schedule: %w", err)
	}
	if schedule == nil {
		return nil, fmt.Errorf("authoring: stored definition schedule is empty")
	}
	definition := &pmv1.Definition{
		Id: row.ID, Name: row.Name, Description: row.Description,
		MemberCount: boundedCount(memberCount), CreatedBy: row.CreatedBy, Schedule: schedule,
	}
	if row.CreatedAt != nil {
		definition.CreatedAt = timestamppb.New(*row.CreatedAt)
	}
	if row.UpdatedAt != nil {
		definition.UpdatedAt = timestamppb.New(*row.UpdatedAt)
	}
	return definition, nil
}

func definitionMembersToProto(rows []store.DefinitionMemberView) []*pmv1.DefinitionMember {
	members := make([]*pmv1.DefinitionMember, len(rows))
	for i, row := range rows {
		members[i] = &pmv1.DefinitionMember{
			ActionSetId: row.ActionSetID, SortOrder: row.SortOrder, ActionSetName: row.ActionSetName,
		}
	}
	return members
}
