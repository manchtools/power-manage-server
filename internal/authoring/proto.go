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
