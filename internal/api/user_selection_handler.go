package api

import (
	"context"
	"crypto/rand"
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// UserSelectionHandler handles user selection RPCs.
type UserSelectionHandler struct {
	store   *store.Store
	entropy *ulid.MonotonicEntropy
}

// NewUserSelectionHandler creates a new user selection handler.
func NewUserSelectionHandler(st *store.Store) *UserSelectionHandler {
	return &UserSelectionHandler{
		store:   st,
		entropy: ulid.Monotonic(rand.Reader, 0),
	}
}

// SetUserSelection sets a user's selection for an available assignment.
func (h *UserSelectionHandler) SetUserSelection(ctx context.Context, req *connect.Request[pm.SetUserSelectionRequest]) (*connect.Response[pm.SetUserSelectionResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	// Verify an available-mode assignment exists for this source targeting this device
	availableAssignments, err := h.store.QueriesFromContext(ctx).ListAvailableAssignmentsForDevice(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to check available assignments"))
	}

	found := false
	for _, asn := range availableAssignments {
		if asn.SourceType == req.Msg.SourceType && asn.SourceID == req.Msg.SourceId {
			found = true
			break
		}
	}
	if !found {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no available assignment found for this source and device"))
	}

	id := ulid.MustNew(ulid.Timestamp(time.Now()), h.entropy).String()

	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "user_selection",
		StreamID:   id,
		EventType:  "UserSelectionChanged",
		Data: map[string]any{
			"device_id":   req.Msg.DeviceId,
			"source_type": req.Msg.SourceType,
			"source_id":   req.Msg.SourceId,
			"selected":    req.Msg.Selected,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to set user selection"))
	}

	selection, err := h.store.QueriesFromContext(ctx).GetUserSelection(ctx, db.GetUserSelectionParams{
		DeviceID:   req.Msg.DeviceId,
		SourceType: req.Msg.SourceType,
		SourceID:   req.Msg.SourceId,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get user selection"))
	}

	return connect.NewResponse(&pm.SetUserSelectionResponse{
		Selection: userSelectionToProto(selection),
	}), nil
}

// ListAvailableActions returns all available-mode items for a device with their selection status.
func (h *UserSelectionHandler) ListAvailableActions(ctx context.Context, req *connect.Request[pm.ListAvailableActionsRequest]) (*connect.Response[pm.ListAvailableActionsResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	// Get available assignments for this device
	assignments, err := h.store.QueriesFromContext(ctx).ListAvailableAssignmentsForDevice(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to list available assignments"))
	}

	// Get user selections for this device
	selections, err := h.store.QueriesFromContext(ctx).ListUserSelectionsForDevice(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to list user selections"))
	}

	// Index selections by (source_type, source_id)
	selectionMap := make(map[string]bool)
	for _, sel := range selections {
		key := sel.SourceType + ":" + sel.SourceID
		selectionMap[key] = sel.Selected
	}

	// Build available items
	items := make([]*pm.AvailableItem, 0, len(assignments))
	for _, asn := range assignments {
		key := asn.SourceType + ":" + asn.SourceID
		selected, hasSelection := selectionMap[key]

		item := &pm.AvailableItem{
			SourceType: asn.SourceType,
			SourceId:   asn.SourceID,
			Selected:   hasSelection && selected,
		}

		// Load source metadata
		switch asn.SourceType {
		case "action":
			action, err := h.store.QueriesFromContext(ctx).GetActionByID(ctx, asn.SourceID)
			if err == nil {
				item.SourceName = action.Name
				if action.Description != nil {
					item.SourceDescription = *action.Description
				}
			}
		case "action_set":
			set, err := h.store.QueriesFromContext(ctx).GetActionSetByID(ctx, asn.SourceID)
			if err == nil {
				item.SourceName = set.Name
				item.SourceDescription = set.Description
			}
		case "definition":
			def, err := h.store.QueriesFromContext(ctx).GetDefinitionByID(ctx, asn.SourceID)
			if err == nil {
				item.SourceName = def.Name
				item.SourceDescription = def.Description
			}
		}

		items = append(items, item)
	}

	return connect.NewResponse(&pm.ListAvailableActionsResponse{
		Items: items,
	}), nil
}

func userSelectionToProto(s db.UserSelectionsProjection) *pm.UserSelection {
	sel := &pm.UserSelection{
		Id:         s.ID,
		DeviceId:   s.DeviceID,
		SourceType: s.SourceType,
		SourceId:   s.SourceID,
		Selected:   s.Selected,
	}

	if s.UpdatedAt.Valid {
		sel.UpdatedAt = timestamppb.New(s.UpdatedAt.Time)
	}

	return sel
}
