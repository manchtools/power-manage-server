package api

import (
	"context"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
)

// UserSelectionHandler handles user selection RPCs.
type UserSelectionHandler struct {
	store  *store.Store
	logger *slog.Logger
}

// NewUserSelectionHandler creates a new user selection handler.
func NewUserSelectionHandler(st *store.Store, logger *slog.Logger) *UserSelectionHandler {
	return &UserSelectionHandler{
		store:  st,
		logger: logger,
	}
}

// SetUserSelection sets a user's selection for an available assignment.
func (h *UserSelectionHandler) SetUserSelection(ctx context.Context, req *connect.Request[pm.SetUserSelectionRequest]) (*connect.Response[pm.SetUserSelectionResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Verify device access (non-admins can only access assigned devices)
	_, err = h.store.Repos().Device.Get(ctx, store.GetDeviceKey{
		ID:         req.Msg.DeviceId,
		OwnerScope: userFilterID(ctx, "ListDevices"),
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrDeviceNotFound, connect.CodeNotFound, "device not found")
	}

	// Translate the wire enum to the projection / event-payload
	// string. The projection still stores the legacy lowercase form
	// so existing rows replay unchanged.
	sourceTypeStr := assignmentSourceTypeToString(req.Msg.SourceType)

	// Verify an available-mode assignment exists for this source targeting this device
	availableAssignments, err := h.store.Queries().ListAvailableAssignmentsForDevice(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to check available assignments")
	}

	found := false
	for _, asn := range availableAssignments {
		if asn.SourceType == sourceTypeStr && asn.SourceID == req.Msg.SourceId {
			found = true
			break
		}
	}
	if !found {
		return nil, apiErrorCtx(ctx, ErrNoAssignmentFound, connect.CodeNotFound, "no available assignment found for this source and device")
	}

	id := ulid.Make().String()

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "user_selection",
		StreamID:   id,
		EventType:  string(eventtypes.UserSelectionChanged),
		Data: payloads.UserSelectionChanged{
			DeviceID:   req.Msg.DeviceId,
			SourceType: sourceTypeStr,
			SourceID:   req.Msg.SourceId,
			Selected:   req.Msg.Selected,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to set user selection"); err != nil {
		return nil, err
	}

	selection, err := h.store.Repos().UserSelection.Get(ctx, store.GetUserSelectionKey{
		DeviceID:   req.Msg.DeviceId,
		SourceType: sourceTypeStr,
		SourceID:   req.Msg.SourceId,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get user selection")
	}

	return connect.NewResponse(&pm.SetUserSelectionResponse{
		Selection: userSelectionToProto(selection),
	}), nil
}

// ListAvailableActions returns all available-mode items for a device with their selection status.
func (h *UserSelectionHandler) ListAvailableActions(ctx context.Context, req *connect.Request[pm.ListAvailableActionsRequest]) (*connect.Response[pm.ListAvailableActionsResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	// Verify device access (non-admins can only access assigned devices)
	_, err := h.store.Repos().Device.Get(ctx, store.GetDeviceKey{
		ID:         req.Msg.DeviceId,
		OwnerScope: userFilterID(ctx, "ListDevices"),
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrDeviceNotFound, connect.CodeNotFound, "device not found")
	}

	// Get available assignments for this device
	assignments, err := h.store.Queries().ListAvailableAssignmentsForDevice(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to list available assignments")
	}

	// Get user selections for this device
	selections, err := h.store.Repos().UserSelection.ListForDevice(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to list user selections")
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
			SourceType: assignmentSourceTypeFromString(asn.SourceType),
			SourceId:   asn.SourceID,
			Selected:   hasSelection && selected,
		}

		// Load source metadata
		switch asn.SourceType {
		case "action":
			action, err := h.store.Queries().GetActionByID(ctx, asn.SourceID)
			if err == nil {
				item.SourceName = action.Name
				if action.Description != nil {
					item.SourceDescription = *action.Description
				}
			} else {
				logEnrichmentErr("GetActionByID", "action_id", asn.SourceID, err)
			}
		case "action_set":
			set, err := h.store.Queries().GetActionSetByID(ctx, asn.SourceID)
			if err == nil {
				item.SourceName = set.Name
				item.SourceDescription = set.Description
			} else {
				logEnrichmentErr("GetActionSetByID", "action_set_id", asn.SourceID, err)
			}
		case "definition":
			def, err := h.store.Queries().GetDefinitionByID(ctx, asn.SourceID)
			if err == nil {
				item.SourceName = def.Name
				item.SourceDescription = def.Description
			} else {
				logEnrichmentErr("GetDefinitionByID", "definition_id", asn.SourceID, err)
			}
		}

		items = append(items, item)
	}

	return connect.NewResponse(&pm.ListAvailableActionsResponse{
		Items: items,
	}), nil
}

func userSelectionToProto(s store.UserSelection) *pm.UserSelection {
	sel := &pm.UserSelection{
		Id:         s.ID,
		DeviceId:   s.DeviceID,
		SourceType: assignmentSourceTypeFromString(s.SourceType),
		SourceId:   s.SourceID,
		Selected:   s.Selected,
	}

	sel.UpdatedAt = timestamppb.New(s.UpdatedAt)

	return sel
}
