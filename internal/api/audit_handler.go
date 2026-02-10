package api

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	db "github.com/manchtools/power-manage/server/internal/store/generated"

	"github.com/manchtools/power-manage/server/internal/store"
)

// AuditHandler handles audit log RPCs.
type AuditHandler struct {
	store *store.Store
}

// NewAuditHandler creates a new audit handler.
func NewAuditHandler(st *store.Store) *AuditHandler {
	return &AuditHandler{store: st}
}

// ListAuditEvents returns a paginated list of audit events.
func (h *AuditHandler) ListAuditEvents(ctx context.Context, req *connect.Request[pm.ListAuditEventsRequest]) (*connect.Response[pm.ListAuditEventsResponse], error) {
	pageSize := int32(req.Msg.PageSize)
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 50
	}

	offset := int32(0)
	if req.Msg.PageToken != "" {
		offset64, err := parsePageToken(req.Msg.PageToken)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid page token"))
		}
		offset = int32(offset64)
	}

	events, err := h.store.Queries().ListAuditEvents(ctx, db.ListAuditEventsParams{
		Column1: req.Msg.ActorId,
		Column2: req.Msg.StreamType,
		Column3: req.Msg.EventType,
		Limit:   pageSize,
		Offset:  offset,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to list audit events"))
	}

	count, err := h.store.Queries().CountAuditEvents(ctx, db.CountAuditEventsParams{
		Column1: req.Msg.ActorId,
		Column2: req.Msg.StreamType,
		Column3: req.Msg.EventType,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to count audit events"))
	}

	var nextPageToken string
	if int32(len(events)) == pageSize && int64(offset)+int64(pageSize) < count {
		nextPageToken = formatPageToken(int64(offset) + int64(pageSize))
	}

	protoEvents := make([]*pm.AuditEvent, len(events))
	for i, e := range events {
		protoEvents[i] = eventToProto(e)
	}

	return connect.NewResponse(&pm.ListAuditEventsResponse{
		Events:        protoEvents,
		NextPageToken: nextPageToken,
		TotalCount:    int32(count),
	}), nil
}

func eventToProto(e db.Event) *pm.AuditEvent {
	event := &pm.AuditEvent{
		Id:         uuid.UUID(e.ID.Bytes).String(),
		EventType:  e.EventType,
		StreamType: e.StreamType,
		StreamId:   e.StreamID,
		ActorType:  e.ActorType,
		ActorId:    e.ActorID,
		Data:       string(e.Data),
	}

	if e.OccurredAt.Valid {
		event.OccurredAt = timestamppb.New(e.OccurredAt.Time)
	}

	return event
}
