package api

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"strconv"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5/pgtype"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// exportPageSize bounds how many events one ExportAuditEvents call
// reads and formats — the server never holds more than one page of the
// export in memory (spec 26 AC5). Package-var seam so tests can shrink
// it and prove the chunking without seeding a thousand events.
var exportPageSize = 1000

// exportCSVHeader is the column set of the CSV artifact. The columns
// mirror the AuditEvent proto (and the JSON export keys) so the two
// formats carry identical information.
var exportCSVHeader = []string{"id", "occurred_at", "actor_type", "actor_id", "stream_type", "stream_id", "event_type", "data"}

// exportEvent is one row of the JSON export artifact. It is built from
// the *pm.AuditEvent that eventToProto returns, so the read-side
// redaction (redactEventData) is on the path by construction — the
// export can never expose a field ListAuditEvents would scrub. Keys
// are snake_case to match the CSV header.
type exportEvent struct {
	ID         string `json:"id"`
	OccurredAt string `json:"occurred_at"`
	ActorType  string `json:"actor_type"`
	ActorID    string `json:"actor_id"`
	StreamType string `json:"stream_type"`
	StreamID   string `json:"stream_id"`
	EventType  string `json:"event_type"`
	// Data is the redacted event payload as a JSON string — embedded
	// verbatim from the audit API surface, not re-parsed, so a payload
	// that fails to decode there stays byte-identical here.
	Data string `json:"data"`
}

// ExportAuditEvents streams the audit log as CSV or JSON for DSAR /
// external review (spec 26). It is a unary, chunked export: the
// client passes next_page_token back until it comes back empty and
// concatenates the chunks into one valid artifact. Unary on purpose —
// the control server's interceptors are deliberately fail-closed on
// streaming RPCs, so this reuses the entire unary auth/authz/validate
// chain, and the authz interceptor gates it with the ListAuditEvents
// permission (procedureAlternatives): the export cannot widen access.
//
// Pagination is keyset on sequence_num, not OFFSET, so events appended
// while an export runs cannot shift rows into a later page and
// duplicate them in the artifact.
func (h *AuditHandler) ExportAuditEvents(ctx context.Context, req *connect.Request[pm.ExportAuditEventsRequest]) (*connect.Response[pm.ExportAuditEventsResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	// Defense in depth behind the proto tag's oneof=csv json.
	format := req.Msg.Format
	if format != "csv" && format != "json" {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "unsupported export format")
	}

	first := req.Msg.PageToken == ""
	var beforeSeq int64
	if !first {
		v, err := strconv.ParseInt(req.Msg.PageToken, 10, 64)
		if err != nil || v <= 0 {
			return nil, apiErrorCtx(ctx, ErrInvalidPageToken, connect.CodeInvalidArgument, "invalid page token")
		}
		beforeSeq = v
	}

	var occurredFrom, occurredTo pgtype.Timestamptz
	if req.Msg.OccurredFrom != nil {
		occurredFrom = pgtype.Timestamptz{Time: req.Msg.OccurredFrom.AsTime(), Valid: true}
	}
	if req.Msg.OccurredTo != nil {
		occurredTo = pgtype.Timestamptz{Time: req.Msg.OccurredTo.AsTime(), Valid: true}
	}

	events, err := h.store.Queries().ExportAuditEvents(ctx, db.ExportAuditEventsParams{
		ActorID:      req.Msg.ActorId,
		StreamTypes:  req.Msg.StreamTypes,
		EventType:    req.Msg.EventType,
		OccurredFrom: occurredFrom,
		OccurredTo:   occurredTo,
		BeforeSeq:    beforeSeq,
		PageSize:     int32(exportPageSize),
	})
	if err != nil {
		h.logger.Error("audit export query failed", "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to export audit events")
	}

	// A full page means there may be more rows; a short page is the
	// end of the export. The cursor is the last row's sequence_num.
	last := len(events) < exportPageSize
	nextToken := ""
	if !last {
		nextToken = strconv.FormatInt(events[len(events)-1].SequenceNum, 10)
	}

	rows := make([]exportEvent, len(events))
	for i, e := range events {
		ev := eventToProto(e) // the ListAuditEvents redaction path
		rows[i] = exportEvent{
			ID:         ev.Id,
			OccurredAt: ev.OccurredAt.AsTime().Format(time.RFC3339Nano),
			ActorType:  ev.ActorType,
			ActorID:    ev.ActorId,
			StreamType: ev.StreamType,
			StreamID:   ev.StreamId,
			EventType:  ev.EventType,
			Data:       ev.Data,
		}
	}

	var chunk []byte
	if format == "csv" {
		chunk, err = exportChunkCSV(rows, first)
	} else {
		chunk, err = exportChunkJSON(rows, first, last)
	}
	if err != nil {
		h.logger.Error("audit export encoding failed", "error", err, "format", format)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to encode audit export")
	}

	return connect.NewResponse(&pm.ExportAuditEventsResponse{
		Chunk:         chunk,
		NextPageToken: nextToken,
	}), nil
}

// exportChunkCSV renders one page of export rows as CSV lines; the
// first chunk carries the header so concatenated chunks form a single
// valid CSV document.
func exportChunkCSV(rows []exportEvent, first bool) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if first {
		if err := w.Write(exportCSVHeader); err != nil {
			return nil, err
		}
	}
	for _, r := range rows {
		if err := w.Write([]string{r.ID, r.OccurredAt, r.ActorType, r.ActorID, r.StreamType, r.StreamID, r.EventType, r.Data}); err != nil {
			return nil, err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// exportChunkJSON renders one page of export rows as a fragment of a
// JSON array: the first chunk opens it, the last closes it, and a
// non-first chunk with rows leads with a separator (a next_page_token
// is only ever issued after a full page, so rows always precede it).
// Concatenating every chunk yields one valid JSON document — an empty
// result is "[]".
func exportChunkJSON(rows []exportEvent, first, last bool) ([]byte, error) {
	var buf bytes.Buffer
	if first {
		buf.WriteByte('[')
	}
	for i, r := range rows {
		if i > 0 || !first {
			buf.WriteByte(',')
		}
		buf.WriteByte('\n')
		b, err := json.Marshal(r)
		if err != nil {
			return nil, err
		}
		buf.Write(b)
	}
	if last {
		buf.WriteString("\n]")
	}
	return buf.Bytes(), nil
}
