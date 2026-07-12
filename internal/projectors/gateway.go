package projectors

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// Gateway projector (spec 31). Materialises the gateway stream
// (GatewayEnrolled / GatewayCertRenewed / GatewayRevoked) into
// gateways_projection. Every event is a single guarded statement, so the
// listener runs them on the autocommit pool (no WithTx). ApplyGateway is the
// shared core used by both the live listener and the rebuild path.

// GatewayEnrolledPayload is the decoded, validated GatewayEnrolled.
type GatewayEnrolledPayload struct {
	GatewayID   string
	Fingerprint string
	Hostname    string
	// NotAfter is required — the column is NOT NULL, and a missing expiry would
	// otherwise produce an enrolled-but-invisible (un-revocable) live gateway.
	NotAfter time.Time
}

// GatewayEnrolledFromEvent decodes GatewayEnrolled. fingerprint and not_after
// are both required — the projection's purpose is the fingerprint↦gateway_id
// mapping, and not_after bounds a gateway's live window.
func GatewayEnrolledFromEvent(e store.PersistedEvent) (GatewayEnrolledPayload, error) {
	raw, err := decodePayload[payloads.GatewayEnrolled](e, "gateway", eventtypes.GatewayEnrolled)
	if err != nil {
		return GatewayEnrolledPayload{}, err
	}
	if raw.Fingerprint == nil || *raw.Fingerprint == "" {
		return GatewayEnrolledPayload{}, fmt.Errorf("projector: GatewayEnrolled requires fingerprint")
	}
	notAfter, err := parseOptionalRFC3339(raw.NotAfter)
	if err != nil {
		return GatewayEnrolledPayload{}, fmt.Errorf("projector: invalid not_after on GatewayEnrolled: %w", err)
	}
	if notAfter == nil {
		return GatewayEnrolledPayload{}, fmt.Errorf("projector: GatewayEnrolled requires not_after")
	}
	out := GatewayEnrolledPayload{
		GatewayID:   e.StreamID,
		Fingerprint: *raw.Fingerprint,
		NotAfter:    *notAfter,
	}
	if raw.Hostname != nil {
		out.Hostname = *raw.Hostname
	}
	return out, nil
}

// GatewayCertRenewedPayload is the decoded, validated GatewayCertRenewed.
type GatewayCertRenewedPayload struct {
	GatewayID   string
	Fingerprint string
	NotAfter    time.Time
}

// GatewayCertRenewedFromEvent decodes GatewayCertRenewed. fingerprint and
// not_after are both required (not_after backs the NOT NULL column).
func GatewayCertRenewedFromEvent(e store.PersistedEvent) (GatewayCertRenewedPayload, error) {
	raw, err := decodePayload[payloads.GatewayCertRenewed](e, "gateway", eventtypes.GatewayCertRenewed)
	if err != nil {
		return GatewayCertRenewedPayload{}, err
	}
	if raw.Fingerprint == nil || *raw.Fingerprint == "" {
		return GatewayCertRenewedPayload{}, fmt.Errorf("projector: GatewayCertRenewed requires fingerprint")
	}
	notAfter, err := parseOptionalRFC3339(raw.NotAfter)
	if err != nil {
		return GatewayCertRenewedPayload{}, fmt.Errorf("projector: invalid not_after on GatewayCertRenewed: %w", err)
	}
	if notAfter == nil {
		return GatewayCertRenewedPayload{}, fmt.Errorf("projector: GatewayCertRenewed requires not_after")
	}
	return GatewayCertRenewedPayload{
		GatewayID:   e.StreamID,
		Fingerprint: *raw.Fingerprint,
		NotAfter:    *notAfter,
	}, nil
}

// ApplyGateway is the transactional core of the gateway projector, gated on the
// "gateway" stream. The listener dispatches live events through it; the rebuild
// path registers it via RegisterRebuildApply.
func ApplyGateway(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	if e.StreamType != "gateway" {
		return nil
	}
	switch e.EventType {
	case string(eventtypes.GatewayEnrolled):
		return applyGatewayEnrolled(ctx, q, e)
	case string(eventtypes.GatewayCertRenewed):
		return applyGatewayCertRenewed(ctx, q, e)
	case string(eventtypes.GatewayRevoked):
		return applyGatewayRevoked(ctx, q, e)
	}
	return nil
}

func applyGatewayEnrolled(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := GatewayEnrolledFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	return q.UpsertGatewayEnrolledProjection(ctx, db.UpsertGatewayEnrolledProjectionParams{
		GatewayID:         payload.GatewayID,
		Fingerprint:       payload.Fingerprint,
		Hostname:          payload.Hostname,
		NotAfter:          payload.NotAfter,
		EnrolledAt:        e.OccurredAt,
		ProjectionVersion: e.SequenceNum,
	})
}

func applyGatewayCertRenewed(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := GatewayCertRenewedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	if _, err := q.UpdateGatewayCertRenewedProjection(ctx, db.UpdateGatewayCertRenewedProjectionParams{
		GatewayID:         payload.GatewayID,
		Fingerprint:       payload.Fingerprint,
		NotAfter:          payload.NotAfter,
		ProjectionVersion: e.SequenceNum,
	}); err != nil {
		return err
	}
	return nil
}

func applyGatewayRevoked(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	// GatewayRevoked carries only an audit fingerprint; the projection change is
	// stamping revoked_at from the event's occurrence time.
	if e.StreamType != "gateway" || e.EventType != string(eventtypes.GatewayRevoked) {
		return nil
	}
	revokedAt := e.OccurredAt
	if _, err := q.MarkGatewayRevokedProjection(ctx, db.MarkGatewayRevokedProjectionParams{
		GatewayID:         e.StreamID,
		RevokedAt:         &revokedAt,
		ProjectionVersion: e.SequenceNum,
	}); err != nil {
		return err
	}
	return nil
}
