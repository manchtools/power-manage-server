package api

import (
	"context"
	"log/slog"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/store"
)

// ComplianceHandler handles compliance-related RPCs.
type ComplianceHandler struct {
	store  *store.Store
	logger *slog.Logger
}

// NewComplianceHandler creates a new compliance handler.
func NewComplianceHandler(st *store.Store, logger *slog.Logger) *ComplianceHandler {
	return &ComplianceHandler{
		store:  st,
		logger: logger,
	}
}

// GetDeviceCompliance returns the compliance status and individual check results for a device.
func (h *ComplianceHandler) GetDeviceCompliance(ctx context.Context, req *connect.Request[pm.GetDeviceComplianceRequest]) (*connect.Response[pm.GetDeviceComplianceResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	deviceID := req.Msg.DeviceId

	// Enforce the same assignment/owner scope as GetDevice. Without this any
	// user could read any device's compliance — including detection-script
	// stdout/stderr — by supplying an arbitrary device_id (#357). An admin
	// (unrestricted GetDeviceCompliance) gets a nil filter and sees all; a
	// scoped user only sees devices assigned to them.
	if _, err := h.store.Repos().Device.Get(ctx, store.GetDeviceKey{
		ID:         deviceID,
		OwnerScope: userFilterID(ctx, "GetDeviceCompliance"),
	}); err != nil {
		return nil, handleGetError(ctx, err, ErrDeviceNotFound, "device not found")
	}

	results, err := h.store.Repos().Compliance.DeviceResults(ctx, deviceID)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to query compliance results")
	}

	summary, err := h.store.Repos().Compliance.DeviceSummary(ctx, deviceID)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to query compliance summary")
	}

	checks := make([]*pm.ComplianceCheckResult, len(results))
	for i, r := range results {
		check := &pm.ComplianceCheckResult{
			ActionId:   r.ActionID,
			ActionName: r.ActionName,
			Compliant:  r.Compliant,
		}
		check.CheckedAt = timestamppb.New(r.CheckedAt)
		check.DetectionOutput = decodeCommandOutput(r.DetectionOutput)
		checks[i] = check
	}

	return connect.NewResponse(&pm.GetDeviceComplianceResponse{
		Status: pm.ComplianceStatus(summary.Status),
		Checks: checks,
	}), nil
}
