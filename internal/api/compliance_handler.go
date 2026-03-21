package api

import (
	"context"
	"encoding/json"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/store"
)

// ComplianceHandler handles compliance-related RPCs.
type ComplianceHandler struct {
	store *store.Store
}

// NewComplianceHandler creates a new compliance handler.
func NewComplianceHandler(st *store.Store) *ComplianceHandler {
	return &ComplianceHandler{store: st}
}

// GetDeviceCompliance returns the compliance status and individual check results for a device.
func (h *ComplianceHandler) GetDeviceCompliance(ctx context.Context, req *connect.Request[pm.GetDeviceComplianceRequest]) (*connect.Response[pm.GetDeviceComplianceResponse], error) {
	deviceID := req.Msg.DeviceId

	results, err := h.store.Queries().GetDeviceComplianceResults(ctx, deviceID)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to query compliance results")
	}

	summary, err := h.store.Queries().GetDeviceComplianceSummary(ctx, deviceID)
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
		if r.CheckedAt.Valid {
			check.CheckedAt = timestamppb.New(r.CheckedAt.Time)
		}
		if len(r.DetectionOutput) > 0 {
			var output struct {
				Stdout   string `json:"stdout"`
				Stderr   string `json:"stderr"`
				ExitCode int32  `json:"exit_code"`
			}
			if json.Unmarshal(r.DetectionOutput, &output) == nil {
				check.DetectionOutput = &pm.CommandOutput{
					Stdout:   output.Stdout,
					Stderr:   output.Stderr,
					ExitCode: output.ExitCode,
				}
			}
		}
		checks[i] = check
	}

	return connect.NewResponse(&pm.GetDeviceComplianceResponse{
		Status: pm.ComplianceStatus(summary.ComplianceStatus),
		Checks: checks,
	}), nil
}
