package dispatch

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/middleware"
)

const (
	errNotAuthenticated  = "not_authenticated"
	errPermissionDenied  = "permission_denied"
	errValidationFailed  = "validation_failed"
	errDeviceNotFound    = "device_not_found"
	errActionNotFound    = "action_not_found"
	errActionSetMissing  = "action_set_not_found"
	errDefinitionMissing = "definition_not_found"
	errInternal          = "internal_error"
)

func rpcError(ctx context.Context, code string, connectCode connect.Code, message string) *connect.Error {
	err := connect.NewError(connectCode, errors.New(message))
	detail, detailErr := connect.NewErrorDetail(&pmv1.ErrorDetail{
		Code: code, RequestId: middleware.RequestIDFromContext(ctx),
	})
	if detailErr == nil {
		err.AddDetail(detail)
	}
	return err
}

func notFound(ctx context.Context, code, message string) *connect.Error {
	return rpcError(ctx, code, connect.CodeNotFound, message)
}
