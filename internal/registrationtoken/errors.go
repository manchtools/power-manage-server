// Package registrationtoken implements direct audited CRUD for device
// registration tokens.
package registrationtoken

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/middleware"
)

const (
	errNotAuthenticated = "not_authenticated"
	errPermissionDenied = "permission_denied"
	errValidationFailed = "validation_failed"
	errInvalidPageToken = "invalid_page_token"
	errInternal         = "internal_error"
	errTokenNotFound    = "token_not_found"
	errUserNotFound     = "user_not_found"
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
