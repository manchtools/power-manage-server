package api

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/middleware"
)

// Authentication & authorization error codes.
const (
	ErrNotAuthenticated     = "not_authenticated"
	ErrInvalidCredentials   = "invalid_credentials"
	ErrTokenExpired         = "token_expired"
	ErrPermissionDenied     = "permission_denied"
	ErrRateLimited          = "rate_limited"
	ErrPasswordIncorrect    = "password_incorrect"
	ErrTOTPRequired         = "totp_required"
	ErrTOTPInvalid          = "totp_invalid"
	ErrTOTPAlreadyEnabled   = "totp_already_enabled"
	ErrTOTPNotEnabled       = "totp_not_enabled"
	ErrTOTPNotSetUp         = "totp_not_set_up"
	ErrTOTPSSONotAllowed    = "totp_sso_not_allowed"
	ErrTOTPChallengeExpired = "totp_challenge_expired"
)

// Resource not found error codes.
const (
	ErrUserNotFound         = "user_not_found"
	ErrDeviceNotFound       = "device_not_found"
	ErrActionNotFound       = "action_not_found"
	ErrActionSetNotFound    = "action_set_not_found"
	ErrDefinitionNotFound   = "definition_not_found"
	ErrDeviceGroupNotFound  = "device_group_not_found"
	ErrUserGroupNotFound    = "user_group_not_found"
	ErrRoleNotFound         = "role_not_found"
	ErrProviderNotFound     = "provider_not_found"
	ErrIdentityLinkNotFound = "identity_link_not_found"
	ErrTokenNotFound        = "token_not_found"
	ErrExecutionNotFound    = "execution_not_found"
	ErrAssignmentNotFound   = "assignment_not_found"
	ErrQueryResultNotFound  = "query_result_not_found"
)

// Conflict error codes.
const (
	ErrEmailAlreadyExists    = "email_already_exists"
	ErrUserGroupNameExists   = "user_group_name_exists"
	ErrDeviceGroupNameExists = "device_group_name_exists"
	ErrRoleNameExists        = "role_name_exists"
	ErrProviderSlugExists    = "provider_slug_exists"
	ErrUserAlreadyHasRole    = "user_already_has_role"
	ErrGroupAlreadyHasRole   = "group_already_has_role"
	ErrUserAlreadyInGroup    = "user_already_in_group"
	ErrDeviceAlreadyInGroup  = "device_already_in_group"
)

// Precondition error codes.
const (
	ErrProviderDisabled         = "provider_disabled"
	ErrGroupNotDynamic          = "group_not_dynamic"
	ErrDynamicGroupManualModify = "dynamic_group_manual_modify"
	ErrCannotDeleteSystemRole   = "cannot_delete_system_role"
	ErrCannotRenameSystemRole   = "cannot_rename_system_role"
	ErrRoleInUse                = "role_in_use"
	ErrSCIMAlreadyEnabled       = "scim_already_enabled"
	ErrSCIMNotEnabled           = "scim_not_enabled"
	ErrSCIMManagedResource      = "scim_managed_resource"
	ErrSSOStateExpired          = "sso_state_expired"
	ErrPasswordLoginDisabled    = "password_login_disabled"
	ErrNoAssignmentFound        = "no_assignment_found"
	ErrDeviceNotConnected       = "device_not_connected"
	ErrCannotUnlinkOtherUser    = "cannot_unlink_other_user"
	ErrLastAuthMethod            = "last_auth_method"

	// Remote terminal sessions
	ErrTerminalLinuxUsernameNotSet = "terminal_linux_username_not_set"
	ErrTerminalNotConfigured       = "terminal_not_configured"
)

// Compliance policy error codes.
const (
	ErrCompliancePolicyNotFound  = "compliance_policy_not_found"
	ErrCompliancePolicyNameExists = "compliance_policy_name_exists"
	ErrActionNotCompliance       = "action_not_compliance"
)

// Validation error codes.
const (
	ErrValidationFailed = "validation_failed"
	ErrInvalidPageToken = "invalid_page_token"
	ErrInvalidQuery     = "invalid_query"
)

// Internal error code (generic).
const (
	ErrInternal      = "internal_error"
	ErrUnimplemented = "unimplemented"
)

// apiErrorCtx creates a connect.Error with a structured ErrorDetail containing the error code
// and the request ID from context for client-side correlation.
func apiErrorCtx(ctx context.Context, code string, connectCode connect.Code, msg string) *connect.Error {
	e := connect.NewError(connectCode, errors.New(msg))
	detail := &pm.ErrorDetail{Code: code, RequestId: middleware.RequestIDFromContext(ctx)}
	if d, err := connect.NewErrorDetail(detail); err == nil {
		e.AddDetail(d)
	}
	return e
}

// apiError creates a connect.Error without request ID context.
// Prefer apiErrorCtx when a context is available.
func apiError(code string, connectCode connect.Code, msg string) *connect.Error {
	e := connect.NewError(connectCode, errors.New(msg))
	if detail, detailErr := connect.NewErrorDetail(&pm.ErrorDetail{Code: code}); detailErr == nil {
		e.AddDetail(detail)
	}
	return e
}
