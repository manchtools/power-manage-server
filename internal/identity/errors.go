// Package identity implements the control server's identity RPCs:
// sessions, OIDC single sign-on, identity providers and their links,
// users, roles and role grants.
//
// Every handler in this package follows the same order at its trust
// boundary — validate, authenticate, authorize, act — and every
// mutation reaches the database through store.WithAudit, so the state
// change and the evidence for it commit together or not at all.
package identity

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/middleware"
)

// Error codes carried in the structured error detail. They are a fixed
// vocabulary: a client branches on the code, never on the message.
const (
	ErrNotAuthenticated = "not_authenticated"
	ErrTokenExpired     = "token_expired"
	ErrPermissionDenied = "permission_denied"
	ErrValidationFailed = "validation_failed"
	ErrInvalidPageToken = "invalid_page_token"
	ErrInternal         = "internal_error"

	ErrUserNotFound            = "user_not_found"
	ErrRoleNotFound            = "role_not_found"
	ErrProviderNotFound        = "provider_not_found"
	ErrIdentityLinkNotFound    = "identity_link_not_found"
	ErrGrantNotFound           = "grant_not_found"
	ErrUserGroupNotFound       = "user_group_not_found"
	ErrUserGroupMemberNotFound = "user_group_member_not_found"

	ErrEmailAlreadyExists  = "email_already_exists"
	ErrRoleNameExists      = "role_name_exists"
	ErrProviderSlugExists  = "provider_slug_exists"
	ErrUserAlreadyHasRole  = "user_already_has_role"
	ErrUserGroupNameExists = "user_group_name_exists"

	ErrCannotModifySystemRole = "cannot_modify_system_role"
	ErrRoleInUse              = "role_in_use"
	ErrScopeNotPermitted      = "scope_not_permitted"
	ErrProviderDisabled       = "provider_disabled"
	ErrSCIMNotEnabled         = "scim_not_enabled"
	ErrSSOStateExpired        = "sso_state_expired"
	ErrSSONoMatchingAccount   = "sso_no_matching_account"
	ErrCannotUnlinkOtherUser  = "cannot_unlink_other_user"
	ErrLastAuthMethod         = "last_auth_method"
	ErrDynamicGroupMembership = "dynamic_group_membership_managed"
	ErrSCIMManagedResource    = "scim_managed_resource"
	ErrInvalidDynamicQuery    = "invalid_dynamic_query"
	ErrGroupNotDynamic        = "group_not_dynamic"
)

// rpcError builds a connect error carrying the structured detail the
// client correlates on.
//
// The message is always a fixed string chosen by the handler. Request
// input is never interpolated into it: an error message is the easiest
// accidental oracle in an RPC surface, and echoing input into one is
// how a value that should never leave the server ends up in a client
// log.
func rpcError(ctx context.Context, code string, connectCode connect.Code, msg string) *connect.Error {
	e := connect.NewError(connectCode, errors.New(msg))
	detail := &pmv1.ErrorDetail{Code: code, RequestId: middleware.RequestIDFromContext(ctx)}
	if d, err := connect.NewErrorDetail(detail); err == nil {
		e.AddDetail(d)
	}
	return e
}

// notFound is the answer for every object the caller may not see, as
// well as for every object that does not exist.
//
// Scoped non-owner access reports not-found rather than
// permission-denied: telling a caller "you may not see THAT one" is
// telling them it exists, which is the existence oracle the design
// forbids.
func notFound(ctx context.Context, code, msg string) *connect.Error {
	return rpcError(ctx, code, connect.CodeNotFound, msg)
}

// internalError is the catch-all for a failure the caller cannot act
// on. The underlying error is never attached: it routinely quotes the
// input that caused it.
func internalError(ctx context.Context, msg string) *connect.Error {
	return rpcError(ctx, ErrInternal, connect.CodeInternal, msg)
}
