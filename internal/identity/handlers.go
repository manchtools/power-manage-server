package identity

import (
	"context"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	"github.com/go-playground/validator/v10"

	sdkvalidate "github.com/manchtools/power-manage-sdk/validate"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/idp"
	"github.com/manchtools/power-manage/server/internal/store"
)

// Store is the database surface the identity handlers use. It is the
// audited mutation door plus the individual reads — deliberately not a
// generic handle, so this package cannot write outside WithAudit.
// Satisfied by *store.Store.
type Store interface {
	WithAudit(ctx context.Context, op store.AuditOperation, mutate func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error) (store.AuditRecord, error)
	RecordOperation(ctx context.Context, op store.AuditOperation, effects ...store.AuditEffect) (store.AuditRecord, error)

	GetUser(ctx context.Context, id string) (store.UserRow, error)
	GetUserByEmail(ctx context.Context, email string) (store.UserRow, error)
	GetUserSessionState(ctx context.Context, id string) (store.UserSessionStateRow, error)
	ListUsers(ctx context.Context, after string, limit int32) ([]store.UserRow, error)
	CountUsers(ctx context.Context) (int64, error)
	ListUserPermissions(ctx context.Context, userID string) ([]string, error)
	ListUserScopedGrants(ctx context.Context, userID string) ([]store.ScopedGrantRow, error)
	ListUserRoleGrants(ctx context.Context, userID string) ([]store.RoleGrantRow, error)
	ListInheritedRolesForUser(ctx context.Context, userID string) ([]store.InheritedRoleRow, error)
	ListUserGroupIDsForUser(ctx context.Context, userID string) ([]string, error)
	GetUserGroupView(ctx context.Context, id string) (store.UserGroupView, error)
	ListUserGroups(ctx context.Context, filter store.UserGroupListFilter) ([]store.UserGroupView, error)
	CountUserGroups(ctx context.Context, filter store.UserGroupListFilter) (int64, error)
	ListUserGroupsForUser(ctx context.Context, userID string, filter store.UserGroupListFilter) ([]store.UserGroupView, error)
	ListUserGroupMembers(ctx context.Context, groupID string) ([]store.UserGroupMemberView, error)
	ListUserGroupRoleGrants(ctx context.Context, groupID string) ([]store.GroupRoleGrantRow, error)
	ListUserSSHKeys(ctx context.Context, userID string) ([]store.UserSSHKeyRow, error)
	ListIdentityLinksForUser(ctx context.Context, userID string) ([]store.IdentityLinkWithProviderRow, error)
	GetIdentityLink(ctx context.Context, id string) (store.IdentityLinkRow, error)

	GetRole(ctx context.Context, id string) (store.RoleRow, error)
	GetRoleByName(ctx context.Context, name string) (store.RoleRow, error)
	ListRoles(ctx context.Context, after string, limit int32) ([]store.RoleRow, error)
	CountRoles(ctx context.Context) (int64, error)
	CountRoleHolders(ctx context.Context, roleID string) (int64, error)

	GetIdentityProvider(ctx context.Context, id string) (store.IdentityProviderRow, error)
	GetIdentityProviderBySlug(ctx context.Context, slug string) (store.IdentityProviderRow, error)
	ListIdentityProviders(ctx context.Context, after string, limit int32) ([]store.IdentityProviderRow, error)
	ListEnabledIdentityProviders(ctx context.Context) ([]store.IdentityProviderRow, error)
	CountIdentityProviders(ctx context.Context) (int64, error)

	IsTokenRevoked(ctx context.Context, jti string) (bool, error)
}

// ProviderFactory builds an OIDC client for a configured provider. It
// is an injection point so a test drives the real handler against a
// local OIDC double instead of reaching the internet.
type ProviderFactory func(ctx context.Context, cfg idp.ProviderConfig) (*idp.OIDCProvider, error)

// Config wires the identity handlers.
type Config struct {
	Store  Store
	Logger *slog.Logger
	// JWT mints and validates session tokens.
	JWT *auth.JWTManager
	// KEK wraps per-subject data-encryption keys and seals the
	// provider client secrets at rest.
	KEK *crypto.Encryptor
	// PublicBaseURL is the externally reachable base of this
	// deployment. It forms the OIDC redirect and the SCIM endpoint.
	PublicBaseURL string
	// NewProvider builds the OIDC client. Defaults to real discovery.
	NewProvider ProviderFactory
	// Now is the clock seam.
	Now func() time.Time
}

// Handlers implements the identity portion of the control service.
type Handlers struct {
	store     Store
	logger    *slog.Logger
	jwt       *auth.JWTManager
	kek       *crypto.Encryptor
	baseURL   string
	newOIDC   ProviderFactory
	linker    *idp.Linker
	now       func() time.Time
	validator *validator.Validate
}

// New builds the identity handlers.
func New(cfg Config) *Handlers {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	newOIDC := cfg.NewProvider
	if newOIDC == nil {
		newOIDC = idp.NewOIDCProvider
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Handlers{
		store:     cfg.Store,
		logger:    logger,
		jwt:       cfg.JWT,
		kek:       cfg.KEK,
		baseURL:   cfg.PublicBaseURL,
		newOIDC:   newOIDC,
		linker:    idp.NewLinker(cfg.KEK, now),
		now:       now,
		validator: sdkvalidate.NewValidator(),
	}
}

// validate runs the request's declared constraints at the transport
// boundary AND again at the handler. The interceptor covers the wire
// path; the handler call covers every other caller and keeps the check
// from being silently disabled by an interceptor-chain edit.
func (h *Handlers) validate(ctx context.Context, msg any) error {
	if detail, ok := sdkvalidate.Struct(h.validator, msg); !ok {
		return rpcError(ctx, ErrValidationFailed, connect.CodeInvalidArgument, detail)
	}
	return nil
}

// requireActor returns the authenticated principal, or the
// unauthenticated error. Handlers call it AFTER validating and BEFORE
// authorizing.
func (h *Handlers) requireActor(ctx context.Context) (*auth.UserContext, error) {
	actor, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, rpcError(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}
	return actor, nil
}

// authorize is the handler-level permission gate. The interceptor's
// pass is coarse — it only proves the actor holds SOMETHING that could
// authorize the procedure — so each handler re-asks with the resource
// it actually resolved.
func (h *Handlers) authorize(ctx context.Context, permission, resourceID string) error {
	if !auth.AuthorizeContext(ctx, permission, resourceID) {
		return rpcError(ctx, ErrPermissionDenied, connect.CodePermissionDenied, "permission denied")
	}
	return nil
}

// mutationOp builds the audit operation for a state-changing request.
//
// Origin and actor are derived from the request and the authenticated
// principal, never from request input. A principal whose id is not a
// subject ULID — the reserved bootstrap principal — is attributed by
// actor TYPE with an empty actor id, because the audit log's actor id
// column means "the subject who did this" and the bootstrap principal
// is no subject.
func (h *Handlers) mutationOp(req connect.AnyRequest, actor *auth.UserContext, permission string) store.AuditOperation {
	return h.operation(req, actor, store.ClassMutation, permission, store.AuthorizationAllowed, store.ResultSuccess, "")
}

func (h *Handlers) operation(
	req connect.AnyRequest,
	actor *auth.UserContext,
	class store.OperationClass,
	permission string,
	outcome store.AuthorizationOutcome,
	result store.OperationResult,
	resultCode string,
) store.AuditOperation {
	op := store.AuditOperation{
		Class:                class,
		ActorType:            string(auth.PrincipalUser),
		Origin:               auth.ControlRPCOrigin,
		RequestDescriptor:    req.Spec().Procedure,
		AuthorizationOutcome: outcome,
		AuthorizationDetail:  permission,
		Result:               result,
		ResultCode:           resultCode,
	}
	if actor != nil {
		op.ActorType = string(actor.Kind)
		if actor.CanOwnResources() {
			op.ActorID = actor.ID
		}
	}
	if ip := auth.ClientIP(req); ip != "" {
		op.OriginFingerprint = auth.Fingerprint(ip)
	}
	return op
}

// sealForSubject seals a value under a subject's data-encryption key,
// producing class-three audit detail: evidence that is only meaningful
// as its value, readable only while the subject's key exists.
//
// Callers pass the wrapped key they read inside the same transaction
// that writes the audit row, so a subject erased concurrently cannot
// leave detail sealed under a key that is already gone.
func (h *Handlers) sealForSubject(subjectID, wrappedDEK, field, value string) ([]byte, error) {
	dek, err := crypto.UnwrapDEK(h.kek, subjectID, wrappedDEK)
	if err != nil {
		return nil, err
	}
	sealed, err := dek.SealField(value, field)
	if err != nil {
		return nil, err
	}
	return []byte(sealed), nil
}

// mintSubjectDEK creates a subject's data-encryption key inside the
// caller's transaction and returns the wrapped form.
//
// The insert is first-write-wins: a key that already exists is kept,
// because replacing one would irreversibly erase everything already
// sealed under it. The wrapped value is then read back so the caller
// seals against whichever key actually survived.
func (h *Handlers) mintSubjectDEK(ctx context.Context, tx *store.Tx, subjectID string) (string, error) {
	wrapped, err := crypto.GenerateWrappedDEK(h.kek, subjectID)
	if err != nil {
		return "", err
	}
	if _, err := tx.InsertUserEncryptionKey(ctx, insertDEKParams(subjectID, wrapped)); err != nil {
		return "", err
	}
	row, err := tx.GetUserEncryptionKey(ctx, subjectID)
	if err != nil {
		return "", err
	}
	return row.WrappedDek, nil
}

// pageLimit clamps a requested page size to the contract's bounds.
const (
	defaultPageSize = 50
	maxPageSize     = 200
)

func pageLimit(requested int32) int32 {
	switch {
	case requested <= 0:
		return defaultPageSize
	case requested > maxPageSize:
		return maxPageSize
	default:
		return requested
	}
}
