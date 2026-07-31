package scim

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/store"
)

// Store is the database surface the SCIM routes use: the audited
// mutation door, the audited no-mutation door, and the individual
// reads. Deliberately not a generic handle — this package cannot write
// outside WithAudit. Satisfied by *store.Store.
type Store interface {
	WithAudit(ctx context.Context, op store.AuditOperation, mutate func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error) (store.AuditRecord, error)
	RecordOperation(ctx context.Context, op store.AuditOperation, effects ...store.AuditEffect) (store.AuditRecord, error)

	GetIdentityProviderBySlug(ctx context.Context, slug string) (store.IdentityProviderRow, error)
	GetServerSettings(ctx context.Context) (store.ServerSettingsRow, error)

	GetUser(ctx context.Context, id string) (store.UserRow, error)
	GetUserByEmail(ctx context.Context, email string) (store.UserRow, error)
	ListSCIMUsers(ctx context.Context, providerID string, limit, offset int32) ([]store.SCIMUserRow, error)
	CountSCIMUsers(ctx context.Context, providerID string) (int64, error)
	FindSCIMUserByEmail(ctx context.Context, providerID, email string) (store.SCIMUserRow, error)
	FindSCIMUserByExternalID(ctx context.Context, providerID, externalID string) (store.SCIMUserRow, error)
	GetIdentityLinkByProviderAndUser(ctx context.Context, providerID, userID string) (store.IdentityLinkRow, error)
	CountIdentityLinksForUser(ctx context.Context, userID string) (int64, error)

	GetUserGroup(ctx context.Context, id string) (store.UserGroupRow, error)
	ListUserGroupMemberIDs(ctx context.Context, groupID string) ([]string, error)
	GetSCIMGroupMapping(ctx context.Context, providerID, scimGroupID string) (store.SCIMGroupMappingRow, error)
	GetSCIMGroupMappingByUserGroup(ctx context.Context, providerID, userGroupID string) (store.SCIMGroupMappingRow, error)
	ListSCIMGroupMappings(ctx context.Context, providerID string) ([]store.SCIMGroupMappingRow, error)
}

// Audit vocabulary for this surface. Every value is a code-derived
// constant that satisfies the audit schema's token shapes; none of them
// can carry request input.
const (
	// Origin names the surface a directory request entered through.
	Origin = "scim"
	// ActorTypeProvider is the acting principal on an authenticated
	// directory request: a provider row, not a human subject.
	ActorTypeProvider = "scim_provider"
	// AuthorizationDetail names what decided the request. A directory
	// holds no RBAC permission; presenting the provider's bearer token
	// is the whole of its authority, and it reaches only the subjects
	// and groups bound to that provider.
	AuthorizationDetail = "scim_bearer_token"
)

// Rejection reason codes. They are recorded server-side; the response
// a client sees is identical for every one of them, so distinguishing
// them here is evidence rather than an oracle.
const (
	reasonMissingCredentials = "missing_credentials"
	reasonUnknownProvider    = "unknown_provider"
	reasonProviderDisabled   = "provider_disabled"
	reasonSCIMDisabled       = "scim_disabled"
	reasonNoTokenConfigured  = "no_token_configured"
	reasonInvalidToken       = "invalid_token"
)

// Rate-limit ceilings. Two buckets guard the credential path and a
// third bounds how fast one source can make the audit log grow.
const (
	// providerRequestsPerWindow is generous: a real directory sync
	// (list users, upsert each, patch groups) must never bump into it.
	providerRequestsPerWindow = 100
	// providerIPRequestsPerWindow is tighter and keyed on (slug,
	// address), so an attacker holding several valid slugs cannot
	// spread requests across them to evade the per-slug ceiling.
	providerIPRequestsPerWindow = 20
	// rejectedPerWindow bounds recorded authentication failures per
	// source address. Throttling changes what is RECORDED, never what
	// is ADMITTED.
	rejectedPerWindow = 20
	rateLimitWindow   = time.Minute
)

// Config wires the SCIM routes.
type Config struct {
	Store  Store
	Logger *slog.Logger
	// KEK wraps the per-subject data-encryption keys this surface mints
	// when it provisions a subject, and opens them to seal class-three
	// audit detail.
	KEK *crypto.Encryptor
	// Now is the clock seam.
	Now func() time.Time
}

// Handler serves the SCIM v2 provisioning routes for every configured
// directory. One instance serves all providers; the slug in the path
// selects which, and the bearer token proves it.
type Handler struct {
	store  Store
	logger *slog.Logger
	kek    *crypto.Encryptor
	now    func() time.Time

	providerLimiter  *auth.RateLimiter
	providerIPLimit  *auth.RateLimiter
	rejectionLimiter *auth.RateLimiter
}

// New builds the SCIM handler.
func New(cfg Config) *Handler {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		store:            cfg.Store,
		logger:           logger,
		kek:              cfg.KEK,
		now:              now,
		providerLimiter:  auth.NewRateLimiter(providerRequestsPerWindow, rateLimitWindow),
		providerIPLimit:  auth.NewRateLimiter(providerIPRequestsPerWindow, rateLimitWindow),
		rejectionLimiter: auth.NewRateLimiter(rejectedPerWindow, rateLimitWindow),
	}
}

// Close releases the handler's rate-limit sweepers.
func (h *Handler) Close() {
	h.providerLimiter.Stop()
	h.providerIPLimit.Stop()
	h.rejectionLimiter.Stop()
}

// session is the authenticated directory on one request. It is built
// by withAuth and handed to the route, so a route can never act for a
// provider the credential did not prove.
type session struct {
	provider store.IdentityProviderRow
	// descriptor is the code-derived route name the audit record
	// carries. It comes from the mount table, never from the URL.
	descriptor string
	// tokenFingerprint is the SHA-256 digest of the presented bearer
	// token, which is also the stored form. It proves WHICH token
	// acted without the log holding anything presentable.
	tokenFingerprint string
	// originFingerprint is the SHA-256 digest of the client address.
	originFingerprint string
}

// routeHandler is a SCIM route body. It runs only for an authenticated
// directory.
type routeHandler func(w http.ResponseWriter, r *http.Request, s *session)

// Route descriptors. They name the route in the audit log and are the
// enumerated writable surface a coverage test walks.
const (
	DescUsersList     = "scim.v2.Users.List"
	DescUsersGet      = "scim.v2.Users.Get"
	DescUsersCreate   = "scim.v2.Users.Create"
	DescUsersReplace  = "scim.v2.Users.Replace"
	DescUsersPatch    = "scim.v2.Users.Patch"
	DescUsersDelete   = "scim.v2.Users.Delete"
	DescGroupsList    = "scim.v2.Groups.List"
	DescGroupsGet     = "scim.v2.Groups.Get"
	DescGroupsCreate  = "scim.v2.Groups.Create"
	DescGroupsReplace = "scim.v2.Groups.Replace"
	DescGroupsPatch   = "scim.v2.Groups.Patch"
	DescGroupsDelete  = "scim.v2.Groups.Delete"

	DescServiceProviderConfig = "scim.v2.ServiceProviderConfig"
	DescSchemas               = "scim.v2.Schemas"
	DescResourceTypes         = "scim.v2.ResourceTypes"
)

// MutationRoutes is the exact set of SCIM routes that change state.
// The design enumerates non-RPC writers from their writable surface and
// requires each to be shown writing its operation and effects in the
// same transaction as its mutation; this is that enumeration, and a
// route mounted without being classified fails the coverage test.
func MutationRoutes() []string {
	return []string{
		DescUsersCreate,
		DescUsersReplace,
		DescUsersPatch,
		DescUsersDelete,
		DescGroupsCreate,
		DescGroupsReplace,
		DescGroupsPatch,
		DescGroupsDelete,
	}
}

// SensitiveReadRoutes is the exact set of SCIM routes that return
// personal data without changing anything. They record an audited
// operation of the sensitive-read class.
func SensitiveReadRoutes() []string {
	return []string{
		DescUsersList,
		DescUsersGet,
		DescGroupsList,
		DescGroupsGet,
	}
}

// DiscoveryRoutes is the exact set of SCIM routes that describe the
// service itself. They expose no subject, no group and no
// deployment-specific value, so they record nothing.
func DiscoveryRoutes() []string {
	return []string{
		DescServiceProviderConfig,
		DescSchemas,
		DescResourceTypes,
	}
}

// Mount registers the SCIM routes on mux and returns the descriptors it
// mounted, so a test can assert the surface rather than trust this list.
//
// Every route is wrapped in withAuth: discovery MAY be anonymous under
// RFC 7644, but these responses confirm that a slug exists, so they sit
// behind the same credential as the rest.
func (h *Handler) Mount(mux *http.ServeMux) []string {
	var mounted []string
	register := func(method, path, descriptor string, handle routeHandler) {
		mux.HandleFunc(method+" "+path, h.withAuth(descriptor, handle))
		mounted = append(mounted, descriptor)
	}

	const base = "/scim/v2/{slug}"

	register(http.MethodGet, base+"/ServiceProviderConfig", DescServiceProviderConfig, h.serviceProviderConfig)
	register(http.MethodGet, base+"/Schemas", DescSchemas, h.schemas)
	register(http.MethodGet, base+"/ResourceTypes", DescResourceTypes, h.resourceTypes)

	register(http.MethodGet, base+"/Users", DescUsersList, h.listUsers)
	register(http.MethodPost, base+"/Users", DescUsersCreate, h.createUser)
	register(http.MethodGet, base+"/Users/{id}", DescUsersGet, h.getUser)
	register(http.MethodPut, base+"/Users/{id}", DescUsersReplace, h.replaceUser)
	register(http.MethodPatch, base+"/Users/{id}", DescUsersPatch, h.patchUser)
	register(http.MethodDelete, base+"/Users/{id}", DescUsersDelete, h.deleteUser)

	register(http.MethodGet, base+"/Groups", DescGroupsList, h.listGroups)
	register(http.MethodPost, base+"/Groups", DescGroupsCreate, h.createGroup)
	register(http.MethodGet, base+"/Groups/{id}", DescGroupsGet, h.getGroup)
	register(http.MethodPut, base+"/Groups/{id}", DescGroupsReplace, h.replaceGroup)
	register(http.MethodPatch, base+"/Groups/{id}", DescGroupsPatch, h.patchGroup)
	register(http.MethodDelete, base+"/Groups/{id}", DescGroupsDelete, h.deleteGroup)

	return mounted
}

// mutationOp builds the audit operation for a directory write. SCIM is
// a non-RPC writer, which is the class the design names for it.
func (h *Handler) mutationOp(s *session) store.AuditOperation {
	return h.operation(s, store.ClassBackgroundWriter)
}

// sensitiveReadOp builds the audit operation for a directory read of
// personal data.
func (h *Handler) sensitiveReadOp(s *session) store.AuditOperation {
	return h.operation(s, store.ClassSensitiveRead)
}

func (h *Handler) operation(s *session, class store.OperationClass) store.AuditOperation {
	return store.AuditOperation{
		Class:     class,
		ActorType: ActorTypeProvider,
		// The provider's own ULID: the acting principal is the
		// directory, and naming it is what makes a provisioning change
		// attributable to the directory that asked for it.
		ActorID:              s.provider.ID,
		ActorFingerprint:     s.tokenFingerprint,
		Origin:               Origin,
		OriginFingerprint:    s.originFingerprint,
		RequestDescriptor:    s.descriptor,
		AuthorizationOutcome: store.AuthorizationAllowed,
		AuthorizationDetail:  AuthorizationDetail,
		Result:               store.ResultSuccess,
	}
}
