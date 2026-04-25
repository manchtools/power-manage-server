package scim

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// appendEvent appends an event and logs any error.
// Use this for best-effort event appends where failure should be logged but not fatal.
func (h *Handler) appendEvent(ctx context.Context, event store.Event) {
	if err := h.store.AppendEvent(ctx, event); err != nil {
		h.logger.Error("failed to append event", "event_type", event.EventType, "stream_type", event.StreamType, "error", err)
	}
}

// contextKey is a private type for context keys in this package.
type contextKey string

// providerContextKey is the context key for the authenticated SCIM provider.
const providerContextKey contextKey = "scim_provider"

// SystemActionsCleaner is the narrow surface SCIM needs from the
// api.SystemActionManager so it can clean up system actions when a
// user is deleted via the SCIM provisioning path. Defined here as
// an interface (rather than importing api) to keep the SCIM package
// import graph free of api → scim cycles. Provided at construction
// time; nil disables cleanup (handler-test friendly).
//
// rc11 #77: SCIM was previously bypassing the system-actions
// cleanup entirely on user deletion, leaving orphan pm-tty-* and
// USER provision actions on devices.
type SystemActionsCleaner interface {
	CleanupDeletedUserActions(ctx context.Context, user db.UsersProjection) error
}

// Handler handles SCIM v2 API requests.
type Handler struct {
	store          *store.Store
	logger         *slog.Logger
	rateLimiter    *auth.RateLimiter
	systemActions  SystemActionsCleaner // optional; nil = no cleanup on delete
}

// NewHandler creates an http.Handler that serves all SCIM v2 routes.
// Routes are mounted at /scim/v2/{slug}/...
//
// systemActions may be nil — used by tests that don't exercise the
// delete cleanup path. Production wiring in cmd/control/main.go
// passes the live SystemActionManager.
func NewHandler(st *store.Store, logger *slog.Logger, systemActions SystemActionsCleaner) http.Handler {
	h := &Handler{
		store:         st,
		logger:        logger,
		rateLimiter:   auth.NewRateLimiter(100, 1*time.Minute),
		systemActions: systemActions,
	}

	mux := http.NewServeMux()

	// Discovery endpoints (no auth required)
	mux.HandleFunc("GET /scim/v2/{slug}/ServiceProviderConfig", h.withAuth(h.serviceProviderConfig))
	mux.HandleFunc("GET /scim/v2/{slug}/Schemas", h.withAuth(h.schemas))
	mux.HandleFunc("GET /scim/v2/{slug}/ResourceTypes", h.withAuth(h.resourceTypes))

	// User endpoints
	mux.HandleFunc("GET /scim/v2/{slug}/Users", h.withAuth(h.listUsers))
	mux.HandleFunc("POST /scim/v2/{slug}/Users", h.withAuth(h.createUser))
	mux.HandleFunc("GET /scim/v2/{slug}/Users/{id}", h.withAuth(h.getUser))
	mux.HandleFunc("PUT /scim/v2/{slug}/Users/{id}", h.withAuth(h.replaceUser))
	mux.HandleFunc("PATCH /scim/v2/{slug}/Users/{id}", h.withAuth(h.patchUser))
	mux.HandleFunc("DELETE /scim/v2/{slug}/Users/{id}", h.withAuth(h.deleteUser))

	// Group endpoints
	mux.HandleFunc("GET /scim/v2/{slug}/Groups", h.withAuth(h.listGroups))
	mux.HandleFunc("POST /scim/v2/{slug}/Groups", h.withAuth(h.createGroup))
	mux.HandleFunc("GET /scim/v2/{slug}/Groups/{id}", h.withAuth(h.getGroup))
	mux.HandleFunc("PUT /scim/v2/{slug}/Groups/{id}", h.withAuth(h.replaceGroup))
	mux.HandleFunc("PATCH /scim/v2/{slug}/Groups/{id}", h.withAuth(h.patchGroup))
	mux.HandleFunc("DELETE /scim/v2/{slug}/Groups/{id}", h.withAuth(h.deleteGroup))

	return mux
}
