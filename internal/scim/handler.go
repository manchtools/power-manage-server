package scim

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/manchtools/power-manage/server/internal/store"
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

// Handler handles SCIM v2 API requests.
type Handler struct {
	store  *store.Store
	logger *slog.Logger
}

// NewHandler creates an http.Handler that serves all SCIM v2 routes.
// Routes are mounted at /scim/v2/{slug}/...
func NewHandler(st *store.Store, logger *slog.Logger) http.Handler {
	h := &Handler{
		store:  st,
		logger: logger,
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
