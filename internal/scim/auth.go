package scim

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"

	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// withAuth wraps a handler with SCIM bearer token authentication.
// It extracts the slug from the URL path, looks up the identity provider,
// verifies the bearer token against the stored bcrypt hash, and stores
// the provider in the request context.
func (h *Handler) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.logger.Debug("SCIM request received", "method", r.Method, "path", r.URL.Path)

		// Extract bearer token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			h.logger.Warn("SCIM auth failed: missing authorization header", "method", r.Method, "path", r.URL.Path)
			writeError(w, http.StatusUnauthorized, "missing authorization header")
			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			h.logger.Warn("SCIM auth failed: not a Bearer token", "method", r.Method, "path", r.URL.Path)
			writeError(w, http.StatusUnauthorized, "authorization header must use Bearer scheme")
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == "" {
			h.logger.Warn("SCIM auth failed: empty token", "method", r.Method, "path", r.URL.Path)
			writeError(w, http.StatusUnauthorized, "bearer token is empty")
			return
		}

		// Get slug from path
		slug := r.PathValue("slug")
		if slug == "" {
			h.logger.Warn("SCIM auth failed: missing slug", "method", r.Method, "path", r.URL.Path)
			writeError(w, http.StatusBadRequest, "missing provider slug")
			return
		}

		// Look up provider by slug with SCIM enabled
		provider, err := h.store.Queries().GetIdentityProviderBySlugForSCIM(r.Context(), slug)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				h.logger.Warn("SCIM auth failed: unknown provider or SCIM not enabled", "slug", slug)
				writeError(w, http.StatusUnauthorized, "unknown provider or SCIM not enabled")
				return
			}
			h.logger.Error("failed to look up SCIM provider", "slug", slug, "error", err)
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}

		// Verify bearer token against stored bcrypt hash
		if provider.ScimTokenHash == "" {
			h.logger.Warn("SCIM auth failed: token not configured", "slug", slug, "provider_id", provider.ID)
			writeError(w, http.StatusUnauthorized, "SCIM token not configured")
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(provider.ScimTokenHash), []byte(token)); err != nil {
			h.logger.Warn("SCIM auth failed: invalid bearer token", "slug", slug, "provider_id", provider.ID)
			writeError(w, http.StatusUnauthorized, "invalid bearer token")
			return
		}

		// Rate limit per provider slug
		if !h.rateLimiter.Allow(slug) {
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}

		// Validate Content-Type on requests with a body
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
			ct := r.Header.Get("Content-Type")
			if ct != "" && !strings.HasPrefix(ct, "application/scim+json") && !strings.HasPrefix(ct, "application/json") {
				writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/scim+json or application/json")
				return
			}
		}

		// Store provider in context and proceed
		h.logger.Debug("SCIM request authenticated", "slug", slug, "provider_id", provider.ID, "method", r.Method, "path", r.URL.Path)
		ctx := context.WithValue(r.Context(), providerContextKey, provider)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// providerFromContext extracts the authenticated identity provider from the context.
func providerFromContext(ctx context.Context) (db.IdentityProvidersProjection, bool) {
	provider, ok := ctx.Value(providerContextKey).(db.IdentityProvidersProjection)
	return provider, ok
}
