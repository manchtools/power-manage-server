package scim

import (
	"context"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
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

		// Rate limit per provider slug (before bcrypt to prevent CPU DoS)
		if !h.rateLimiter.Allow(slug) {
			h.logger.Warn("SCIM rate limit exceeded", "slug", slug, "method", r.Method, "path", r.URL.Path)
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		// Secondary rate-limit bucket keyed on (slug, client IP) so an
		// attacker that distributes requests across multiple known
		// slugs cannot evade the per-slug cap (audit F-08). The IP
		// fallback path returns "" for unparsable RemoteAddr — coalescing
		// those onto a single bucket would let a misconfigured deploy
		// rate-limit everyone to 20/min, so we skip the IP gate when
		// the address can't be identified and rely on the slug limit
		// + the underlying TCP-level peer accounting.
		if ip := auth.ClientIPFromHTTP(r); ip != "" {
			if !h.ipRateLimiter.Allow(slug + "|" + ip) {
				h.logger.Warn("SCIM per-IP rate limit exceeded",
					"slug", slug, "client_ip", ip,
					"method", r.Method, "path", r.URL.Path)
				writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
		}

		// Look up provider by slug, restricted to SCIM-enabled AND
		// login-enabled providers (WS5 #5). Unknown slug, SCIM-disabled, and
		// login-disabled all return ErrNotFound here.
		//
		// WS5 #9/#11 — no existence/timing oracle. The unknown-provider,
		// token-not-configured, and wrong-token branches ALL return one
		// identical 401 ("invalid credentials") AND perform a bcrypt compare,
		// so a client cannot distinguish "this slug exists" from "wrong token"
		// by response message or wall-clock. Distinct Warn lines stay
		// server-side for operators.
		provider, err := h.store.Repos().IdentityProvider.GetBySlugForSCIM(r.Context(), slug)
		if err != nil {
			if store.IsNotFound(err) {
				h.logger.Warn("SCIM auth failed: unknown provider, SCIM not enabled, or provider disabled", "slug", slug)
				_ = bcrypt.CompareHashAndPassword([]byte(auth.DummyHash), []byte(token))
				writeError(w, http.StatusUnauthorized, "invalid credentials")
				return
			}
			h.logger.Error("failed to look up SCIM provider", "slug", slug, "error", err)
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}

		// Verify bearer token against stored bcrypt hash.
		if provider.ScimTokenHash == "" {
			h.logger.Warn("SCIM auth failed: token not configured", "slug", slug, "provider_id", provider.ID)
			_ = bcrypt.CompareHashAndPassword([]byte(auth.DummyHash), []byte(token))
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(provider.ScimTokenHash), []byte(token)); err != nil {
			h.logger.Warn("SCIM auth failed: invalid bearer token", "slug", slug, "provider_id", provider.ID)
			writeError(w, http.StatusUnauthorized, "invalid credentials")
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
func providerFromContext(ctx context.Context) (store.IdentityProvider, bool) {
	provider, ok := ctx.Value(providerContextKey).(store.IdentityProvider)
	return provider, ok
}
