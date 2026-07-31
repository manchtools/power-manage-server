package scim

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
)

// bearerScheme is the only authentication scheme this surface accepts.
const bearerScheme = "Bearer "

// absentTokenDigest is what an unknown provider is compared against.
//
// Every credential path does the same work — digest the presented
// value, compare it in constant time against a 64-character hex string
// — so "no such directory" and "wrong token" differ in neither the
// response nor the work performed. The value is not a digest of
// anything; no token can produce it.
const absentTokenDigest = "0000000000000000000000000000000000000000000000000000000000000000"

// withAuth is the SCIM trust boundary. It runs in the design's order:
// the request's shape is validated, then the credential is
// authenticated, and only then does a route body see the provider it is
// allowed to act for.
//
// Every refusal returns one identical body. A client that could tell
// "no such directory" from "wrong token" could enumerate which
// directories a deployment has configured, so the branches differ only
// in what they record server-side.
func (h *Handler) withAuth(descriptor string, next routeHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// --- validate -------------------------------------------------
		slug := r.PathValue("slug")
		if slug == "" {
			writeError(w, http.StatusBadRequest, "missing provider slug")
			return
		}
		if !acceptableContentType(r) {
			writeError(w, http.StatusUnsupportedMediaType,
				"Content-Type must be application/scim+json or application/json")
			return
		}

		clientIP := auth.ClientIPFromHTTP(r)

		// The credential path is gated before any digest work. The
		// per-slug bucket bounds one directory; the (slug, address)
		// bucket stops an attacker holding several valid slugs from
		// spreading requests across them to evade it. An address that
		// cannot be identified skips the second bucket rather than
		// coalescing every anonymous caller onto one, which would let a
		// misconfigured deployment throttle everyone.
		if !h.providerLimiter.Allow(slug) {
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		if clientIP != "" && !h.providerIPLimit.Allow(slug+"|"+clientIP) {
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}

		// --- authenticate ---------------------------------------------
		token, ok := bearerToken(r.Header.Get("Authorization"))
		if !ok {
			h.refuse(ctx, w, descriptor, reasonMissingCredentials, token, clientIP)
			return
		}
		presented := fingerprint(token)

		expected := absentTokenDigest
		reason := ""
		provider, err := h.store.GetIdentityProviderBySlug(ctx, slug)
		switch {
		case err != nil && store.IsNotFound(err):
			reason = reasonUnknownProvider
		case err != nil:
			h.logger.Error("scim: failed to resolve provider", "error", err)
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		case !provider.Enabled:
			// One switch turns the whole provider off. A directory that
			// kept provisioning through a disabled provider would keep
			// minting subjects nobody can sign in as.
			reason = reasonProviderDisabled
		case !provider.ScimEnabled:
			reason = reasonSCIMDisabled
		case provider.ScimTokenHash == "":
			reason = reasonNoTokenConfigured
		default:
			expected = provider.ScimTokenHash
		}

		// The comparison runs on every path, including the ones already
		// refused above, so the work is the same whatever went wrong.
		matched := subtle.ConstantTimeCompare([]byte(presented), []byte(expected)) == 1
		if reason == "" && !matched {
			reason = reasonInvalidToken
		}
		if reason != "" {
			h.refuse(ctx, w, descriptor, reason, token, clientIP)
			return
		}

		next(w, r, &session{
			provider:          provider,
			descriptor:        descriptor,
			tokenFingerprint:  presented,
			originFingerprint: fingerprint(clientIP),
		})
	}
}

// refuse answers a failed credential and records it under the dedicated
// rejected-authentication class.
//
// The audit write is gated by a per-address limiter: a flood of bad
// credentials from one source is throttled, so the audit log cannot be
// used as a write amplifier. The refusal itself is unconditional —
// throttling changes what is RECORDED, never what is ADMITTED.
func (h *Handler) refuse(ctx context.Context, w http.ResponseWriter, descriptor, reason, credential, clientIP string) {
	// Logging stays metadata-only: the reason and the route, never the
	// presented value.
	h.logger.Warn("scim: refused credential", "route", descriptor, "reason", reason)

	if h.rejectionLimiter.Allow("rej:" + clientIP) {
		_, err := h.store.RecordOperation(ctx, store.AuditOperation{
			Class: store.ClassRejectedAuthentication,
			// Not "scim_provider": nothing about the attempt is known
			// to be a provider, and an actor id is what a rejected
			// attempt has by definition failed to establish.
			ActorType:            auth.AnonymousActorType,
			ActorFingerprint:     fingerprint(credential),
			Origin:               Origin,
			OriginFingerprint:    fingerprint(clientIP),
			RequestDescriptor:    descriptor,
			AuthorizationOutcome: store.AuthorizationDenied,
			AuthorizationDetail:  AuthorizationDetail,
			Result:               store.ResultRejected,
			ResultCode:           reason,
		})
		if err != nil {
			h.logger.Error("scim: failed to record rejected authentication",
				"route", descriptor, "reason", reason, "error", err)
		}
	}

	writeError(w, http.StatusUnauthorized, "invalid credentials")
}

// bearerToken extracts the credential from an Authorization header. A
// missing header, a different scheme and an empty credential are all
// reported as the same "no usable credential" condition.
func bearerToken(header string) (string, bool) {
	if !strings.HasPrefix(header, bearerScheme) {
		return "", false
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, bearerScheme))
	return token, token != ""
}

// acceptableContentType reports whether a request that carries a body
// declared a type this surface parses. A request with no body imposes
// no requirement.
func acceptableContentType(r *http.Request) bool {
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
	default:
		return true
	}
	ct := r.Header.Get("Content-Type")
	return ct == "" ||
		strings.HasPrefix(ct, scimContentType) ||
		strings.HasPrefix(ct, "application/json")
}
