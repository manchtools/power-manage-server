package middleware

import (
	"log/slog"
	"net/http"
)

// CORS header constants for Connect-RPC compatibility.
const (
	// corsAllowMethods lists HTTP methods allowed in cross-origin requests.
	corsAllowMethods = "GET, POST, PUT, DELETE, OPTIONS"
	// corsAllowHeaders lists request headers the client may send.
	corsAllowHeaders = "Accept, Authorization, Content-Type, Connect-Protocol-Version, Connect-Timeout-Ms, Cookie"
	// corsExposeHeaders lists response headers the browser may access.
	corsExposeHeaders = "Connect-Content-Encoding, Connect-Protocol-Version"
	// corsMaxAge is the preflight cache duration in seconds (24 hours).
	corsMaxAge = "86400"
)

// CORS returns a middleware that adds CORS headers for cross-origin requests.
// If allowedOrigins is empty and allowAll is false, CORS requests are denied (fail-closed).
// Set allowAll to true only for local development.
func CORS(allowedOrigins []string, allowAll bool, logger *slog.Logger) func(http.Handler) http.Handler {
	originSet := make(map[string]bool, len(allowedOrigins))
	for _, o := range allowedOrigins {
		originSet[o] = true
	}

	if allowAll {
		logger.Warn("CORS: allow-all mode enabled — do not use in production")
	} else if len(allowedOrigins) == 0 {
		logger.Warn("CORS: no origins configured (CONTROL_CORS_ORIGINS), all cross-origin requests will be denied")
	} else {
		logger.Info("CORS: allowed origins configured", "origins", allowedOrigins)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			if origin != "" {
				if allowAll || originSet[origin] {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				} else {
					// Origin not allowed - do not set CORS headers
					if r.Method == http.MethodOptions {
						w.WriteHeader(http.StatusForbidden)
						return
					}
					next.ServeHTTP(w, r)
					return
				}
			}

			// Handle preflight requests
			if r.Method == http.MethodOptions {
				w.Header().Add("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Methods", corsAllowMethods)
				w.Header().Set("Access-Control-Allow-Headers", corsAllowHeaders)
				w.Header().Set("Access-Control-Expose-Headers", corsExposeHeaders)
				w.Header().Set("Access-Control-Max-Age", corsMaxAge)
				w.Header().Add("Vary", "Access-Control-Request-Method")
				w.Header().Add("Vary", "Access-Control-Request-Headers")
				w.WriteHeader(http.StatusNoContent)
				return
			}

			// Always set Vary: Origin so caches key by origin presence
			w.Header().Add("Vary", "Origin")

			// Set headers for actual requests
			w.Header().Set("Access-Control-Expose-Headers", corsExposeHeaders)

			next.ServeHTTP(w, r)
		})
	}
}
