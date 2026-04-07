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
// If allowedOrigins is empty, all origins are allowed (development mode) with a warning.
// Set CONTROL_CORS_ORIGINS=https://app.example.com,https://other.example.com for production.
func CORS(allowedOrigins []string, logger *slog.Logger) func(http.Handler) http.Handler {
	originSet := make(map[string]bool, len(allowedOrigins))
	for _, o := range allowedOrigins {
		originSet[o] = true
	}

	allowAll := len(allowedOrigins) == 0
	if allowAll {
		logger.Warn("CORS: no origins configured (CONTROL_CORS_ORIGINS), allowing all origins -- set this in production")
	} else {
		logger.Info("CORS: allowed origins configured", "origins", allowedOrigins)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// OPTIONS without Origin is not a CORS preflight — return early.
			if r.Method == http.MethodOptions && origin == "" {
				w.WriteHeader(http.StatusNoContent)
				return
			}

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
				w.Header().Set("Access-Control-Allow-Methods", corsAllowMethods)
				w.Header().Set("Access-Control-Allow-Headers", corsAllowHeaders)
				w.Header().Set("Access-Control-Expose-Headers", corsExposeHeaders)
				w.Header().Set("Access-Control-Max-Age", corsMaxAge)
				w.WriteHeader(http.StatusNoContent)
				return
			}

			// Set headers for actual requests
			w.Header().Set("Access-Control-Expose-Headers", corsExposeHeaders)

			next.ServeHTTP(w, r)
		})
	}
}
