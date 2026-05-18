package middleware

import "net/http"

// SecurityHeaders adds standard security headers to all responses.
//
// Content-Security-Policy is intentionally tight (audit F-05): the
// control server hosts the Connect-RPC API only — never user-supplied
// HTML or third-party iframes — so 'self'-everything is a safe
// default. `style-src` keeps `'unsafe-inline'` because Connect-RPC
// error pages and the test-harness fall back to inline style
// attributes; tighten further once the surface is audited end-to-end.
// `frame-ancestors 'none'` overlaps with X-Frame-Options DENY but is
// the modern equivalent for browsers that ignore the legacy header.
const contentSecurityPolicy = "default-src 'self'; " +
	"script-src 'self'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; " +
	"connect-src 'self'; " +
	"frame-ancestors 'none'; " +
	"base-uri 'self'; " +
	"form-action 'self'"

func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("X-XSS-Protection", "0")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}
