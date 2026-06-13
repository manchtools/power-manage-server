package middleware

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func corsTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
}

// TestCORS_AllowAll_NoCredentialedWildcard pins WS5 #7: in allow-all mode the
// middleware reflects the Origin but MUST NOT also send
// Access-Control-Allow-Credentials — the reflect-any + allow-credentials combo
// is the credentialed-wildcard hole.
func TestCORS_AllowAll_NoCredentialedWildcard(t *testing.T) {
	h := CORS(nil, true, corsTestLogger())(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, "https://evil.example", w.Header().Get("Access-Control-Allow-Origin"),
		"allow-all reflects the origin")
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Credentials"),
		"allow-all must NOT set Allow-Credentials (credentialed-wildcard hole)")
}

// TestCORS_ExplicitOrigin_KeepsCredentials pins the regression-guard: an
// explicitly allow-listed origin still gets Allow-Credentials:true (the cookie
// auth flow depends on it for named origins).
func TestCORS_ExplicitOrigin_KeepsCredentials(t *testing.T) {
	h := CORS([]string{"https://app.example"}, false, corsTestLogger())(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Origin", "https://app.example")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, "https://app.example", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"),
		"a named origin keeps credentials")
}

// TestCORS_UnlistedOrigin_NoHeaders pins that a non-allow-listed origin (not in
// allow-all mode) gets no CORS headers and a preflight is 403.
func TestCORS_UnlistedOrigin_NoHeaders(t *testing.T) {
	h := CORS([]string{"https://app.example"}, false, corsTestLogger())(okHandler())

	req := httptest.NewRequest(http.MethodOptions, "/x", nil)
	req.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Credentials"))
}
