package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// stubHandler writes a sentinel so the test can tell the bridge
// handler apart from the ServeMux default NotFound.
type stubHandler struct{}

func (stubHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("bridge"))
}

func TestBuildWebMux_RegistersBothTerminalPaths(t *testing.T) {
	mux := buildWebMux("01KEXAMPLEGATEWAYID00000000", stubHandler{})

	tests := []struct {
		name     string
		path     string
		wantCode int
		wantBody string
	}{
		{"prefixed path routes to bridge", "/gw/01KEXAMPLEGATEWAYID00000000/terminal", http.StatusOK, "bridge"},
		{"unprefixed path still routes to bridge", "/terminal", http.StatusOK, "bridge"},
		{"health is plain OK", "/health", http.StatusOK, "ok"},
		{"unknown path is 404", "/nope", http.StatusNotFound, "404 page not found\n"},
		{"wrong gateway id prefix is 404", "/gw/01KOTHERID/terminal", http.StatusNotFound, "404 page not found\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != tt.wantCode {
				t.Errorf("%s: got status %d, want %d", tt.path, rec.Code, tt.wantCode)
			}
			if body := rec.Body.String(); body != tt.wantBody {
				t.Errorf("%s: got body %q, want %q", tt.path, body, tt.wantBody)
			}
		})
	}
}

func TestBuildWebMux_EmptyGatewayIDSkipsPrefixedRoute(t *testing.T) {
	mux := buildWebMux("", stubHandler{})

	// Unprefixed /terminal still works — single-gateway case.
	req := httptest.NewRequest(http.MethodGet, "/terminal", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("/terminal should route to bridge even without gatewayID, got %d", rec.Code)
	}

	// No prefixed route registered — any /gw/... 404s.
	req = httptest.NewRequest(http.MethodGet, "/gw/01KOTHERID/terminal", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("/gw/... should 404 without gatewayID, got %d", rec.Code)
	}
}
