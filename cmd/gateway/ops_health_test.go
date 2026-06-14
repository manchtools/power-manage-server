package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestOpsHealth_DoesNotDiscloseAgentCount pins WS10 #12: the
// unauthenticated ops /health endpoint reports liveness only and must
// not leak fleet telemetry (the connected-agent count).
func TestOpsHealth_DoesNotDiscloseAgentCount(t *testing.T) {
	rec := httptest.NewRecorder()
	opsHealthHandler(rec, httptest.NewRequest("GET", "/health", nil))

	body := rec.Body.String()
	if rec.Code != 200 {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if body != `{"status":"healthy"}` {
		t.Errorf("body = %q, want %q", body, `{"status":"healthy"}`)
	}
	if strings.Contains(body, "agents") {
		t.Errorf("health body must not disclose the agent count: %q", body)
	}
}
