package controlruntime

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadinessHandlerFailsClosed(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/ready", nil)

	ok := httptest.NewRecorder()
	readinessHandler(func(context.Context) error { return nil })(ok, request)
	assert.Equal(t, http.StatusOK, ok.Code)

	unavailable := httptest.NewRecorder()
	readinessHandler(func(context.Context) error { return errors.New("unavailable") })(unavailable, request)
	assert.Equal(t, http.StatusServiceUnavailable, unavailable.Code)
	assert.NotContains(t, unavailable.Body.String(), "unavailable", "readiness must not expose internal errors")
}
