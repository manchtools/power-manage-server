package agentstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/mtls"
)

type fakeRevocation struct {
	revoked bool
	err     error
}

func (f fakeRevocation) IsRevoked(context.Context, string) (bool, error) {
	return f.revoked, f.err
}

func TestMTLSMiddlewareFailsClosedAndBindsAgentIdentity(t *testing.T) {
	deviceID := ulid.Make().String()
	agentURI, err := mtls.PeerClassURI(mtls.PeerClassAgent)
	require.NoError(t, err)
	controlURI, err := mtls.PeerClassURI(mtls.PeerClassControl)
	require.NoError(t, err)
	cert := func(uri *url.URL) *x509.Certificate {
		return &x509.Certificate{
			Raw: []byte("certificate"), Subject: pkix.Name{CommonName: deviceID}, URIs: []*url.URL{uri},
		}
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	next := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		got, ok := DeviceIDFromContext(request.Context())
		if !ok || got != deviceID {
			http.Error(w, "identity missing", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	call := func(checker mtls.RevocationChecker, peer *x509.Certificate, path string) int {
		request := httptest.NewRequest(http.MethodPost, path, nil)
		if peer != nil {
			request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peer}}
		}
		response := httptest.NewRecorder()
		MTLSMiddleware(next, checker, logger).ServeHTTP(response, request)
		return response.Code
	}

	assert.Equal(t, http.StatusNoContent, call(fakeRevocation{}, cert(agentURI), "/stream"))
	assert.Equal(t, http.StatusUnauthorized, call(fakeRevocation{}, nil, "/stream"))
	assert.Equal(t, http.StatusForbidden, call(fakeRevocation{}, cert(controlURI), "/stream"))
	assert.Equal(t, http.StatusForbidden, call(nil, cert(agentURI), "/stream"))
	assert.Equal(t, http.StatusForbidden, call(fakeRevocation{err: errors.New("database unavailable")}, cert(agentURI), "/stream"))
	assert.Equal(t, http.StatusForbidden, call(fakeRevocation{revoked: true}, cert(agentURI), "/stream"))

	health := httptest.NewRequest(http.MethodGet, "/health", nil)
	healthResponse := httptest.NewRecorder()
	MTLSMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }), nil, logger).
		ServeHTTP(healthResponse, health)
	assert.Equal(t, http.StatusOK, healthResponse.Code)
}
