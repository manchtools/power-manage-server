package webhook

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRejectsUnsafeWebhookURLs(t *testing.T) {
	t.Parallel()

	client, err := New("")
	require.NoError(t, err)
	assert.Nil(t, client, "an omitted webhook must disable outbound notifications")
	assert.NoError(t, client.Send(context.Background(), Event{}), "a disabled webhook is a no-op")

	for _, raw := range []string{
		"http://hooks.example.test/notify",
		"https://user:secret@hooks.example.test/notify",
		"https://hooks.example.test/notify#fragment",
		"https:///missing-host",
	} {
		_, err := New(raw)
		assert.Error(t, err, raw)
	}
}

func TestClientSendsOnlyTheGenericEventEnvelope(t *testing.T) {
	t.Parallel()
	var got eventEnvelope
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		require.NoError(t, json.NewDecoder(r.Body).Decode(&got))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client, err := New(server.URL + "/security?token=operator-configured")
	require.NoError(t, err)
	client.http.Transport = server.Client().Transport
	at := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	require.NoError(t, client.Send(context.Background(), Event{
		Name: EventZeroEnabledAdministrators, OccurredAt: at,
	}))

	assert.Equal(t, 1, got.Version)
	assert.Equal(t, EventZeroEnabledAdministrators, got.Event)
	assert.Equal(t, at, got.OccurredAt)
}

func TestClientRejectsRedirectsAndNonSuccessResponses(t *testing.T) {
	t.Parallel()
	t.Run("redirect", func(t *testing.T) {
		followed := false
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/redirected" {
				followed = true
				w.WriteHeader(http.StatusNoContent)
				return
			}
			http.Redirect(w, r, "/redirected", http.StatusFound)
		}))
		defer server.Close()
		client, err := New(server.URL)
		require.NoError(t, err)
		client.http.Transport = server.Client().Transport

		assert.Error(t, client.Send(context.Background(), Event{Name: EventZeroEnabledAdministrators, OccurredAt: time.Now()}))
		assert.False(t, followed)
	})

	t.Run("non-success", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer server.Close()
		client, err := New(server.URL)
		require.NoError(t, err)
		client.http.Transport = server.Client().Transport

		assert.ErrorContains(t, client.Send(context.Background(), Event{
			Name: EventZeroEnabledAdministrators, OccurredAt: time.Now(),
		}), "503")
	})
}

func TestClientRejectsUnregisteredEventNames(t *testing.T) {
	t.Parallel()
	client, err := New("https://hooks.example.test")
	require.NoError(t, err)
	assert.Error(t, client.Send(context.Background(), Event{
		Name: "security.operator_supplied_detail", OccurredAt: time.Now(),
	}))
}
