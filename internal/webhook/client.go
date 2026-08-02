// Package webhook sends bounded, generic operator notifications over HTTPS.
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// EventZeroEnabledAdministrators reports that bootstrap-admin is the only
	// remaining path back into the control plane.
	EventZeroEnabledAdministrators = "security.zero_enabled_administrators"
	// EventBackupLag reports a missing, invalid, or overdue verified backup.
	EventBackupLag = "storage.backup_lag"
	requestTimeout = 10 * time.Second
)

// Event is deliberately metadata-only: notification call sites cannot attach
// user, device, or secret values to an outbound message.
type Event struct {
	Name       string
	OccurredAt time.Time
}

type eventEnvelope struct {
	Version    int       `json:"version"`
	Event      string    `json:"event"`
	OccurredAt time.Time `json:"occurred_at"`
}

// Client sends generic events to one operator-configured endpoint.
type Client struct {
	endpoint string
	http     *http.Client
}

// New returns nil when notifications are not configured.
func New(rawURL string) (*Client, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, nil
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, errors.New("webhook_url must be an absolute https URL without credentials or fragment")
	}
	return &Client{
		endpoint: parsed.String(),
		http: &http.Client{
			Timeout:       requestTimeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// Send posts one bounded event envelope. Redirects are never followed, so an
// operator-provided credential in the webhook URL cannot be forwarded.
func (c *Client) Send(ctx context.Context, event Event) error {
	if c == nil {
		return nil
	}
	if c.http == nil || ctx == nil || !registeredEvent(event.Name) || event.OccurredAt.IsZero() {
		return errors.New("webhook requires a client, context, event name, and occurrence time")
	}
	payload, err := json.Marshal(eventEnvelope{
		Version: 1, Event: event.Name, OccurredAt: event.OccurredAt.UTC(),
	})
	if err != nil {
		return errors.New("encode webhook event")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return errors.New("build webhook request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return errors.New("send webhook request")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func registeredEvent(name string) bool {
	switch name {
	case EventZeroEnabledAdministrators, EventBackupLag:
		return true
	default:
		return false
	}
}
