package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/oklog/ulid/v2"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/store"
)

// ValidateGatewayURL returns nil when raw is a gateway URL an agent
// can actually connect to over mTLS. A surprising number of shapes
// pass `url.Parse` without being usable:
//   - bare hostnames like `gateway.example.com` parse with Scheme="",
//     Host="", Path="gateway.example.com" — the agent would try to
//     dial a relative path;
//   - `http://...` is refused because rc10 agents refuse h2c;
//   - `wss://...` or other schemes are refused because the agent's
//     gateway client uses HTTPS transport;
//   - user-info (`https://user:pass@host/`) is refused because
//     credentials in the URL are never the right answer and would
//     leak on every enrollment response;
//   - fragments are meaningless on the wire and refused to keep the
//     shape tight.
//
// Used both at control server startup (fatal on violation, so a
// misconfiguration is visible at boot) and defensively in the
// registration handler before the URL is handed to the agent.
func ValidateGatewayURL(raw string) error {
	if raw == "" {
		return fmt.Errorf("gateway URL is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("gateway URL parse failed: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("gateway URL must use https scheme, got %q", u.Scheme)
	}
	// u.Hostname() strips port and brackets so "https://:8443" (port
	// only, no host) and "https://[::1]:443" (IPv6) both validate
	// under the same rule. u.Host would accept ":8443" silently.
	if u.Hostname() == "" {
		return fmt.Errorf("gateway URL has no host — bare hostnames like %q are not absolute URLs", RedactGatewayURL(raw))
	}
	if u.User != nil {
		return fmt.Errorf("gateway URL must not contain userinfo (credentials in URL leak on every enrollment response)")
	}
	if u.Fragment != "" {
		return fmt.Errorf("gateway URL must not contain a fragment")
	}
	return nil
}

// RedactGatewayURL strips userinfo from a URL-shaped string for safe
// logging / panic messages. Exported so cmd/control/main.go can use
// the same redaction on the startup-log error path.
//
// If the input is unparseable, returns a placeholder rather than the
// raw value — a malformed url.Parse input that still carries
// credentials in a substring shouldn't leak just because the parser
// rejected it (e.g. "https://u:p@host:notaport" fails to parse as
// a URL but still contains "u:p" in-band).
func RedactGatewayURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "<unparseable URL>"
	}
	if u.User == nil {
		return raw
	}
	// Rebuild without userinfo.
	u.User = nil
	return u.String()
}

// RegistrationHandler handles agent registration requests.
type RegistrationHandler struct {
	store      *store.Store
	ca         *ca.CA
	gatewayURL string
	logger     *slog.Logger
}

// NewRegistrationHandler creates a new registration handler. Panics
// when gatewayURL fails ValidateGatewayURL — caller is expected to
// have validated at startup, so reaching the handler constructor
// with a bad value is a programmer error, not a runtime condition.
// Startup-time validation (cmd/control/main.go) surfaces the same
// check with a clean operator-facing error message.
func NewRegistrationHandler(st *store.Store, certAuth *ca.CA, gatewayURL string, logger *slog.Logger) *RegistrationHandler {
	if err := ValidateGatewayURL(gatewayURL); err != nil {
		// Redact userinfo before panicking — a gateway URL that
		// contains credentials (which the validator is rejecting)
		// would otherwise leak them into the crash log.
		panic(fmt.Sprintf("NewRegistrationHandler: invalid gateway URL %q: %v", RedactGatewayURL(gatewayURL), err))
	}
	return &RegistrationHandler{
		store:      st,
		ca:         certAuth,
		gatewayURL: gatewayURL,
		logger:     logger,
	}
}

// Register handles agent registration requests synchronously.
// Validates the registration token, signs the CSR, emits events, and returns credentials.
func (h *RegistrationHandler) Register(ctx context.Context, req *connect.Request[pm.RegisterRequest]) (*connect.Response[pm.RegisterResponse], error) {
	logger := h.logger.With("hostname", req.Msg.Hostname, "agent_version", req.Msg.AgentVersion)
	logger.Info("processing registration request")

	// Defence in depth: the startup guard in cmd/control/main.go
	// plus the NewRegistrationHandler constructor both run
	// ValidateGatewayURL, so reaching this check with an invalid
	// URL would mean both earlier layers regressed. We re-run the
	// full validator (not just the emptiness check) so the agent
	// never receives a URL shape that the URL validators missed —
	// bare hostnames, http://, userinfo, etc.
	if err := ValidateGatewayURL(h.gatewayURL); err != nil {
		logger.Error("registration refused: gatewayURL failed validation",
			"gateway_url", RedactGatewayURL(h.gatewayURL), "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeFailedPrecondition, "server misconfiguration: gateway URL is invalid")
	}

	// Validate CSR is present
	if len(req.Msg.Csr) == 0 {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "CSR is required")
	}

	// Hash the token and look it up
	tokenHash := sha256.Sum256([]byte(req.Msg.Token))
	tokenHashHex := hex.EncodeToString(tokenHash[:])

	token, err := h.store.Queries().GetTokenByHash(ctx, tokenHashHex)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			logger.Warn("invalid registration token")
			return nil, apiErrorCtx(ctx, ErrPermissionDenied, connect.CodePermissionDenied, "invalid registration token")
		}
		logger.Error("failed to look up token", "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to validate token")
	}

	// Check if token is disabled
	if token.Disabled {
		logger.Warn("token is disabled")
		return nil, apiErrorCtx(ctx, ErrPermissionDenied, connect.CodePermissionDenied, "registration token is disabled")
	}

	// Check if token is expired
	if token.ExpiresAt != nil && time.Now().After(*token.ExpiresAt) {
		logger.Warn("token is expired")
		return nil, apiErrorCtx(ctx, ErrPermissionDenied, connect.CodePermissionDenied, "registration token has expired")
	}

	// Check max uses for reusable tokens
	if !token.OneTime && token.MaxUses > 0 && token.CurrentUses >= token.MaxUses {
		logger.Warn("token max uses reached")
		return nil, apiErrorCtx(ctx, ErrPermissionDenied, connect.CodePermissionDenied, "registration token has reached max uses")
	}
	// Defence-in-depth for one-time tokens. The `token.Disabled` check above
	// already rejects consumed one-time tokens once their TokenDisabled event
	// has projected, and the event-store optimistic lock at AppendEvent
	// rejects concurrent consumptions. Rejecting on CurrentUses>0 here fails
	// fast in the projection-lag window, before the (expensive) CSR signing.
	if token.OneTime && token.CurrentUses > 0 {
		logger.Warn("one-time token already used")
		return nil, apiErrorCtx(ctx, ErrPermissionDenied, connect.CodePermissionDenied, "registration token has already been used")
	}

	// Generate device ID
	deviceID := ulid.Make().String()

	// Sign the CSR (private key stays on agent)
	cert, err := h.ca.IssueCertificateFromCSR(deviceID, req.Msg.Csr)
	if err != nil {
		logger.Error("failed to sign CSR", "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to issue certificate")
	}

	// Build event data for device registration
	eventData := map[string]any{
		"hostname":              req.Msg.Hostname,
		"agent_version":         req.Msg.AgentVersion,
		"cert_fingerprint":      cert.Fingerprint,
		"cert_not_after":        cert.NotAfter.Format(time.RFC3339),
		"registration_token_id": token.ID,
		"cert_pem":              string(cert.CertPEM),
		"ca_cert_pem":           string(h.ca.CACertPEM()),
	}

	// Auto-assign device to token owner if the token has an owner
	if token.OwnerID != nil && *token.OwnerID != "" {
		eventData["assigned_user_id"] = *token.OwnerID
		logger.Info("auto-assigning device to token owner", "owner_id", *token.OwnerID)
	}

	// Consume the token FIRST to prevent race conditions with one-time tokens.
	// The token stream has optimistic locking (version conflict on concurrent
	// writes), so only one concurrent registration can succeed for a one-time
	// token. If we registered the device first, a second concurrent request
	// could create an orphaned device before failing on the token event.
	eventType := "TokenUsed"
	if token.OneTime {
		eventType = "TokenDisabled"
	}
	if err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "token",
		StreamID:   token.ID,
		EventType:  eventType,
		Data: map[string]any{
			"device_id": deviceID,
		},
		ActorType: "system",
		ActorID:   "registration",
	}); err != nil {
		logger.Error("failed to consume token (possible concurrent use)", "error", err)
		return nil, apiErrorCtx(ctx, ErrPermissionDenied, connect.CodePermissionDenied, "registration token has already been used")
	}

	// Emit DeviceRegistered event (token is already consumed, safe to proceed)
	if err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   deviceID,
		EventType:  "DeviceRegistered",
		Data:       eventData,
		ActorType:  "system",
		ActorID:    "registration",
	}); err != nil {
		logger.Error("failed to append device registered event", "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to register device")
	}

	logger.Info("device registered successfully", "device_id", deviceID)

	return connect.NewResponse(&pm.RegisterResponse{
		DeviceId:    &pm.DeviceId{Value: deviceID},
		CaCert:      h.ca.CACertPEM(),
		Certificate: cert.CertPEM,
		GatewayUrl:  h.gatewayURL,
	}), nil
}
