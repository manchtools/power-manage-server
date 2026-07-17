package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
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
	now        func() time.Time // clock seam; defaults to time.Now, overridden in tests
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
		now:        time.Now,
	}
}

// Register handles agent registration requests synchronously.
// Validates the registration token, signs the CSR, emits events, and returns credentials.
func (h *RegistrationHandler) Register(ctx context.Context, req *connect.Request[pm.RegisterRequest]) (*connect.Response[pm.RegisterResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

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

	token, err := h.store.Repos().Token.GetByHash(ctx, tokenHashHex)
	if err != nil {
		if store.IsNotFound(err) {
			logger.Warn("invalid registration token")
			return nil, apiErrorCtx(ctx, ErrPermissionDenied, connect.CodePermissionDenied, "invalid registration token")
		}
		logger.Error("failed to look up token", "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to validate token")
	}

	// Fail-fast pre-check against the (possibly stale) projection read, so an
	// obviously-unusable token is rejected before the expensive CSR signing.
	// This is defence-in-depth, NOT the single-use guarantee: because it reads a
	// projection that only updates post-commit, concurrent Register calls all
	// see CurrentUses==0 and all pass here. The AUTHORITATIVE single-use / max-
	// uses enforcement is the version-pinned consume below (H2).
	if reason, ok := tokenConsumable(token, h.now()); !ok {
		logger.Warn("registration token not consumable", "reason", reason)
		return nil, apiErrorCtx(ctx, ErrPermissionDenied, connect.CodePermissionDenied, reason)
	}

	// Generate device ID
	deviceID := ulid.Make().String()

	// Sign the CSR (private key stays on agent)
	cert, err := h.ca.IssueCertificateFromCSR(deviceID, req.Msg.Csr)
	if err != nil {
		logger.Error("failed to sign CSR", "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to issue certificate")
	}

	// Build event data for device registration. CertPEM + CACertPEM
	// ride along so future replays can recover the cert bytes from
	// the event log; the projector ignores them.
	hostname := req.Msg.Hostname
	agentVersion := req.Msg.AgentVersion
	certFingerprint := cert.Fingerprint
	// Serialise as RFC3339Nano to align with the dispatch-event
	// timestamp format (audit N016). The projector parses the
	// string back into a time.Time via parseOptionalRFC3339, which
	// accepts both RFC 3339 and RFC 3339Nano so older events
	// without sub-second precision still round-trip cleanly.
	certNotAfterStr := cert.NotAfter.Format(time.RFC3339Nano)
	registrationTokenID := token.ID
	certPEM := string(cert.CertPEM)
	caCertPEM := string(h.ca.CACertPEM())
	deviceData := payloads.DeviceRegistered{
		Hostname:            &hostname,
		AgentVersion:        &agentVersion,
		CertFingerprint:     &certFingerprint,
		CertNotAfter:        &certNotAfterStr,
		RegistrationTokenID: &registrationTokenID,
		CertPEM:             &certPEM,
		CACertPEM:           &caCertPEM,
	}

	// Auto-assign device to token owner if the token has an owner
	if token.OwnerID != nil && *token.OwnerID != "" {
		ownerID := *token.OwnerID
		deviceData.AssignedUserID = &ownerID
		logger.Info("auto-assigning device to token owner", "owner_id", ownerID)
	}

	// Consume the token race-free BEFORE emitting DeviceRegistered. Using the
	// auto-versioning h.store.AppendEvent here would RETRY on version conflict,
	// so two concurrent Register calls that both passed the stale-projection
	// pre-check would BOTH consume a single-use token and both register a device
	// (H2). consumeRegistrationToken pins the expected stream version so the
	// event store's UNIQUE(stream_type, stream_id, stream_version) constraint
	// serialises concurrent consumptions: exactly one lands per version.
	if err := h.consumeRegistrationToken(ctx, logger, token, deviceID); err != nil {
		return nil, err
	}

	// Emit DeviceRegistered event (token is already consumed, safe to proceed)
	if err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   deviceID,
		EventType:  string(eventtypes.DeviceRegistered),
		Data:       deviceData,
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

// registrationBeforeConsumeHook is a test-only barrier invoked at the top of
// consumeRegistrationToken — after the (stale) projection read but before the
// first versioned append. The H2 concurrency regression test uses it to release
// all racing goroutines together so they provably read CurrentUses==0 before any
// consume lands. nil in production.
var registrationBeforeConsumeHook func()

// tokenConsumable reports whether a registration token may be consumed right
// now and, if not, the fixed user-facing reason. Shared by the fail-fast
// pre-check and the post-conflict re-validation in consumeRegistrationToken so
// both agree on the disabled / expired / max-uses / one-time-used invariant.
func tokenConsumable(token store.Token, now time.Time) (reason string, ok bool) {
	switch {
	case token.Disabled:
		return "registration token is disabled", false
	case token.ExpiresAt != nil && now.After(*token.ExpiresAt):
		return "registration token has expired", false
	case !token.OneTime && token.MaxUses > 0 && token.CurrentUses >= token.MaxUses:
		return "registration token has reached max uses", false
	case token.OneTime && token.CurrentUses > 0:
		return "registration token has already been used", false
	}
	return "", true
}

// consumeRegistrationToken consumes one use of a registration token race-free,
// using the event store's UNIQUE(stream_type, stream_id, stream_version)
// constraint as the serialisation point. Concurrent Register calls that all
// passed the stale-projection pre-check converge on the same expected version
// (ProjectionVersion+1); the DB lets exactly one land per version. A loser
// re-reads the now-advanced projection, re-validates the consume invariant
// against fresh state, and retries with the new version — so a one-time token
// yields exactly one device and a reusable token never exceeds MaxUses no matter
// how many requests race (H2). fireListeners is synchronous, so the winner's
// projection update is visible to a loser's re-read within a few attempts.
func (h *RegistrationHandler) consumeRegistrationToken(ctx context.Context, logger *slog.Logger, token store.Token, deviceID string) error {
	if registrationBeforeConsumeHook != nil {
		registrationBeforeConsumeHook()
	}

	const maxAttempts = 8
	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Re-validate against the current (fresh after a retry) projection so a
		// now-used one-time token or an at-cap reusable token fails closed
		// instead of consuming again.
		if reason, ok := tokenConsumable(token, h.now()); !ok {
			logger.Warn("registration token not consumable", "reason", reason, "attempt", attempt)
			return apiErrorCtx(ctx, ErrPermissionDenied, connect.CodePermissionDenied, reason)
		}

		eventType := "TokenUsed"
		if token.OneTime {
			eventType = "TokenDisabled"
		}
		expectedVersion := int32(token.ProjectionVersion) + 1
		err := h.store.AppendEventWithVersion(ctx, store.Event{
			StreamType: "token",
			StreamID:   token.ID,
			EventType:  eventType,
			Data:       payloads.RegistrationTokenConsumed{DeviceID: deviceID},
			ActorType:  "system",
			ActorID:    "registration",
		}, expectedVersion)
		if err == nil {
			return nil
		}
		if !store.IsVersionConflict(err) {
			logger.Error("failed to consume registration token", "error", err)
			return apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to consume registration token")
		}

		// Lost the OCC race — another consume advanced the token stream. Reload
		// the fresh projection and retry; the loop head re-validates the
		// invariant so a fully-consumed token fails closed.
		fresh, gErr := h.store.Repos().Token.GetByHash(ctx, token.ValueHash)
		if gErr != nil {
			logger.Error("failed to reload registration token after version conflict", "error", gErr)
			return apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to consume registration token")
		}
		token = fresh
	}

	// Exhausted retries purely due to contention (not an invariant violation).
	// Fail closed with a retryable code rather than risk an unbounded loop.
	logger.Warn("registration token consume exhausted retries under contention", "token_id", token.ID)
	return apiErrorCtx(ctx, ErrInternal, connect.CodeUnavailable, "registration token is contended; retry")
}
