package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/oklog/ulid/v2"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/store"
)

// RegistrationHandler handles agent registration requests.
type RegistrationHandler struct {
	store      *store.Store
	ca         *ca.CA
	gatewayURL string
	logger     *slog.Logger
	entropy    *ulid.MonotonicEntropy
}

// NewRegistrationHandler creates a new registration handler.
func NewRegistrationHandler(st *store.Store, certAuth *ca.CA, gatewayURL string, logger *slog.Logger) *RegistrationHandler {
	return &RegistrationHandler{
		store:      st,
		ca:         certAuth,
		gatewayURL: gatewayURL,
		logger:     logger,
		entropy:    ulid.Monotonic(rand.Reader, 0),
	}
}

// Register handles agent registration requests synchronously.
// Validates the registration token, signs the CSR, emits events, and returns credentials.
func (h *RegistrationHandler) Register(ctx context.Context, req *connect.Request[pm.RegisterRequest]) (*connect.Response[pm.RegisterResponse], error) {
	logger := h.logger.With("hostname", req.Msg.Hostname, "agent_version", req.Msg.AgentVersion)
	logger.Info("processing registration request")

	// Validate CSR is present
	if len(req.Msg.Csr) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("CSR is required"))
	}

	// Hash the token and look it up
	tokenHash := sha256.Sum256([]byte(req.Msg.Token))
	tokenHashHex := hex.EncodeToString(tokenHash[:])

	token, err := h.store.Queries().GetTokenByHash(ctx, tokenHashHex)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			logger.Warn("invalid registration token")
			return nil, connect.NewError(connect.CodePermissionDenied, errors.New("invalid registration token"))
		}
		logger.Error("failed to look up token", "error", err)
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to validate token"))
	}

	// Check if token is disabled
	if token.Disabled {
		logger.Warn("token is disabled")
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("registration token is disabled"))
	}

	// Check if token is expired
	if token.ExpiresAt.Valid && time.Now().After(token.ExpiresAt.Time) {
		logger.Warn("token is expired")
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("registration token has expired"))
	}

	// Check max uses for reusable tokens
	if !token.OneTime && token.MaxUses > 0 && token.CurrentUses >= token.MaxUses {
		logger.Warn("token max uses reached")
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("registration token has reached max uses"))
	}

	// Generate device ID
	deviceID := ulid.MustNew(ulid.Timestamp(time.Now()), h.entropy).String()

	// Sign the CSR (private key stays on agent)
	cert, err := h.ca.IssueCertificateFromCSR(deviceID, req.Msg.Csr)
	if err != nil {
		logger.Error("failed to sign CSR", "error", err)
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to issue certificate"))
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

	// Emit DeviceRegistered event
	if err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   deviceID,
		EventType:  "DeviceRegistered",
		Data:       eventData,
		ActorType:  "system",
		ActorID:    "registration",
	}); err != nil {
		logger.Error("failed to append device registered event", "error", err)
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to register device"))
	}

	// Emit token used event
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
		logger.Error("failed to append token event", "error", err)
	}

	logger.Info("device registered successfully", "device_id", deviceID)

	return connect.NewResponse(&pm.RegisterResponse{
		DeviceId:    &pm.DeviceId{Value: deviceID},
		CaCert:      h.ca.CACertPEM(),
		Certificate: cert.CertPEM,
		GatewayUrl:  h.gatewayURL,
	}), nil
}
