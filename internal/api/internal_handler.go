package api

import (
	"context"
	"crypto/ecdh"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"

	sdkcrypto "github.com/manchtools/power-manage-sdk/crypto"
	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/pm/v1/pmv1connect"
	"github.com/manchtools/power-manage/server/internal/actionparams"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/crl"
	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/gateway/registry"
	"github.com/manchtools/power-manage/server/internal/resolution"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/terminal"
)

// InternalHandler implements the InternalService for gateway → control proxying.
// This service is only accessible on the internal network, not exposed externally.
type InternalHandler struct {
	pmv1connect.UnimplementedInternalServiceHandler

	store     *store.Store
	encryptor *crypto.Encryptor
	logger    *slog.Logger

	// signer signs the SignedActionEnvelope for each action delivered by
	// the autonomous SYNC path (ProxySyncActions). The PUSH/dispatch
	// rewrite stopped create-time signing, so the sync path re-signs at
	// DELIVERY, device-bound to the syncing device. A nil signer is a
	// wiring bug: ProxySyncActions fails closed rather than hand the agent
	// an unsigned action it would reject. main.go passes the real
	// internal/ca signer; tests pass a CA-backed ca.ActionSigner.
	signer ca.ActionSigner

	// terminalTokenStore is set via SetTerminalTokenStore after the
	// Valkey-backed store is constructed in main.go. nil when terminal
	// sessions are not configured on this control instance, in which
	// case ProxyValidateTerminalToken returns Unavailable so the
	// gateway gets a clean error rather than the InternalService
	// default 'method not implemented'.
	terminalTokenStore *terminal.TokenStore

	// deviceGatewayResolver resolves which gateway a device is currently live
	// on, written under the agent's mTLS identity (the device→gateway routing
	// registry). Set via SetDeviceGatewayResolver in HA/multi-gateway
	// deployments. When nil (single-gateway, non-HA), the device-origin binding
	// check is bypassed — the documented single-gateway exception (see ADR).
	deviceGatewayResolver registry.DeviceGatewayLookup

	now func() time.Time // clock seam; defaults to time.Now, overridden in tests

	// lpsPrivateKey unseals LPS passwords the agent sealed to the control
	// LPS public key (ProxyStoreLpsPasswords). lpsPublicKey is the CA-signed
	// public key distributed to agents in the sync response
	// (ProxySyncActions). Both are set via SetLpsKeypair after EnsureLpsKeypair
	// in main.go; nil when the LPS keypair is not configured, in which case
	// ProxyStoreLpsPasswords fails closed (cannot unseal) and sync omits the
	// key (agents then refuse to rotate — fail closed on both ends).
	lpsPrivateKey *ecdh.PrivateKey
	lpsPublicKey  *pm.LpsPublicKey

	// gatewayCA re-signs gateway certs on RenewGatewayCertificate; gatewayCRL
	// revokes the superseded fingerprint. Both wired via SetGatewayRenewal in
	// main.go (spec 31); nil until then, in which case renewal fails closed.
	gatewayCA  *ca.CA
	gatewayCRL *crl.Store
}

// SetLpsKeypair wires the control server's LPS sealing keypair: the private
// key used to unseal rotated passwords at receipt, and the pre-signed public
// key distributed to agents in the sync response. Called from main.go after
// EnsureLpsKeypair + BuildSignedLpsPublicKey.
func (h *InternalHandler) SetLpsKeypair(priv *ecdh.PrivateKey, signedPublicKey *pm.LpsPublicKey) {
	h.lpsPrivateKey = priv
	h.lpsPublicKey = signedPublicKey
}

// SetDeviceGatewayResolver wires the device→gateway routing registry so every
// credential-bearing InternalService request (ProxySync*/LUKS/LPS/terminal) is
// confined to the gateway the device is actually live on
// (verifyDeviceGatewayBinding). VerifyDevice is exempt — it is the pre-attach
// bootstrap and would otherwise deadlock the device's own connection. Called from
// main.go in HA/multi-gateway deployments; left nil for single-gateway.
func (h *InternalHandler) SetDeviceGatewayResolver(r registry.DeviceGatewayLookup) {
	h.deviceGatewayResolver = r
}

// NewInternalHandler creates a new internal service handler.
//
// signer is the CA-backed action signer used by ProxySyncActions to sign
// each delivered SignedActionEnvelope device-bound. It is required for the
// sync path; a nil signer makes ProxySyncActions fail closed rather than
// deliver unsigned actions the agent would reject.
func NewInternalHandler(st *store.Store, enc *crypto.Encryptor, logger *slog.Logger, signer ca.ActionSigner) *InternalHandler {
	return &InternalHandler{
		store:     st,
		encryptor: enc,
		logger:    logger,
		signer:    signer,
		now:       time.Now,
	}
}

// SetTerminalTokenStore wires the Valkey-backed terminal token store
// so ProxyValidateTerminalToken can validate the bearer tokens minted
// by ControlService.StartTerminal. Called from main.go alongside
// ControlService.SetTerminalHandler so the two paths share one store.
func (h *InternalHandler) SetTerminalTokenStore(s *terminal.TokenStore) {
	h.terminalTokenStore = s
}

// VerifyDevice checks that a device exists and is not deleted.
// Called by the gateway before registering an agent connection.
func (h *InternalHandler) VerifyDevice(ctx context.Context, req *connect.Request[pm.VerifyDeviceRequest]) (*connect.Response[pm.VerifyDeviceResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	deviceID := req.Msg.DeviceId
	if deviceID == "" {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "device_id is required")
	}

	// VerifyDevice deliberately does NOT call verifyDeviceGatewayBinding. It is the
	// connection BOOTSTRAP: handler/agent.go calls it to admit a device's mTLS
	// stream BEFORE AttachDevice publishes the device→gateway binding. Enforcing
	// the binding here is a chicken-and-egg — the device can't verify (to connect)
	// until it is live, and can't become live until it connects — so it rejects
	// EVERY agent whenever the routing registry is wired (the server#404 regression
	// these binding checks introduced). The SA-C2 confinement that binding protects
	// does not apply: VerifyDevice reads only existence, returns no secret/action,
	// and appends no event, and the device's identity is already proven by its mTLS
	// client cert (agent.go checks cert device-id == hello device-id). The binding
	// stays enforced on the credential-bearing ProxySync*/LUKS/LPS/terminal methods,
	// which run only after the device is live.
	_, err := h.store.Repos().Device.Get(ctx, store.GetDeviceKey{ID: deviceID})
	if err != nil {
		h.logger.Warn("device verification failed", "device_id", deviceID, "error", err)
		return nil, apiErrorCtx(ctx, ErrDeviceNotFound, connect.CodeNotFound, "device not found or deleted")
	}

	return connect.NewResponse(&pm.VerifyDeviceResponse{}), nil
}

// ProxySyncActions resolves all assigned actions for a device.
func (h *InternalHandler) ProxySyncActions(ctx context.Context, req *connect.Request[pm.InternalSyncActionsRequest]) (*connect.Response[pm.SyncActionsResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	deviceID := req.Msg.DeviceId
	if deviceID == "" {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "device_id is required")
	}
	if err := h.verifyDeviceGatewayBinding(ctx, req.Msg.DeviceId, req.Msg.GatewayId); err != nil {
		return nil, err
	}

	// Fail closed on a missing signer. Synced actions are signed at
	// DELIVERY device-bound (the dispatch rewrite stopped create-time
	// signing); without a signer every Action would ship with an empty
	// signature the offline agent rejects. A nil signer is a wiring bug —
	// surface it loudly rather than silently sync unverifiable actions.
	if h.signer == nil {
		h.logger.Error("sync actions: nil signer — wiring bug", "device_id", deviceID)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "action signer not configured")
	}

	// Verify the device exists and is not deleted.
	if _, err := h.store.Repos().Device.Get(ctx, store.GetDeviceKey{ID: deviceID}); err != nil {
		h.logger.Warn("sync actions for unknown/deleted device", "device_id", deviceID)
		return nil, apiErrorCtx(ctx, ErrDeviceNotFound, connect.CodeNotFound, "device not found or deleted")
	}

	h.logger.Debug("proxy sync actions", "device_id", deviceID)

	// Device-layer tree (groups + standalone), built with the new
	// container-wins precedence introduced for #45.
	tree, err := resolution.ResolveDeviceTree(ctx, h.store.Queries(), deviceID)
	if err != nil {
		h.logger.Error("failed to resolve device tree", "device_id", deviceID, "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to resolve actions")
	}

	// User-layer assignments and the permission-derived TTY actions
	// continue to flow through the existing flat resolver and ride on
	// standalone_actions. The flat resolver also still serves the
	// device-layer; we filter its result down to "actions absorbed by
	// the new tree" to avoid duplicate emission, and use the tree's
	// container modes (UNINSTALL → ABSENT) where they apply.
	dbActions, err := resolution.ResolveActionsForDevice(ctx, h.store.Queries(), deviceID)
	if err != nil {
		h.logger.Error("failed to resolve actions", "device_id", deviceID, "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to resolve actions")
	}

	syncInterval, err := h.store.Repos().Device.SyncInterval(ctx, deviceID)
	if err != nil {
		h.logger.Warn("failed to get sync interval, using default", "device_id", deviceID, "error", err)
		syncInterval = 0
	}

	// Action ids covered by the device-layer tree (groups + standalone).
	covered := make(map[string]bool, len(tree.Actions))
	for id := range tree.Actions {
		covered[id] = true
	}

	standalone := make([]*pm.Action, 0, len(tree.StandaloneActions)+len(dbActions))

	// Standalone from the new tree first — these take precedence over
	// the flat resolver's view (the flat resolver still uses the old
	// action-wins collapse, which the new tree overrides).
	for _, sa := range tree.StandaloneActions {
		raw, ok := tree.Actions[sa.ActionID]
		if !ok {
			continue
		}
		// Fold UNINSTALL → ABSENT into the desired state we SIGN, not just
		// the advisory wire field: the agent executes the verified envelope,
		// so the container's uninstall intent must ride in the signed bytes.
		desiredState := raw.DesiredState
		if sa.Mode == resolution.ModeUninstall {
			desiredState = int32(pm.DesiredState_DESIRED_STATE_ABSENT)
		}
		wire, err := dbActionToWireAction(raw, h.signer, deviceID, desiredState)
		if err != nil {
			// Fail closed: skip an action whose params don't parse (or
			// whose envelope can't be signed) rather than sync it to the
			// agent with empty/invalid params or an empty signature (#368).
			h.logger.Warn("skipping standalone action with unparseable params or unsignable envelope", "action_id", raw.ID, "error", err)
			continue
		}
		standalone = append(standalone, wire)
	}

	// Flat resolver's leftovers — anything not in the tree (user-layer,
	// TTY actions, and any device-layer leftover the new tree didn't
	// surface). These keep the flat resolver's per-action desired_state.
	for _, dbAction := range dbActions {
		if covered[dbAction.ID] {
			continue
		}
		action, err := dbResolvedActionToWireAction(dbAction, h.signer, deviceID)
		if err != nil {
			// Fail closed: skip rather than sync empty params or an
			// unsignable envelope (#368).
			h.logger.Warn("skipping resolved action with unparseable params or unsignable envelope", "action_id", dbAction.ID, "error", err)
			continue
		}
		standalone = append(standalone, action)
	}

	// Group emission: walk the tree's group list, hydrate proto Actions,
	// and apply UNINSTALL → ABSENT for groups whose container is in
	// uninstall mode.
	groups := make([]*pm.ActionGroup, 0, len(tree.Groups))
	for _, g := range tree.Groups {
		groupActions := make([]*pm.Action, 0, len(g.ActionIDs))
		for _, id := range g.ActionIDs {
			raw, ok := tree.Actions[id]
			if !ok {
				continue
			}
			// Fold the group container's UNINSTALL → ABSENT into the signed
			// desired state (see the standalone path above): the agent
			// executes the verified envelope, so the override must be inside
			// the signed bytes, not just the advisory wire field.
			desiredState := raw.DesiredState
			if g.Mode == resolution.ModeUninstall {
				desiredState = int32(pm.DesiredState_DESIRED_STATE_ABSENT)
			}
			wire, err := dbActionToWireAction(raw, h.signer, deviceID, desiredState)
			if err != nil {
				// Fail closed: skip rather than sync empty params or an
				// unsignable envelope (#368).
				h.logger.Warn("skipping group action with unparseable params or unsignable envelope", "action_id", raw.ID, "error", err)
				continue
			}
			groupActions = append(groupActions, wire)
		}
		if len(groupActions) == 0 {
			continue
		}
		groups = append(groups, &pm.ActionGroup{
			SourceLabel: g.SourceLabel,
			Schedule:    actionparams.ScheduleFromJSON(g.Schedule),
			Actions:     groupActions,
		})
	}

	// Resolved maintenance window across every group reaching the
	// device. resolveMaintenanceWindowUnion returns nil when there is
	// no constraint — the proto field stays unset so the agent skips
	// the gate entirely. See manchtools/power-manage-server#58.
	windowRows, err := h.store.Queries().ListMaintenanceWindowsForDevice(ctx, deviceID)
	if err != nil {
		h.logger.Warn("failed to load maintenance windows for sync; falling back to no constraint",
			"device_id", deviceID, "error", err)
	}
	resolvedWindow := resolveMaintenanceWindowUnion(windowRows)

	h.logger.Debug("proxy sync actions completed",
		"device_id", deviceID,
		"standalone_count", len(standalone),
		"group_count", len(groups),
		"sync_interval_minutes", syncInterval,
		"window_entries", windowEntryCount(resolvedWindow))

	return connect.NewResponse(&pm.SyncActionsResponse{
		StandaloneActions:   standalone,
		GroupedActions:      groups,
		SyncIntervalMinutes: syncInterval,
		MaintenanceWindow:   resolvedWindow,
		// CA-signed LPS sealing key. nil when the keypair is not configured
		// on this instance — the agent then has no key to seal to and refuses
		// to rotate (fail closed), rather than rotating and sending cleartext.
		LpsPublicKey: h.lpsPublicKey,
	}), nil
}

func windowEntryCount(w *pm.MaintenanceWindow) int {
	if w == nil {
		return 0
	}
	return len(w.GetSchedule())
}

// dbActionToWireAction converts a raw actions_projection row to wire
// format. Mirrors dbResolvedActionToWireAction but operates on the
// projection row directly so the tree resolver doesn't have to detour
// through the per-action mode-collapse query for every member action.
//
// SYNC-path device-bound signing (WS1 SERVER): the PUSH/dispatch rewrite
// stopped create-time signing, so the autonomous SYNC path re-signs each
// action at DELIVERY, bound to the SYNCING DEVICE. The built Action carries
// signed_envelope (the deterministic bytes the agent verifies + executes)
// and signature (the CA signature over those exact bytes). The typed-params
// oneof + schedule stay populated as advisory metadata for the offline
// scheduler — the agent executes the VERIFIED envelope, not the advisory
// fields, so the signed envelope is the source of truth.
//
// effectiveDesiredState lets the caller fold the container-mode override
// (UNINSTALL → ABSENT) INTO the signed envelope rather than only the
// advisory wire field. The agent honours UNINSTALL only if it rides in the
// signed bytes it executes — flipping the wire field alone would be a no-op
// the verifier never sees.
//
// executionID = a.ID: synced actions have no execution id yet (the agent
// mints the execution when it runs the action offline), so the action's own
// id binds the envelope. This mirrors the dispatch path, where the freshly
// minted execution id binds the envelope.
func dbActionToWireAction(a db.ActionsProjection, signer ca.ActionSigner, deviceID string, effectiveDesiredState int32) (*pm.Action, error) {
	action := &pm.Action{
		Id:             &pm.ActionId{Value: a.ID},
		Type:           pm.ActionType(a.ActionType),
		DesiredState:   pm.DesiredState(effectiveDesiredState),
		TimeoutSeconds: a.TimeoutSeconds,
	}
	if len(a.Params) > 0 {
		if err := actionparams.PopulateAction(action, a.ActionType, a.Params); err != nil {
			return nil, err
		}
	}
	if len(a.Schedule) > 0 {
		action.Schedule = actionparams.ScheduleFromJSON(a.Schedule)
	}

	envelopeBytes, signature, err := actionparams.BuildAndSignEnvelope(
		signer,
		a.ID,
		a.ActionType,
		a.Params,
		effectiveDesiredState,
		a.TimeoutSeconds,
		action.Schedule,
		deviceID,
	)
	if err != nil {
		return nil, err
	}
	action.SignedEnvelope = envelopeBytes
	action.Signature = signature
	return action, nil
}

// ProxyValidateLuksToken validates and consumes a one-time LUKS token.
func (h *InternalHandler) ProxyValidateLuksToken(ctx context.Context, req *connect.Request[pm.InternalValidateLuksTokenRequest]) (*connect.Response[pm.ValidateLuksTokenResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	if req.Msg.DeviceId == "" || req.Msg.Token == "" {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "device_id and token are required")
	}
	if err := h.verifyDeviceGatewayBinding(ctx, req.Msg.DeviceId, req.Msg.GatewayId); err != nil {
		return nil, err
	}

	// WS10 #3: tokens are stored hashed — hash the presented plaintext
	// before lookup so the at-rest column never holds a usable token.
	token, err := h.store.Repos().Luks.ConsumeToken(ctx, store.ConsumeLuksTokenParams{Token: hashLuksToken(req.Msg.Token), DeviceID: req.Msg.DeviceId})
	if err != nil {
		h.logger.Warn("LUKS token validation failed", "device_id", req.Msg.DeviceId, "error", err)
		return nil, apiErrorCtx(ctx, ErrTokenNotFound, connect.CodeNotFound, "token is invalid or has expired")
	}

	devicePath := ""
	key, err := h.store.Repos().Luks.GetCurrentForAction(ctx, store.LuksKeyByActionKey{DeviceID: req.Msg.DeviceId, ActionID: token.ActionID})
	if err == nil {
		devicePath = key.DevicePath
	} else {
		logEnrichmentErr("GetCurrentLuksKeyForAction", "device_id", req.Msg.DeviceId, err)
	}

	return connect.NewResponse(&pm.ValidateLuksTokenResponse{
		ActionId:   token.ActionID,
		DevicePath: devicePath,
		MinLength:  token.MinLength,
		Complexity: pm.LpsPasswordComplexity(token.Complexity),
	}), nil
}

// ProxyGetLuksKey retrieves and decrypts the current LUKS key for a device+action.
func (h *InternalHandler) ProxyGetLuksKey(ctx context.Context, req *connect.Request[pm.InternalGetLuksKeyRequest]) (*connect.Response[pm.GetLuksKeyResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	if req.Msg.DeviceId == "" || req.Msg.ActionId == "" {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "device_id and action_id are required")
	}
	if err := h.verifyDeviceGatewayBinding(ctx, req.Msg.DeviceId, req.Msg.GatewayId); err != nil {
		return nil, err
	}

	key, err := h.store.Repos().Luks.GetCurrentForAction(ctx, store.LuksKeyByActionKey{DeviceID: req.Msg.DeviceId, ActionID: req.Msg.ActionId})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrLuksKeyNotFound, connect.CodeNotFound, "no LUKS key found for this action")
	}

	passphrase, err := h.encryptor.DecryptWithContext(key.Passphrase, crypto.SecretAAD(req.Msg.DeviceId, req.Msg.ActionId, "luks"))
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to decrypt passphrase")
	}

	return connect.NewResponse(&pm.GetLuksKeyResponse{
		Passphrase: passphrase,
	}), nil
}

// ProxyStoreLuksKey encrypts and stores a new LUKS key.
func (h *InternalHandler) ProxyStoreLuksKey(ctx context.Context, req *connect.Request[pm.InternalStoreLuksKeyRequest]) (*connect.Response[pm.StoreLuksKeyResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	if req.Msg.DeviceId == "" || req.Msg.ActionId == "" || len(req.Msg.SealedPassphrase) == 0 {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "device_id, action_id, and sealed_passphrase are required")
	}
	if err := h.verifyDeviceGatewayBinding(ctx, req.Msg.DeviceId, req.Msg.GatewayId); err != nil {
		return nil, err
	}

	// Unsealing requires the control private key (the same keypair LPS
	// sealing uses). A nil key is a wiring/config failure: fail closed
	// rather than accept bytes we cannot open — there is no cleartext
	// fallback path (spec 25).
	if h.lpsPrivateKey == nil {
		h.logger.Error("LUKS store: nil private key — keypair not configured", "device_id", req.Msg.DeviceId)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "control keypair not configured")
	}

	// Unseal under the reconstructed device|action|"luks" AAD (spec 25). A
	// failure — tampered, wrong key, wrong context, or a blob sealed under
	// the LPS domain — is permanent, so reject with InvalidArgument: no
	// event appended, and the caller does not retry a blob that can never
	// open. Neither the blob nor any plaintext appears in logs.
	plaintext, err := sdkcrypto.OpenLuksPassphrase(h.lpsPrivateKey, req.Msg.SealedPassphrase, req.Msg.DeviceId, req.Msg.ActionId)
	if err != nil {
		h.logger.Error("failed to unseal LUKS passphrase", "error", err, "device_id", req.Msg.DeviceId, "action_id", req.Msg.ActionId)
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "failed to unseal passphrase")
	}

	encPassphrase, err := h.encryptor.EncryptWithContext(plaintext, crypto.SecretAAD(req.Msg.DeviceId, req.Msg.ActionId, "luks"))
	if err != nil {
		h.logger.Error("failed to encrypt LUKS passphrase", "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to encrypt passphrase")
	}

	luksStreamID := ulid.Make().String()
	if err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "luks_key",
		StreamID:   luksStreamID,
		EventType:  string(eventtypes.LuksKeyRotated),
		Data: payloads.LuksKeyRotated{
			DeviceID:       req.Msg.DeviceId,
			ActionID:       req.Msg.ActionId,
			DevicePath:     req.Msg.DevicePath,
			Passphrase:     encPassphrase,
			RotatedAt:      h.now().UTC(),
			RotationReason: rotationReasonToString(req.Msg.RotationReason),
		},
		ActorType: "device",
		ActorID:   req.Msg.DeviceId,
	}); err != nil {
		h.logger.Error("failed to store LUKS key event", "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to store LUKS key")
	}

	return connect.NewResponse(&pm.StoreLuksKeyResponse{
		Success: true,
	}), nil
}

// ProxyStoreLpsPasswords encrypts and stores LPS password rotation entries.
func (h *InternalHandler) ProxyStoreLpsPasswords(ctx context.Context, req *connect.Request[pm.InternalStoreLpsPasswordsRequest]) (*connect.Response[pm.InternalStoreLpsPasswordsResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	if req.Msg.DeviceId == "" || req.Msg.ActionId == "" {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "device_id and action_id are required")
	}
	if err := h.verifyDeviceGatewayBinding(ctx, req.Msg.DeviceId, req.Msg.GatewayId); err != nil {
		return nil, err
	}

	// Unsealing requires the LPS private key. A nil key is a wiring/config
	// failure (EnsureLpsKeypair not run): fail closed rather than accept
	// passwords we cannot open — the agent should not have sealed to a key we
	// don't hold, and we must never fall back to a cleartext path.
	if h.lpsPrivateKey == nil {
		h.logger.Error("LPS store: nil private key — keypair not configured", "device_id", req.Msg.DeviceId)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "lps keypair not configured")
	}

	// Two phases so a bad entry never leaves a partial batch. Phase 1 unseals,
	// re-encrypts, and parses EVERY rotation before a single event is appended:
	// an unseal failure (tampered, wrong key, or context mismatch) is permanent
	// for the batch, so reject with InvalidArgument — no event appended, and the
	// inbox does not retry a blob that can never open. Only after the whole
	// batch is known persistable does phase 2 append. The blob and plaintext
	// never appear in logs; device_id + action_id locate the failure.
	staged := make([]payloads.LpsPasswordRotated, 0, len(req.Msg.Rotations))
	for _, r := range req.Msg.Rotations {
		plaintext, err := sdkcrypto.OpenLpsPassword(h.lpsPrivateKey, r.SealedPassword, req.Msg.DeviceId, req.Msg.ActionId, r.Username)
		if err != nil {
			h.logger.Error("failed to unseal LPS password", "error", err, "device_id", req.Msg.DeviceId, "action_id", req.Msg.ActionId)
			return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "failed to unseal password")
		}

		encPassword, err := h.encryptor.EncryptWithContext(plaintext, crypto.SecretAAD(req.Msg.DeviceId, req.Msg.ActionId, "lps"))
		if err != nil {
			h.logger.Error("failed to encrypt LPS password", "error", err, "device_id", req.Msg.DeviceId, "action_id", req.Msg.ActionId)
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to encrypt password")
		}

		// r.RotatedAt rides the wire as an RFC 3339 string in the
		// proto LpsPasswordRotation; parse it back to time.Time so
		// the typed payload matches the projector decoder shape.
		// Fall back to "now" if the agent shipped an unparseable
		// timestamp — the projector requires a non-zero rotated_at.
		rotatedAt, err := time.Parse(time.RFC3339Nano, r.RotatedAt)
		if err != nil {
			if rotatedAt, err = time.Parse(time.RFC3339, r.RotatedAt); err != nil {
				h.logger.Warn("LpsPasswordRotation rotated_at unparseable; falling back to now",
					"raw", r.RotatedAt, "error", err)
				rotatedAt = h.now().UTC()
			}
		}
		staged = append(staged, payloads.LpsPasswordRotated{
			DeviceID:       req.Msg.DeviceId,
			ActionID:       req.Msg.ActionId,
			Username:       r.Username,
			Password:       encPassword,
			RotatedAt:      rotatedAt,
			RotationReason: rotationReasonToString(r.Reason),
		})
	}

	// Phase 2: append the fully-staged batch. Persistence MUST fail-closed. LPS
	// rotation is irreversible: the agent has already run chpasswd locally, so
	// the old password is gone. If the server silently fails to persist the new
	// one, the user loses the only copy LPS was meant to retain — and the
	// gateway's post-RPC cleanup in agent.go clears the lps.rotations metadata
	// the moment this RPC returns success, so there is no second chance. Return
	// an error on any append failure so the gateway leaves the metadata in place
	// and the inbox retry replays the batch.
	var (
		persisted int
		firstErr  error
	)
	for _, payload := range staged {
		lpsStreamID := ulid.Make().String()
		if err := h.store.AppendEvent(ctx, store.Event{
			StreamType: "lps_password",
			StreamID:   lpsStreamID,
			EventType:  string(eventtypes.LpsPasswordRotated),
			Data:       payload,
			ActorType:  "device",
			ActorID:    req.Msg.DeviceId,
		}); err != nil {
			h.logger.Error("failed to append LpsPasswordRotated event",
				"device_id", req.Msg.DeviceId,
				"action_id", req.Msg.ActionId,
				"persisted_before_failure", persisted,
				"total_rotations", len(staged),
				"error", err,
			)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		persisted++
	}
	if firstErr != nil {
		// Partial success is indistinguishable from full failure
		// from the agent's perspective: the gateway will leave the
		// execution-result metadata alone and the inbox task will
		// retry. The retry will re-attempt the full rotation list.
		// Already-persisted rotations will append a second event
		// with the same (device_id, username, password) payload —
		// not ideal, but harmless: the projection deduplicates by
		// (device_id, username) and keeps the most recent, and the
		// event stream is an append-only audit record where a
		// duplicate tells the truth ("we saw this twice during a
		// retry") rather than lying.
		//
		// Route through apiErrorCtx so the response carries the
		// same `internal_error` ErrorDetail code the rest of the
		// handlers emit — the agent's inbox retry loop keys off
		// that code to decide whether to retry.
		h.logger.Error("LPS rotation persistence failed, returning error to trigger inbox retry",
			"device_id", req.Msg.DeviceId,
			"action_id", req.Msg.ActionId,
			"persisted", persisted,
			"total_rotations", len(staged),
			"first_error", firstErr,
		)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal,
			fmt.Sprintf("failed to persist %d of %d LPS rotations",
				len(staged)-persisted, len(staged)))
	}

	return connect.NewResponse(&pm.InternalStoreLpsPasswordsResponse{}), nil
}

// ProxyValidateTerminalToken validates the bearer token a web client
// presents when opening the gateway's WebSocket terminal endpoint and
// returns the session metadata the gateway needs to bridge the
// connection.
//
// rc10 single-use contract: a successful validation CONSUMES the
// token atomically (Valkey GETDEL), so a second call with the same
// bearer returns Unauthenticated. This blocks the replay surface
// where a token leaks via a reverse-proxy access log that captured
// the query-string — the attacker can no longer mint additional
// WebSocket connections during the 60 s TTL.
//
// Real flow only validates once per WS: the gateway calls this RPC
// from terminal_bridge.go at connection acceptance, stashes the
// returned metadata for the WebSocket's lifetime, and never re-
// validates. So the single-use contract is consistent with normal
// operation; only attacker replays break.
//
// Forgery attempts (valid session_id, wrong bearer) do NOT consume
// the entry — the terminal store restores the session with its
// remaining TTL so a legitimate client isn't locked out by a guess.
//
// Distinguishes 'unknown / expired / already consumed' (Unauthenticated,
// with a generic message so a forgery probe cannot tell the
// difference) from 'mismatched token' (Unauthenticated, but logged
// separately so the audit pipeline can flag forgery attempts). 'Token
// store not configured' is Unavailable — operator misconfiguration,
// not a client bug.
func (h *InternalHandler) ProxyValidateTerminalToken(ctx context.Context, req *connect.Request[pm.InternalValidateTerminalTokenRequest]) (*connect.Response[pm.InternalValidateTerminalTokenResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	if h.terminalTokenStore == nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeUnavailable,
			"remote terminal sessions are not configured on this control instance")
	}

	sessionID := req.Msg.SessionId
	bearer := req.Msg.Token
	if sessionID == "" || bearer == "" {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument,
			"session_id and token are required")
	}

	session, err := h.terminalTokenStore.Validate(ctx, sessionID, bearer)
	if err != nil {
		// Map the two possible store errors to the same gRPC code so a
		// forgery probe cannot tell expired from mismatched, but log
		// them differently so operators can spot active attacks.
		switch {
		case errors.Is(err, terminal.ErrTokenMismatch):
			h.logger.Warn("terminal token mismatch (possible forgery attempt)",
				"session_id", sessionID)
		case errors.Is(err, terminal.ErrTokenNotFound):
			h.logger.Debug("terminal token unknown or expired",
				"session_id", sessionID)
		default:
			h.logger.Error("terminal token validation failed",
				"session_id", sessionID, "error", err)
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal,
				"failed to validate session token")
		}
		return nil, apiErrorCtx(ctx, ErrTokenNotFound, connect.CodeUnauthenticated,
			"invalid or expired session token")
	}

	h.logger.Debug("terminal token validated",
		"session_id", sessionID,
		"user_id", session.UserID,
		"device_id", session.DeviceID,
	)
	return connect.NewResponse(&pm.InternalValidateTerminalTokenResponse{
		UserId:   session.UserID,
		DeviceId: session.DeviceID,
		TtyUser:  session.TtyUser,
		Cols:     session.Cols,
		Rows:     session.Rows,
	}), nil
}

// dbResolvedActionToWireAction converts a resolved action row to wire format.
// Note: This is also defined in handler/agent.go — when the gateway migration
// is complete, only this version will remain.
//
// SYNC-path device-bound signing: like dbActionToWireAction, the delivered
// Action carries a freshly signed, device-bound SignedActionEnvelope so the
// offline agent can verify it. The flat resolver already collapsed this row
// to its effective desired_state, so a.DesiredState is what we sign — there
// is no separate container override to fold here.
func dbResolvedActionToWireAction(a db.ListResolvedActionsForDeviceRow, signer ca.ActionSigner, deviceID string) (*pm.Action, error) {
	action := &pm.Action{
		Id:             &pm.ActionId{Value: a.ID},
		Type:           pm.ActionType(a.ActionType),
		DesiredState:   pm.DesiredState(a.DesiredState),
		TimeoutSeconds: a.TimeoutSeconds,
	}

	if len(a.Params) > 0 {
		if err := actionparams.PopulateAction(action, a.ActionType, a.Params); err != nil {
			return nil, err
		}
	}

	if len(a.Schedule) > 0 {
		action.Schedule = actionparams.ScheduleFromJSON(a.Schedule)
	}

	envelopeBytes, signature, err := actionparams.BuildAndSignEnvelope(
		signer,
		a.ID,
		a.ActionType,
		a.Params,
		a.DesiredState,
		a.TimeoutSeconds,
		action.Schedule,
		deviceID,
	)
	if err != nil {
		return nil, err
	}
	action.SignedEnvelope = envelopeBytes
	action.Signature = signature

	return action, nil
}

// rotationReasonToString converts the wire enum into the lowercase
// string the events table and projection columns have always stored
// ("initial" / "scheduled"). Mirrors the PR-A/B boundary-helper
// pattern: keep the JSONB shape stable for backward replay while
// callers move to the typed enum on the wire. UNSPECIFIED maps to the
// empty string so the projector defaulting logic
// (LpsPasswordRotatedFromEvent and LuksKeyRotatedFromEvent) sees the
// same shape an older agent would have produced.
//
// No FromString counterpart is exported here because nothing in the
// api package currently lifts a stored rotation reason back onto the
// wire — the surface is write-only at this boundary. The gateway's
// agent-side mirror (rotationReasonFromAgentString in
// internal/handler/agent.go) covers the other direction at the only
// site that needs it.
func rotationReasonToString(r pm.RotationReason) string {
	switch r {
	case pm.RotationReason_ROTATION_REASON_INITIAL:
		return "initial"
	case pm.RotationReason_ROTATION_REASON_SCHEDULED:
		return "scheduled"
	case pm.RotationReason_ROTATION_REASON_AUTH_GRACE:
		return "auth_grace"
	default:
		return ""
	}
}

// rotationReasonFromString is the inverse of rotationReasonToString.
// Used by read paths that decode the string-typed `rotation_reason`
// column from the lps/luks projections back into the wire enum.
// Unknown values (including the empty string from older rows that
// pre-date the enum migration) collapse to UNSPECIFIED.
func rotationReasonFromString(s string) pm.RotationReason {
	switch s {
	case "initial":
		return pm.RotationReason_ROTATION_REASON_INITIAL
	case "scheduled":
		return pm.RotationReason_ROTATION_REASON_SCHEDULED
	case "auth_grace":
		return pm.RotationReason_ROTATION_REASON_AUTH_GRACE
	default:
		return pm.RotationReason_ROTATION_REASON_UNSPECIFIED
	}
}

// luksRevocationStatusFromString decodes the string-typed
// `revocation_status` column from the luks_keys_projection back into
// the wire enum. Unknown values collapse to UNSPECIFIED.
func luksRevocationStatusFromString(s string) pm.LuksRevocationStatus {
	switch s {
	case "none":
		return pm.LuksRevocationStatus_LUKS_REVOCATION_STATUS_NONE
	case "dispatched":
		return pm.LuksRevocationStatus_LUKS_REVOCATION_STATUS_DISPATCHED
	case "success":
		return pm.LuksRevocationStatus_LUKS_REVOCATION_STATUS_SUCCESS
	case "failed":
		return pm.LuksRevocationStatus_LUKS_REVOCATION_STATUS_FAILED
	default:
		return pm.LuksRevocationStatus_LUKS_REVOCATION_STATUS_UNSPECIFIED
	}
}
