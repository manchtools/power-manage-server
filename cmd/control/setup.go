// Boot-time setup helpers extracted from main.go (audit F043 / #157,
// slice 3). The encryptor init, SSH-access seed, and system-action
// wiring previously inlined ~80 LOC of boot wiring in main(); the
// helpers here own that wiring so main() reads as "build → wire →
// listen" rather than "build + 12 inline conditionals + wire + listen".
package main

import (
	"context"
	"errors"
	"log/slog"
	"os"

	"github.com/oklog/ulid/v2"

	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/projectors"
	"github.com/manchtools/power-manage/server/internal/store"
)

// bootstrapAllDevicesGroup emits the seed DeviceGroupCreated event
// for the "All Devices" dynamic group on a fresh deployment. Previously
// done in PL/pgSQL inside migration 008 via a DO block + generate_ulid()
// function (#242 Wave H); moved into Go bootstrap so a future non-Postgres
// backend doesn't need a dialect-specific seed.
//
// Must run AFTER projectors.WireAll so the event flows through the
// registered DeviceGroup listener and materialises the projection row.
// Idempotent — early-returns when the group already exists. Errors are
// logged (not returned) because this is a best-effort boot convenience
// matching seedSSHAccessForAll.
func bootstrapAllDevicesGroup(ctx context.Context, st *store.Store, logger *slog.Logger) {
	_, err := st.Repos().DeviceGroup.GetByName(ctx, "All Devices")
	if err == nil {
		return // already present
	}
	if !store.IsNotFound(err) {
		logger.Error("bootstrap: All Devices group lookup failed", "error", err)
		return
	}
	id := ulid.Make().String()
	if err := st.AppendEvent(ctx, store.Event{
		StreamType: "device_group",
		StreamID:   id,
		EventType:  string(eventtypes.DeviceGroupCreated),
		Data: payloads.DeviceGroupCreated{
			Name:         "All Devices",
			Description:  "Dynamic group that matches all registered devices",
			IsDynamic:    true,
			DynamicQuery: "",
		},
		ActorType: "system",
		ActorID:   "bootstrap",
	}); err != nil {
		logger.Error("bootstrap: failed to emit DeviceGroupCreated for All Devices", "error", err)
		return
	}
	logger.Info("bootstrap: emitted DeviceGroupCreated for All Devices", "group_id", id)
}

// errEncryptionKeyRequired is the boot-time fatal returned when
// CONTROL_ENCRYPTION_KEY is unset. The error type is the only signal
// main() needs to log+exit.
var errEncryptionKeyRequired = errors.New("CONTROL_ENCRYPTION_KEY is required (32-byte key; generate one with `openssl rand -hex 32`)")

// initEncryptor reads CONTROL_ENCRYPTION_KEY from the environment and returns
// the constructed Encryptor.
//
// The encryption key is MANDATORY — there is NO plaintext opt-out (WS11 #4: the
// former CONTROL_ENCRYPTION_KEY_REQUIRED=false escape was removed so no
// deployment, not even by accident, can store IdP client secrets, TOTP secrets,
// LUKS keys, or LPS passwords unencrypted at rest).
//
// Returns (nil, errEncryptionKeyRequired) when the key is unset — main() must
// log+exit. Returns (nil, err) for malformed-key errors from
// crypto.NewEncryptor (surfaced as-is so an operator sees a typo'd key rather
// than mistaking it for a missing one). On success returns the encryptor.
func initEncryptor(_ *slog.Logger) (*crypto.Encryptor, error) {
	enc, err := crypto.NewEncryptor(os.Getenv("CONTROL_ENCRYPTION_KEY"))
	if err != nil {
		return nil, err
	}
	if enc == nil {
		return nil, errEncryptionKeyRequired
	}
	return enc, nil
}

// seedSSHAccessForAll honours the CONTROL_SSH_ACCESS_FOR_ALL env-var
// by emitting a one-shot ServerSettingUpdated event when the DB value
// is still false. Idempotent across boots — the second-and-subsequent
// runs early-return because GetServerSettings reports the seed already
// happened.
//
// Errors are logged (not returned) because this is a best-effort
// boot-time convenience for fresh deploys; a stuck seed shouldn't
// block the server from starting.
func seedSSHAccessForAll(ctx context.Context, st *store.Store, logger *slog.Logger) {
	v := os.Getenv("CONTROL_SSH_ACCESS_FOR_ALL")
	if v != "true" && v != "1" {
		return
	}
	settings, err := st.Queries().GetServerSettings(ctx)
	if err != nil || settings.SshAccessForAll {
		return
	}
	provisioning := settings.UserProvisioningEnabled
	sshAll := true
	if err := st.AppendEvent(ctx, store.Event{
		StreamType: "server_settings",
		StreamID:   "global",
		EventType:  string(eventtypes.ServerSettingUpdated),
		Data: payloads.ServerSettingUpdated{
			UserProvisioningEnabled: &provisioning,
			SshAccessForAll:         &sshAll,
		},
		ActorType: "system",
		ActorID:   "system",
	}); err != nil {
		logger.Error("failed to seed SSH access for all from env var", "error", err)
		return
	}
	logger.Info("seeded SSH access for all from CONTROL_SSH_ACCESS_FOR_ALL env var")
}

// wireSystemActions runs the three-step system-action setup:
// (1) projectors.WireAll registers every Go-side projector listener,
// (2) one-shot startup sweep for idempotent convergence, and
// (3) post-commit listener + periodic reconciler durability safety net.
//
// projectors.WireAll runs unconditionally so a deployment without
// system actions still gets every other projector registered. The
// system-action triplet runs only when svc.SystemActions() is non-nil
// (cfg-disabled deploys skip it).
func wireSystemActions(ctx context.Context, st *store.Store, svc *api.ControlService, cfg *Config, logger *slog.Logger) {
	projectors.WireAll(st, logger)

	if svc.SystemActions() == nil {
		return
	}

	// (0) Bootstrap the two global TerminalAdmin AdminPolicy actions
	// (#70). Idempotent — creates the rows on a fresh DB, no-ops on a
	// DB that already has them. Runs before the user-level sync so the
	// reconciler (started in step 3 below) finds the action rows to
	// update on its first tick.
	if err := svc.SystemActions().BootstrapGlobalTerminalAdminActions(ctx); err != nil {
		logger.Error("failed to bootstrap global TerminalAdmin actions at startup", "error", err)
	}

	// (1) Startup sweep — keeps the existing Info line so operators
	// see the one-shot convergence in boot logs.
	if err := svc.SystemActions().SyncAllUsersSystemActions(ctx); err != nil {
		logger.Error("failed to sync system actions at startup", "error", err)
	} else {
		logger.Info("system actions synced for all users (startup)")
	}

	// (2) Listener — registered post-commit on the store. Logged
	// errors are swallowed; the periodic reconciler is the
	// durability safety net. Reuse the same per-sweep timeout as
	// the reconciler so a wedged DB / signer can't leak a
	// goroutine indefinitely (#77 review round 2).
	st.RegisterEventListener(api.SystemActionListener(
		svc.SystemActions(),
		logger.With("component", "system_action_listener"),
		cfg.SystemActionReconcileTimeout,
	))

	// (3) Periodic reconciler — interval and per-sweep timeout from
	// config (defaults set in parseFlags).
	svc.SystemActions().StartReconciliation(ctx,
		cfg.SystemActionReconcileInterval,
		cfg.SystemActionReconcileTimeout)
	logger.Info("system-action reconciliation started",
		"interval", cfg.SystemActionReconcileInterval,
		"sweep_timeout", cfg.SystemActionReconcileTimeout)
}

// configureTrustedProxies pushes the operator's trusted-proxy CIDR
// list into the auth package's package-global allowlist used by the
// X-Forwarded-For validator. No-op when the list is empty (the
// validator falls back to RemoteAddr in that case).
func configureTrustedProxies(cfg *Config, logger *slog.Logger) {
	if len(cfg.TrustedProxies) == 0 {
		return
	}
	auth.SetTrustedProxies(cfg.TrustedProxies)
	logger.Info("trusted proxies configured", "proxies", cfg.TrustedProxies)
}
