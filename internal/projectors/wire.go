package projectors

import (
	"log/slog"

	"github.com/manchtools/power-manage/server/internal/store"
)

// WireAll registers every Go-side projector listener against the
// store's post-commit listener pipeline. Single source of truth for
// projector wiring so production boot (cmd/control/main.go) and
// tests (internal/testutil.SetupPostgres) get identical projector
// coverage. A new projector port adds itself here once and both
// sides pick it up.
//
// Listeners fire synchronously inside Store.AppendEvent — by the
// time AppendEvent returns to the handler, every listener's writes
// have landed. So read-your-writes works the same as the deleted
// PL/pgSQL triggers from the caller's perspective; the only
// behavioural delta is that the listener writes are not atomic with
// the event commit (separate autocommit per listener call). That
// matters only when multiple consecutive events would corrupt state
// on partial-failure mid-listener; the periodic indexer reconciler
// is the safety net for any drift.
//
// Refs tracker #107.
func WireAll(st *store.Store, logger *slog.Logger) {
	if st == nil {
		return
	}
	st.RegisterEventListener(SecurityAlertListener(
		st,
		loggerFor(logger, "security_alert_projector"),
	))
	st.RegisterEventListener(TotpListener(
		st,
		loggerFor(logger, "totp_projector"),
	))
	st.RegisterEventListener(LpsPasswordListener(
		st,
		loggerFor(logger, "lps_password_projector"),
	))
	st.RegisterEventListener(LuksKeyListener(
		st,
		loggerFor(logger, "luks_key_projector"),
	))
	st.RegisterEventListener(ServerSettingsListener(
		st,
		loggerFor(logger, "server_settings_projector"),
	))
	// Subsequent ports under #101–#106 add their listener here.
}

// loggerFor returns a sub-logger tagged with the projector
// component name, or a discard logger when the parent is nil so
// tests that pass nil don't panic.
func loggerFor(parent *slog.Logger, component string) *slog.Logger {
	if parent == nil {
		return slog.Default()
	}
	return parent.With("component", component)
}
