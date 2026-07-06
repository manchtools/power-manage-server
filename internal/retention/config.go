package retention

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/manchtools/power-manage/server/internal/archive"
)

// EnvConfig is the operator-facing retention configuration, sourced from
// the CONTROL_RETENTION_* environment variables (spec 19 D2 — env-only by
// decision, no RPC/UI surface):
//
//	CONTROL_RETENTION_ENABLED         "true"/"1" to activate the prune worker
//	CONTROL_RETENTION_WINDOW          Go duration, e.g. "2160h" (90 days)
//	CONTROL_RETENTION_ARCHIVE_BACKEND "filesystem" (the only v1 backend)
//	CONTROL_RETENTION_ARCHIVE_PATH    absolute directory for sealed archives
//	CONTROL_RETENTION_INTERVAL        how often the prune ticks (default 1h)
//
// Validate is shared by the control boot path (fatal on violation — a
// destructive feature must never run on a half-read config) and the
// doctor's posture check (reports the same violations as findings).
type EnvConfig struct {
	Enabled     bool
	Window      time.Duration
	Backend     string
	ArchivePath string
	Interval    time.Duration
}

// MinWindow is the smallest permitted retention window. Deliberately
// validated (fatal), not clamped: silently stretching an operator's typo
// ("90m" meant "90 days") into a different retention period would prune
// history they intended to keep. The worker's own pruneSafetyMargin (1h)
// is a last-resort floor, not a substitute for a sane window.
const MinWindow = 24 * time.Hour

// MinInterval is the smallest permitted tick interval. Validated here —
// not only clamped at boot — because config.ClampInterval preserves a
// zero value ("0 means disabled" convention), but retention has an
// explicit Enabled flag, so an enabled config with Interval <= 0 is
// simply invalid and would panic time.NewTicker at runtime. The boot
// clamp additionally raises anything below 10m.
const MinInterval = time.Minute

// Validate returns the first configuration violation, or nil. A disabled
// config is always valid — the other variables are simply unused.
func (c EnvConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.Window < MinWindow {
		return fmt.Errorf("retention: CONTROL_RETENTION_WINDOW must be at least %s when retention is enabled (got %s); use a Go duration, e.g. \"2160h\" for 90 days", MinWindow, c.Window)
	}
	if c.Interval < MinInterval {
		return fmt.Errorf("retention: CONTROL_RETENTION_INTERVAL must be at least %s when retention is enabled (got %s)", MinInterval, c.Interval)
	}
	if archive.Backend(c.Backend) != archive.BackendFilesystem {
		return fmt.Errorf("retention: CONTROL_RETENTION_ARCHIVE_BACKEND %q is not supported; the only backend is %q", c.Backend, archive.BackendFilesystem)
	}
	if c.ArchivePath == "" {
		return fmt.Errorf("retention: CONTROL_RETENTION_ARCHIVE_PATH is required when retention is enabled — the sealed archives are the ONLY copy of pruned history")
	}
	if !filepath.IsAbs(c.ArchivePath) {
		return fmt.Errorf("retention: CONTROL_RETENTION_ARCHIVE_PATH must be absolute (got %q) — a relative path silently depends on the process working directory", c.ArchivePath)
	}
	return nil
}

// ArchiveConfig maps the validated env config onto the archive
// constructor's config.
func (c EnvConfig) ArchiveConfig() archive.Config {
	return archive.Config{Backend: archive.Backend(c.Backend), FilesystemPath: c.ArchivePath}
}
