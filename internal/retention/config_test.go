package retention

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validEnvConfig() EnvConfig {
	return EnvConfig{
		Enabled:     true,
		Window:      90 * 24 * time.Hour,
		Backend:     "filesystem",
		ArchivePath: "/var/lib/power-manage/archive",
		Interval:    time.Hour,
	}
}

func TestEnvConfig_ValidIsAccepted(t *testing.T) {
	require.NoError(t, validEnvConfig().Validate())
}

func TestEnvConfig_DisabledSkipsAllChecks(t *testing.T) {
	// Disabled means the rest is unused — even a fully-zero config is valid.
	require.NoError(t, EnvConfig{}.Validate())
}

// Correct / absent / wrong per field (enabled configs only).

func TestEnvConfig_WindowBelowFloorRejected(t *testing.T) {
	c := validEnvConfig()
	c.Window = 90 * time.Minute // the "90m meant 90 days" typo
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CONTROL_RETENTION_WINDOW")

	c.Window = 0 // absent
	require.Error(t, c.Validate())
}

func TestEnvConfig_IntervalBelowFloorRejected(t *testing.T) {
	c := validEnvConfig()
	c.Interval = 0 // absent — ClampInterval's "0 disables" must not slip through here
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CONTROL_RETENTION_INTERVAL")

	c.Interval = time.Second // wrong: below the floor
	require.Error(t, c.Validate())
}

func TestEnvConfig_UnknownBackendRejected(t *testing.T) {
	c := validEnvConfig()
	c.Backend = "s3" // not in v1
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not supported")

	c.Backend = "" // absent
	require.Error(t, c.Validate())
}

func TestEnvConfig_ArchivePathRequiredAndAbsolute(t *testing.T) {
	c := validEnvConfig()
	c.ArchivePath = "" // absent
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ONLY copy of pruned history")

	c.ArchivePath = "archives/here" // wrong: relative
	err = c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "absolute")
}

func TestEnvConfig_ArchiveConfigMapsToFilesystem(t *testing.T) {
	ac := validEnvConfig().ArchiveConfig()
	assert.Equal(t, "filesystem", string(ac.Backend))
	assert.Equal(t, "/var/lib/power-manage/archive", ac.FilesystemPath)
}
