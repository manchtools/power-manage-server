package doctor

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/store"
)

func TestErasureProvisioningCheck_CleanIsOK(t *testing.T) {
	env := testEnv(nil)
	env.DB = fakeDB{} // no orphans
	fs := run1(t, ErasureProvisioningCheck{}, env)
	assert.Equal(t, SeverityOK, worst(fs), "no erased user retains a live account")
}

func TestErasureProvisioningCheck_LiveActionIsCritical(t *testing.T) {
	env := testEnv(nil)
	env.DB = fakeDB{orphans: []store.ErasedProvisioning{
		{UserID: "erased-1", SystemUserActionID: "act-1"},
	}}
	fs := run1(t, ErasureProvisioningCheck{}, env)
	require.Equal(t, SeverityCritical, worst(fs))
	txt := findingText(fs)
	assert.Contains(t, txt, "live PRESENT system USER action",
		"AC 36: a lingering PRESENT system USER action is the flagged gap")
	assert.Contains(t, txt, "persists on devices", "and the finding names the real exposure")
}

func TestErasureProvisioningCheck_DBDownSkips(t *testing.T) {
	env := testEnv(nil) // DB nil → dbReady returns a skip, not a false pass
	fs := run1(t, ErasureProvisioningCheck{}, env)
	assert.NotEqual(t, SeverityCritical, worst(fs), "a down DB skips rather than false-flags")
}
