package doctor

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/store"
)

// testKEK is a fixed 32-byte (64 hex) key for the unwrap-probe tests.
const testKEK = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

func kekEnv(t *testing.T, db DBProbe) *Env {
	t.Helper()
	env := testEnv(map[string]string{"CONTROL_ENCRYPTION_KEY": testKEK})
	env.DB = db
	return env
}

func TestDEKInvariantCheck_HealthyIsOK(t *testing.T) {
	kek, err := crypto.NewEncryptor(testKEK)
	require.NoError(t, err)
	good1, err := crypto.GenerateWrappedDEK(kek, "user-1")
	require.NoError(t, err)
	good2, err := crypto.GenerateWrappedDEK(kek, "user-2")
	require.NoError(t, err)

	env := kekEnv(t, fakeDB{liveDEKs: []store.UserDEK{
		{UserID: "user-1", Wrapped: good1},
		{UserID: "user-2", Wrapped: good2},
	}})
	fs := run1(t, DEKInvariantCheck{}, env)
	assert.Equal(t, SeverityOK, worst(fs), "all DEKs unwrap and none are resurrected")
}

func TestDEKInvariantCheck_MissingDEKIsCritical(t *testing.T) {
	env := kekEnv(t, fakeDB{liveDEKs: []store.UserDEK{{UserID: "user-nokey", Wrapped: ""}}})
	fs := run1(t, DEKInvariantCheck{}, env)
	require.Equal(t, SeverityCritical, worst(fs))
	assert.Contains(t, findingText(fs), "NO encryption key", "AC 30: a live user with no DEK is critical")
}

func TestDEKInvariantCheck_UnwrappableDEKIsCritical(t *testing.T) {
	kek, err := crypto.NewEncryptor(testKEK)
	require.NoError(t, err)
	// A DEK wrapped for a DIFFERENT subject fails the AAD-bound unwrap for
	// this user — the present-but-unwrappable case (KEK/AAD mismatch), which
	// AC 30 requires be reported critical rather than mistaken for erasure.
	mismatched, err := crypto.GenerateWrappedDEK(kek, "someone-else")
	require.NoError(t, err)

	env := kekEnv(t, fakeDB{liveDEKs: []store.UserDEK{{UserID: "user-corrupt", Wrapped: mismatched}}})
	fs := run1(t, DEKInvariantCheck{}, env)
	require.Equal(t, SeverityCritical, worst(fs))
	assert.Contains(t, findingText(fs), "does not unwrap")
}

func TestDEKInvariantCheck_ResurrectedDEKIsCritical(t *testing.T) {
	env := kekEnv(t, fakeDB{deletedDEKs: []string{"erased-user-1"}})
	fs := run1(t, DEKInvariantCheck{}, env)
	require.Equal(t, SeverityCritical, worst(fs))
	txt := findingText(fs)
	assert.Contains(t, txt, "still hold an encryption key", "AC 31: deleted user with a DEK is critical")
	assert.Contains(t, txt, "re-shred", "and the remediation names the re-shred reconcile")
}

func TestDEKInvariantCheck_MissingKEKIsExecError(t *testing.T) {
	env := testEnv(nil) // no CONTROL_ENCRYPTION_KEY
	env.DB = fakeDB{}
	err := runErr(t, DEKInvariantCheck{}, env)
	require.Error(t, err, "without the KEK the unwrap probe cannot run — exec error, not a false pass")
}

func TestDEKInvariantCheck_DBDownSkips(t *testing.T) {
	env := testEnv(map[string]string{"CONTROL_ENCRYPTION_KEY": testKEK}) // DB nil
	fs := run1(t, DEKInvariantCheck{}, env)
	assert.NotEqual(t, SeverityCritical, worst(fs), "no DB → skipped, not a false critical")
}

func TestProjectionDriftCheck_HealthyIsOK(t *testing.T) {
	env := testEnv(nil)
	env.DB = fakeDB{drift: []store.TargetDrift{
		{Target: "users", StreamMax: 10, ProjMax: 10, Behind: false},
		{Target: "devices", StreamMax: 7, ProjMax: 7, Behind: false},
	}}
	fs := run1(t, ProjectionDriftCheck{}, env)
	assert.Equal(t, SeverityOK, worst(fs))
}

func TestProjectionDriftCheck_DriftIsCritical(t *testing.T) {
	env := testEnv(nil)
	env.DB = fakeDB{drift: []store.TargetDrift{
		{Target: "users", StreamMax: 42, ProjMax: 40, Behind: true, LaggingTable: "user_roles_projection", LaggingMax: 30},
		{Target: "devices", StreamMax: 7, ProjMax: 7, Behind: false},
	}}
	fs := run1(t, ProjectionDriftCheck{}, env)
	require.Equal(t, SeverityCritical, worst(fs))
	txt := findingText(fs)
	assert.Contains(t, txt, "users")
	assert.Contains(t, txt, "user_roles_projection", "the finding names the LAGGING table")
	assert.Contains(t, txt, "applied ≤ 30", "and ITS high-water, not the fresh sibling's target-wide max (40)")
	assert.Contains(t, txt, "rebuild-projections", "AC 31a remediation points at the rebuild before the next prune")
}

func TestProjectionDriftCheck_DBDownSkips(t *testing.T) {
	env := testEnv(nil) // DB nil
	fs := run1(t, ProjectionDriftCheck{}, env)
	assert.NotEqual(t, SeverityCritical, worst(fs))
}

func findingText(fs []Finding) string {
	var b strings.Builder
	for _, f := range fs {
		b.WriteString(f.Message)
		b.WriteString(" ")
		b.WriteString(f.Remediation)
		b.WriteString("\n")
	}
	return b.String()
}
