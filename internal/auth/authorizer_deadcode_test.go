package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// WS16 #14: the device-authz machinery (DeviceContext, WithDevice,
// DeviceFromContext, SubjectFromContext, authorizeDevice and the AuthzInput
// device fields) was dead — agents authenticate to the gateway over mTLS and
// never reach this control-plane interceptor. It was removed. This
// self-discovering guard fails if any of it is reintroduced, so the path can
// never silently rot back into ambiguous, live-looking authz code.
//
// It scans the whole server module's production (non-_test.go) source rather
// than a hardcoded file list, and refuses to pass if it matched zero files.
func TestDeviceAuthz_NoProductionCallerOrSymbol_GuardsAgainstRot(t *testing.T) {
	// Identifiers that lived only in the removed device-authz path. A bare
	// match in any production source means the machinery came back. Note: an
	// unrelated `DeviceContext` type exists in dyngroupeval/dynamicquery, so we
	// only flag the auth-qualified form module-wide and the bare form inside
	// internal/auth.
	deadAuthSymbols := []string{"authorizeDevice", "WithDevice", "DeviceFromContext", "SubjectFromContext"}
	deadQualified := []string{"auth.WithDevice", "auth.DeviceFromContext", "auth.SubjectFromContext", "auth.DeviceContext"}

	moduleRoot := filepath.Join("..", "..") // internal/auth -> server module root

	scanned := 0
	for _, sub := range []string{"internal", "cmd"} {
		root := filepath.Join(moduleRoot, sub)
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			// Don't flag this guard's own source.
			if strings.HasSuffix(path, "authorizer_deadcode_test.go") {
				return nil
			}
			data, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			src := string(data)
			scanned++

			inAuthPkg := strings.Contains(filepath.ToSlash(path), "/internal/auth/")
			if inAuthPkg {
				for _, sym := range deadAuthSymbols {
					require.NotContainsf(t, src, sym,
						"%s: dead device-authz symbol %q reintroduced in the auth package (WS16 #14)", path, sym)
				}
			}
			for _, q := range deadQualified {
				require.NotContainsf(t, src, q,
					"%s: reference to removed device-authz API %q (WS16 #14)", path, q)
			}
			return nil
		})
		require.NoError(t, err)
	}

	require.Greater(t, scanned, 100, "device-authz guard matched too few files — the walk is broken, the check would pass vacuously")
}
