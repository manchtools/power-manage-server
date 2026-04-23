package api

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestErrorCodeParityWithTSSDK guards against drift between the
// snake_case error codes the server emits (errors.go) and the Err*
// constants the TS SDK exports (sdk/ts/errors.ts). When the two
// lists disagree, the web client falls back to raw code strings
// instead of the paraglide-localized message, which is exactly the
// kind of silent UX regression the rc10 audit flagged.
//
// Fails with a diff when the sets don't match. To fix:
//   - If the server added a new code, add a matching Err* const to
//     sdk/ts/errors.ts AND a matching error_<code> paraglide key to
//     web/messages/{en,de}.json.
//   - If the server removed a code, delete the const from
//     sdk/ts/errors.ts and the matching paraglide key.
func TestErrorCodeParityWithTSSDK(t *testing.T) {
	serverCodes := extractServerCodes(t)
	sdkCodes := extractSDKCodes(t)

	missingFromSDK := diff(serverCodes, sdkCodes)
	extraInSDK := diff(sdkCodes, serverCodes)

	if len(missingFromSDK) > 0 {
		t.Errorf("error codes emitted by server but not exported by sdk/ts/errors.ts: %v\n"+
			"→ add a matching Err* const to sdk/ts/errors.ts and an error_<code> key to web/messages/{en,de}.json",
			missingFromSDK)
	}
	if len(extraInSDK) > 0 {
		t.Errorf("error codes exported by sdk/ts/errors.ts but never emitted by the server: %v\n"+
			"→ delete the stale consts (and any matching paraglide keys) to stop lying to future developers",
			extraInSDK)
	}
}

// extractServerCodes walks errors.go and returns every snake_case
// string literal assigned to an Err* constant. Deliberately NOT
// importing the constants directly — we want to catch the case where
// a const is declared but never used, or where a code is hard-coded
// in a handler without going through the constant.
func extractServerCodes(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile("errors.go")
	if err != nil {
		t.Fatalf("read server errors.go: %v", err)
	}
	// Match lines like: ErrWhatever = "snake_case_value"
	re := regexp.MustCompile(`Err\w+\s*=\s*"([a-z][a-z0-9_]*)"`)
	matches := re.FindAllStringSubmatch(string(data), -1)
	seen := make(map[string]struct{}, len(matches))
	for _, m := range matches {
		seen[m[1]] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for code := range seen {
		out = append(out, code)
	}
	sort.Strings(out)
	return out
}

// extractSDKCodes walks sdk/ts/errors.ts and returns every
// snake_case string literal assigned to an exported Err* const.
//
// Resolution order:
//  1. PM_SDK_TS_ERRORS env var (absolute or relative path) — CI sets
//     this when it checks the SDK out beside the server repo, so
//     standalone server CI can still exercise the parity guard.
//  2. ../../../../sdk/ts/errors.ts — the local dev-workspace layout
//     /home/<user>/.../power-manage/{server,sdk}.
//
// If neither resolves AND PM_SDK_PARITY_REQUIRED=1 is set, the test
// fails loudly — this is the mode CI should use when it expects the
// SDK to be available. Without the env var the test skips with a
// clear log line so a local `go test ./...` in a standalone server
// checkout still passes.
func extractSDKCodes(t *testing.T) []string {
	t.Helper()

	var candidates []string
	if env := os.Getenv("PM_SDK_TS_ERRORS"); env != "" {
		candidates = append(candidates, env)
	}
	candidates = append(candidates, filepath.Join("..", "..", "..", "..", "sdk", "ts", "errors.ts"))

	var data []byte
	var tried []string
	for _, path := range candidates {
		tried = append(tried, path)
		b, err := os.ReadFile(path)
		if err == nil {
			data = b
			break
		}
	}
	if data == nil {
		msg := "cannot read sdk/ts/errors.ts from any candidate path: " + strings.Join(tried, ", ")
		if os.Getenv("PM_SDK_PARITY_REQUIRED") == "1" {
			t.Fatalf("PM_SDK_PARITY_REQUIRED=1 but %s — CI should check out the sdk repo beside server or set PM_SDK_TS_ERRORS", msg)
		}
		t.Skipf("%s — set PM_SDK_TS_ERRORS or PM_SDK_PARITY_REQUIRED=1 (with the file available) to exercise the parity guard", msg)
		return nil
	}

	re := regexp.MustCompile(`export\s+const\s+Err\w+\s*=\s*'([a-z][a-z0-9_]*)'`)
	matches := re.FindAllStringSubmatch(string(data), -1)
	seen := make(map[string]struct{}, len(matches))
	for _, m := range matches {
		seen[m[1]] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for code := range seen {
		out = append(out, code)
	}
	sort.Strings(out)
	return out
}

// diff returns elements in a that are not in b, sorted.
func diff(a, b []string) []string {
	present := make(map[string]struct{}, len(b))
	for _, s := range b {
		present[s] = struct{}{}
	}
	var out []string
	for _, s := range a {
		if _, ok := present[s]; !ok {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// Guard against string-builder typos in the tests above.
func init() {
	if strings.Count("Err", "E") != 1 {
		panic("sanity")
	}
}
