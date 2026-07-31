package archtest

import (
	"os/exec"
	"strings"
	"testing"
)

// modulePath is this module's import path; every first-party dependency
// reported by `go list -deps` is prefixed with it.
const modulePath = "github.com/manchtools/power-manage/server"

// gatewayPackages are the import paths spec 41 deleted. R8: none of them may be
// reachable from the control binary. Listed as PREFIXES — a subpackage
// (internal/gateway/foo) is just as much a violation as the package itself.
var gatewayPackages = []string{
	modulePath + "/internal/gateway",
	modulePath + "/internal/gwenroll",
	modulePath + "/cmd/gateway",
}

// controlReachableWitness is a package the control binary provably imports. It
// is the guard's positive control: if `go list` ever stops reporting it, the
// dependency set being scanned is not control's and every ban below would pass
// for the wrong reason.
const controlReachableWitness = modulePath + "/internal/api"

// bannedDep reports whether dep is (or lives under) one of the banned import
// paths. Prefix matching is on a path SEPARATOR, so a hypothetical
// `internal/gatewayish` is not a false positive.
func bannedDep(dep string, banned []string) (string, bool) {
	for _, b := range banned {
		if dep == b || strings.HasPrefix(dep, b+"/") {
			return b, true
		}
	}
	return "", false
}

// TestBannedDepMatchesOnPathBoundaries is the matcher's own positive control.
//
// The real guard below asserts an ABSENCE, and an absence assertion made with a
// broken matcher passes vacuously forever — the whole failure mode spec 41's
// criterion 11 calls out with "with a matches-zero assertion on the scan". This
// pins that the predicate actually fires on the shapes it must catch, and does
// not fire on a package that merely shares a name prefix.
func TestBannedDepMatchesOnPathBoundaries(t *testing.T) {
	for _, dep := range []string{
		modulePath + "/internal/gateway",
		modulePath + "/internal/gateway/enroll",
		modulePath + "/internal/gwenroll",
		modulePath + "/cmd/gateway",
	} {
		if _, hit := bannedDep(dep, gatewayPackages); !hit {
			t.Errorf("matcher failed to flag a banned package: %s", dep)
		}
	}
	for _, dep := range []string{
		modulePath + "/internal/gatewayish",
		modulePath + "/internal/api",
		"crypto/tls",
	} {
		if b, hit := bannedDep(dep, gatewayPackages); hit {
			t.Errorf("matcher flagged %s against %s — prefix matching is not on a path boundary", dep, b)
		}
	}

	// The ban list and the positive control must stay DISJOINT. Banning a
	// package control legitimately imports turns the guard into a permanent
	// red that says nothing about the gateway, and the obvious "fix" for that
	// red is to delete the guard. Pinned explicitly so the two lists cannot
	// drift into contradiction.
	if b, hit := bannedDep(controlReachableWitness, gatewayPackages); hit {
		t.Errorf("the positive-control witness %s is itself banned (by %s) — the guard would fail for a reason "+
			"unrelated to spec 41 R8", controlReachableWitness, b)
	}
}

// TestControlBinaryDoesNotReachGatewayPackages is spec 41 criterion 11 / R8: no
// package under internal/gateway, internal/gwenroll or cmd/gateway may be
// reachable from the control binary.
//
// The question is about the BUILT binary's dependency graph, so it is answered
// by the toolchain (`go list -deps`) rather than by an AST walk: only go list
// resolves build tags, blank imports and indirect edges the same way the linker
// does. An AST-level approximation could miss a reachable package and report
// "clean".
//
// Two guards keep the absence honest:
//
//   - matches-zero: an empty (or first-party-empty) dependency list fails,
//     because `go list` printing nothing looks identical to "no violations".
//   - positive control: a package control definitively imports must appear, so
//     a mis-scoped invocation that lists some OTHER target's dependencies
//     cannot pass by scanning the wrong graph.
func TestControlBinaryDoesNotReachGatewayPackages(t *testing.T) {
	root := moduleRoot(t)

	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("go toolchain not on PATH, cannot resolve the control binary's dependency graph: %v", err)
	}

	cmd := exec.Command(goBin, "list", "-deps", "./cmd/control")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps ./cmd/control failed: %v\n%s", err, out)
	}

	deps := strings.Fields(string(out))
	if len(deps) == 0 {
		t.Fatal("matches-zero guard: go list reported no dependencies for ./cmd/control — the scan is broken, " +
			"and an empty graph would make every ban below pass vacuously")
	}

	firstParty := 0
	sawWitness := false
	for _, dep := range deps {
		if strings.HasPrefix(dep, modulePath+"/") {
			firstParty++
		}
		if dep == controlReachableWitness {
			sawWitness = true
		}
		if banned, hit := bannedDep(dep, gatewayPackages); hit {
			t.Errorf("control reaches a deleted gateway package: %s (banned by %s) — spec 41 R8", dep, banned)
		}
	}

	if firstParty == 0 {
		t.Fatal("matches-zero guard: go list reported no first-party packages for ./cmd/control — " +
			"the module path is wrong and no ban could ever match")
	}
	if !sawWitness {
		t.Fatalf("positive control failed: %s is not in ./cmd/control's dependency list, so this scan is not "+
			"looking at the control binary's graph and its silence proves nothing", controlReachableWitness)
	}
}
