package auth

import "strings"

// scopeSuffixes are the permission scope qualifiers. Holding the unrestricted
// base permission entitles the holder to grant any scoped form of it.
var scopeSuffixes = []string{":self", ":assigned"}

// UncoveredPermissions returns the subset of granted that a caller holding
// `held` may NOT grant — the basis of the "grant only what you hold" privilege
// ceiling. A held permission covers a granted one when they are equal, or when
// the held permission is the unrestricted base of a scoped granted permission
// (holding `X` covers granting `X:self` / `X:assigned`). You may grant a
// NARROWER scope than you hold, never a broader one.
//
// An empty result means the caller is entitled to grant everything in granted.
// Admins hold every unrestricted permission (AdminPermissions), so they cover
// any grant.
func UncoveredPermissions(held, granted []string) []string {
	heldSet := make(map[string]bool, len(held))
	for _, h := range held {
		heldSet[h] = true
	}
	var missing []string
	for _, g := range granted {
		if heldSet[g] {
			continue
		}
		if base, scoped := baseOfScoped(g); scoped && heldSet[base] {
			continue
		}
		missing = append(missing, g)
	}
	return missing
}

// baseOfScoped strips a :self / :assigned suffix, reporting whether one was
// present.
func baseOfScoped(p string) (string, bool) {
	for _, s := range scopeSuffixes {
		if b, ok := strings.CutSuffix(p, s); ok {
			return b, true
		}
	}
	return p, false
}
