package store

// ScopeGroupFilter carries device/user-group scope restriction for a list or
// count query (#3). Restricted=false ⇒ no row filtering (caller is global, has no
// scoping grant, or is confined by a separate owner filter). Restricted=true ⇒
// rows are confined to GroupIDs; an empty GroupIDs restricts to NOTHING (a
// wrong-kind grant or an unauthenticated caller — fail closed).
//
// The generated queries key their membership / id-match predicate off Restricted
// (a boolean), not off GroupIDs being nil-vs-empty, so the SQL is unambiguous and
// pgx array encoding never decides access. Mirrors the (groupIDs, restricted)
// output of auth.DeviceScopeListFilter / auth.UserScopeListFilter.
type ScopeGroupFilter struct {
	Restricted bool
	GroupIDs   []string
}
