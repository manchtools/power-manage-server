package store

// Repos is the union of domain repository interfaces. Handlers depend
// on this struct via Store.Repos(); backends populate it with their
// implementations (Postgres today via internal/store/postgres).
//
// Part of the storage-abstraction tracker (#242). Domains migrate to
// fields here one at a time — until all migrations land, handlers
// that touch un-migrated domains keep using Store.Queries(). See
// project_storage_abstraction_plan.md for the wave order.
//
// Adding a new repo: define the interface alongside this file (e.g.
// device.go for DeviceRepo), implement it under internal/store/postgres,
// add a field here, populate it in postgres.NewRepos.
type Repos struct {
	Compliance      ComplianceRepo
	IdentityLink    IdentityLinkRepo
	Logs            LogsRepo
	OSQuery         OSQueryRepo
	Role            RoleRepo
	Settings        SettingsRepo
	TerminalSession TerminalSessionRepo
	Totp            TotpRepo
}
