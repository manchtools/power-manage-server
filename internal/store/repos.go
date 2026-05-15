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
	AuthState        AuthStateRepo
	Compliance       ComplianceRepo
	Device           DeviceRepo
	DeviceGroup      DeviceGroupRepo
	IdentityLink     IdentityLinkRepo
	IdentityProvider IdentityProviderRepo
	Inventory        InventoryRepo
	Logs             LogsRepo
	OSQuery          OSQueryRepo
	RevokedToken     RevokedTokenRepo
	Role             RoleRepo
	SCIM             SCIMRepo
	Settings         SettingsRepo
	TerminalSession  TerminalSessionRepo
	Token            TokenRepo
	Totp             TotpRepo
	User             UserRepo
	UserGroup        UserGroupRepo
	UserSelection    UserSelectionRepo
}
