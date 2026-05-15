package postgres

import (
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// NewRepos constructs the Postgres-backed Repos bound to the given
// sqlc Queries handle. Callers (cmd/control, cmd/indexer, test
// fixtures) invoke this once after store.New and pass the result
// to Store.SetRepos.
//
// Future domains: extend the returned struct as additional repos
// are migrated under tracker #242.
func NewRepos(q *generated.Queries) *store.Repos {
	return &store.Repos{
		AuthState:        NewAuthState(q),
		Compliance:       NewCompliance(q),
		IdentityLink:     NewIdentityLink(q),
		IdentityProvider: NewIdentityProvider(q),
		Inventory:        NewInventory(q),
		Logs:             NewLogs(q),
		OSQuery:          NewOSQuery(q),
		RevokedToken:     NewRevokedToken(q),
		Role:             NewRole(q),
		Settings:         NewSettings(q),
		TerminalSession:  NewTerminalSession(q),
		Token:            NewToken(q),
		Totp:             NewTotp(q),
		UserSelection:    NewUserSelection(q),
	}
}
