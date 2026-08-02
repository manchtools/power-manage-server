// Package sqliteschema embeds the fresh-install SQLite schema.
package sqliteschema

import "embed"

// FS contains the one clean-break baseline used by pre-alpha installations.
//
//go:embed schema.sql
var FS embed.FS
