//go:build !devauth

package main

import (
	"log/slog"
	"net/http"

	"github.com/manchtools/power-manage/server/internal/auth"
	pmcrypto "github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/store"
)

// wrapDevAuth is a no-op in production builds: the development auth bypass
// (POST /dev/session) exists only in binaries compiled with the `devauth`
// build tag. Keeping the signature identical lets main.go wire it
// unconditionally while the real handler is physically absent here.
func wrapDevAuth(next http.Handler, _ *store.Store, _ *auth.JWTManager, _ *pmcrypto.Encryptor, _ *slog.Logger) http.Handler {
	return next
}
