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

// archiveIsolationRelaxed is false in every production build: the audit
// archive must be on its own filesystem, and a shipped binary offers no way
// to say otherwise. There is deliberately no configuration variable for it —
// an option to skip a verification is the thing an attacker looks for first,
// and the workstation case is served by the same build tag that already gates
// the development sign-in.
func archiveIsolationRelaxed() bool { return false }
