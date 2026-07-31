// The host-authorized bootstrap-admin command.
//
// Human identity is OIDC only, which leaves a fresh deployment with no
// way for anyone to sign in and configure the first identity provider.
// This command is the single exception: run on the host, it mints one
// short-lived, single-use bearer token and prints the URL that spends
// it. Possession of the host IS the authorization — there is no
// credential to present here, and none is stored.
//
// The token authenticates a permanently reserved principal that is not
// a user, owns nothing, and therefore can never satisfy a `:self`
// grant. Its authority is the fixed setup set in
// identity.BootstrapPermissions.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/manchtools/power-manage/server/internal/identity"
	"github.com/manchtools/power-manage/server/internal/store"
)

// runBootstrapAdmin mints a setup token and prints it. Returns a
// process exit code.
func runBootstrapAdmin(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("bootstrap-admin", flag.ContinueOnError)
	databaseURL := fs.String("database-url", os.Getenv("CONTROL_DATABASE_URL"),
		"PostgreSQL connection string")
	publicURL := fs.String("public-url", os.Getenv("CONTROL_PUBLIC_URL"),
		"externally reachable base URL of this deployment")
	ttl := fs.Duration("ttl", identity.DefaultBootstrapTokenTTL,
		"how long the token stays presentable")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *databaseURL == "" {
		fmt.Fprintln(os.Stderr, "bootstrap-admin: --database-url (or CONTROL_DATABASE_URL) is required")
		return 2
	}
	if *publicURL == "" {
		fmt.Fprintln(os.Stderr, "bootstrap-admin: --public-url (or CONTROL_PUBLIC_URL) is required")
		return 2
	}

	st, err := store.NewWithoutMigrations(ctx, *databaseURL)
	if err != nil {
		// The connection string can carry a password, so the error is
		// reported without it.
		fmt.Fprintf(os.Stderr, "bootstrap-admin: cannot reach the database at %s\n", maskDatabaseURL(*databaseURL))
		return 1
	}
	defer st.Close()

	issued, err := identity.NewBootstrapper(st, *publicURL, *ttl, time.Now).Issue(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bootstrap-admin: could not issue a setup token")
		return 1
	}

	// The token is printed to STDOUT exactly once. Only its digest was
	// stored, so it cannot be recovered afterwards; a lost token is
	// replaced by running this command again, which retires the old
	// one.
	fmt.Printf("Bootstrap setup URL (valid until %s, single use):\n%s\n",
		issued.ExpiresAt.Format(time.RFC3339), issued.URL)
	return 0
}
