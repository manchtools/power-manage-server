package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/manchtools/power-manage/server/internal/identity"
	"github.com/manchtools/power-manage/server/internal/store"
)

func runBootstrapAdmin(ctx context.Context, cfg *Config) int {
	st, err := store.NewWithoutMigrations(ctx, cfg.DatabaseURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bootstrap-admin: database unavailable")
		return 1
	}
	defer st.Close()
	issued, err := identity.NewBootstrapper(st, cfg.PublicBaseURL,
		identity.DefaultBootstrapTokenTTL, time.Now).Issue(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bootstrap-admin: token could not be issued")
		return 1
	}
	fmt.Printf("Bootstrap setup URL (valid until %s, single use):\n%s\n",
		issued.ExpiresAt.Format(time.RFC3339), issued.URL)
	return 0
}
