package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/manchtools/power-manage/server/internal/identity"
	"github.com/manchtools/power-manage/server/internal/store"
)

func runBootstrapAdmin(ctx context.Context, cfg *Config, rawToken bool) int {
	st, err := store.NewWithoutMigrations(ctx, cfg.DatabasePath)
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
	if err := writeBootstrapAdminOutput(os.Stdout, issued, rawToken); err != nil {
		fmt.Fprintln(os.Stderr, "bootstrap-admin: output failed")
		return 1
	}
	return 0
}

func writeBootstrapAdminOutput(w io.Writer, issued identity.BootstrapToken, rawToken bool) error {
	if rawToken {
		_, err := fmt.Fprintln(w, issued.Token)
		return err
	}
	_, err := fmt.Fprintf(w, "Bootstrap setup URL (valid until %s, single use):\n%s\n",
		issued.ExpiresAt.Format(time.RFC3339), issued.URL)
	return err
}
