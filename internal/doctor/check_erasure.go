package doctor

import (
	"context"
	"fmt"
)

// ErasureProvisioningCheck is the spec 19 AC 36 safety net: it flags an erased
// (is_deleted) user whose OS account teardown was incomplete — their system
// USER action is still live (not deleted) and PRESENT, so the account persists
// on already-provisioned devices. Deletion crypto-shreds the DEK and redacts the
// projection, but the account teardown rides on a best-effort
// CleanupDeletedUserActions call (user_handler.go — logged, never fails the
// delete so erasure always completes). If that teardown was dropped (queue down,
// gateway offline), the user's OS account can persist on devices with the
// projection already redacted and no other alarm — a GDPR/NIS2 gap. This check
// is that alarm; the reconcile sweep (control periodic worker) is the auto-fix.
//
// A lingering user_provisioning_enabled flag is intentionally not flagged:
// SyncUserSystemActions fail-closes on is_deleted (AC 32), so an erased user can
// never re-acquire a provisioning action, and nothing clears the flag on delete
// — treating it as a finding would fire on every erased user a
// provisioning-for-all deployment ever had.
//
// Read-only: the check reports; reconciliation is the sweep's / operator's job.
type ErasureProvisioningCheck struct{}

func (ErasureProvisioningCheck) ID() string { return "erasure_provisioning" }

func (c ErasureProvisioningCheck) Run(ctx context.Context, env *Env) ([]Finding, error) {
	if skip, proceed := dbReady(ctx, c, env); !proceed {
		return skip, nil
	}

	orphans, err := env.DB.ErasedUsersStillProvisioned(ctx)
	if err != nil {
		return nil, fmt.Errorf("list erased users still provisioned: %w", err)
	}
	if len(orphans) == 0 {
		return []Finding{ok(c.ID(),
			"no erased user retains a live OS account (teardown completed for every deleted user)")}, nil
	}

	ids := make([]string, len(orphans))
	for i, o := range orphans {
		ids[i] = o.UserID
	}
	return []Finding{crit(c.ID(),
		fmt.Sprintf("%d erased user(s) still have a live PRESENT system USER action — their OS account persists on devices (incomplete teardown): %s",
			len(orphans), sample(ids)),
		"the reconcile sweep re-runs teardown automatically; if it is disabled, re-run the user teardown so the system USER action is removed and the account is deleted from devices — until then the erased account lives on managed hosts")}, nil
}
