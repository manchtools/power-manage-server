package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/manchtools/power-manage-sdk/gen/go/pm/v1/pmv1connect"

	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/gwenroll"
	"github.com/manchtools/power-manage/server/internal/mtls"
)

// renewalRetryBackoff bounds how soon a failed renewal retries — long enough not
// to hammer control, short enough that a transient failure well before expiry
// recovers with plenty of margin (the 45-day TTL leaves ~9 days of slack once
// the 80% mark triggers the first attempt).
const renewalRetryBackoff = 5 * time.Minute

// runGatewayCertRenewal renews the gateway certificate at 80% of its lifetime
// and installs the new cert into the rotator, so new agent handshakes pick it up
// while in-flight connections finish on the old one (spec 31 Part B). It renews
// over the InternalService mTLS plane presenting the current gateway cert. Runs
// until ctx is cancelled; a renewal failure retries after a bounded backoff.
func runGatewayCertRenewal(ctx context.Context, internalClient pmv1connect.InternalServiceClient, id *gwenroll.Identity, rotator *mtls.CertRotator, logger *slog.Logger) {
	for {
		notAfter, err := ca.NotAfterFromPEM(id.CertPEM)
		if err != nil {
			logger.Error("gateway renewal disabled: cannot parse current cert expiry", "error", err)
			return
		}
		// Renew when 80% of the lifetime has elapsed — i.e. wait until the last
		// 20% of the remaining life. remaining/5 is 20% of what's left; at issuance
		// (~45d out) that fires ~9 days before expiry.
		remaining := time.Until(notAfter)
		wait := remaining - remaining/5
		if wait < 0 {
			wait = 0
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}

		newNotAfter, err := gwenroll.Renew(ctx, internalClient, id)
		if err != nil {
			logger.Error("gateway certificate renewal failed; retrying", "gateway_id", id.GatewayID, "error", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(renewalRetryBackoff):
			}
			continue
		}
		// Renew updated id.TLSCert/CertPEM in place; install the new leaf.
		rotator.Set(id.TLSCert)
		logger.Info("gateway certificate renewed", "gateway_id", id.GatewayID, "not_after", newNotAfter)
	}
}
