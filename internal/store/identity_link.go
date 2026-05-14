package store

import (
	"context"
	"time"
)

// IdentityLink is the per-user SSO-link projection row.
type IdentityLink struct {
	ID            string
	UserID        string
	ProviderID    string
	ExternalID    string
	ExternalEmail string
	ExternalName  string
	LinkedAt      time.Time
	LastLoginAt   *time.Time
}

// IdentityLinkWithProvider is the join shape used by the
// ListForUser query, which augments each link with display fields
// from identity_providers_projection. Kept distinct from IdentityLink
// so callers can't mistakenly assume provider info is populated on a
// basic Get.
type IdentityLinkWithProvider struct {
	IdentityLink
	ProviderName string
	ProviderSlug string
}

// IdentityLinkRepo reads SSO-link projection rows for self-service
// identity management. Writes happen via the IdentityUnlinked /
// IdentityLinked event types, not through this interface.
type IdentityLinkRepo interface {
	// Get returns the identity link with the given ID. Returns
	// ErrNotFound if the link does not exist (unlinked or never
	// existed).
	Get(ctx context.Context, id string) (IdentityLink, error)

	// ListForUser returns all identity links owned by the user,
	// joined with provider display info, ordered newest-linked
	// first. Returns an empty slice when the user has no links.
	ListForUser(ctx context.Context, userID string) ([]IdentityLinkWithProvider, error)

	// CountForUser returns the number of identity links for the
	// user. Used by the "cannot unlink last auth method"
	// pre-condition in UnlinkIdentity.
	CountForUser(ctx context.Context, userID string) (int64, error)
}
