package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const (
	UserProvisioningSourceSCIM    = "scim"
	UserProvisioningSourceOIDCJIT = "oidc_jit"
)

// EraseUser removes one subject's ordinary state and data-encryption key in
// the caller's audited transaction. Destroying the key makes class-three
// audit detail permanently unreadable while non-personal attribution remains.
func EraseUser(ctx context.Context, tx *Tx, rec *AuditRecorder, before UserRow) error {
	if ctx == nil || tx == nil || rec == nil {
		return fmt.Errorf("erase user: context, transaction, and audit recorder are required")
	}
	links, err := tx.DeleteIdentityLinksForUser(ctx, before.ID)
	if err != nil {
		return err
	}
	memberships, err := tx.DeleteUserGroupMembershipsForUser(ctx, before.ID)
	if err != nil {
		return err
	}
	grants, err := tx.DeleteUserRoleGrantsForUser(ctx, before.ID)
	if err != nil {
		return err
	}
	users, err := tx.DeleteUser(ctx, before.ID)
	if err != nil {
		return err
	}
	if users != 1 {
		return ErrNotFound
	}
	keys, err := tx.DeleteUserEncryptionKey(ctx, before.ID)
	if err != nil {
		return err
	}
	if keys != 1 {
		return fmt.Errorf("destroy subject encryption key: expected 1 row, got %d", keys)
	}

	digest := sha256.Sum256([]byte(before.Email))
	rec.Effect(AuditEffect{
		ResourceType:        "user",
		ResourceID:          before.ID,
		Action:              "ERASE",
		Outcome:             EffectApplied,
		ChangedFields:       []string{"email", "display_name", "linux_username"},
		EvidenceKind:        "email_sha256",
		EvidenceFingerprint: hex.EncodeToString(digest[:]),
	})
	rec.Effect(AuditEffect{
		ResourceType: "identity_link",
		ResourceID:   before.ID,
		Action:       "ERASE_IDENTITY_LINKS",
		Outcome:      EffectApplied,
		BeforeCount:  &links,
	})
	rec.Effect(AuditEffect{
		ResourceType: "user_group_member",
		ResourceID:   before.ID,
		Action:       "ERASE_MEMBERSHIPS",
		Outcome:      EffectApplied,
		BeforeCount:  &memberships,
	})
	rec.Effect(AuditEffect{
		ResourceType: "user_role",
		ResourceID:   before.ID,
		Action:       "ERASE_GRANTS",
		Outcome:      EffectApplied,
		BeforeCount:  &grants,
	})
	rec.Effect(AuditEffect{
		ResourceType: "user_encryption_key",
		ResourceID:   before.ID,
		Action:       "DESTROY_KEY",
		Outcome:      EffectApplied,
		BeforeCount:  &keys,
	})
	return nil
}
