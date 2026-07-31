package scim

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/idp"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// actorSCIM attributes the rows a directory writes on nobody's behalf.
const actorSCIM = "scim"

// errNoChange aborts an audited transaction that turned out to have
// nothing to do.
//
// A directory re-asserts its whole population on every sync cycle, and
// most cycles change nothing. Returning this rolls the transaction back
// so no operation row is appended: the audit log is evidence of change,
// and an empty operation per poll would bury the changes in noise. The
// callback wrote nothing, so there is nothing to lose in the rollback.
var errNoChange = errors.New("scim: the assertion changed nothing")

// noChangeIfNothingRecorded ends a mutation callback: it commits when
// the callback recorded an effect, and aborts when it did not.
func noChangeIfNothingRecorded(rec *store.AuditRecorder) error {
	if rec.Len() == 0 {
		return errNoChange
	}
	return nil
}

// subjectAssertion is what a directory said a subject should look like.
// A nil field was not asserted and is left alone; a non-nil field is
// asserted and overwrites, including with an empty value.
type subjectAssertion struct {
	Email       *string
	Active      *bool
	DisplayName *string
	GivenName   *string
	FamilyName  *string
}

// assertsProfile reports whether any name field was asserted.
func (a subjectAssertion) assertsProfile() bool {
	return a.DisplayName != nil || a.GivenName != nil || a.FamilyName != nil
}

// assertionFromResource reads a full user resource as an assertion.
//
// An omitted name object leaves the profile alone; an explicitly empty
// one clears it. Collapsing those two would make a deliberate clear
// impossible, and the directory is the source of truth for the profile.
func assertionFromResource(u SCIMUser) subjectAssertion {
	a := subjectAssertion{Active: u.Active}
	if email := resourceEmail(u); email != "" {
		normalized := normalizeEmail(email)
		a.Email = &normalized
	}
	if u.Name != nil {
		display := formatExternalName(u.Name)
		a.DisplayName = &display
		a.GivenName = &u.Name.GivenName
		a.FamilyName = &u.Name.FamilyName
	}
	return a
}

// resourceEmail picks the address a user resource carries: userName
// first, then the first email entry.
func resourceEmail(u SCIMUser) string {
	if u.UserName != "" {
		return u.UserName
	}
	if len(u.Emails) > 0 {
		return u.Emails[0].Value
	}
	return ""
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

// createUser handles POST /Users.
//
// A directory re-asserts its whole population on every sync cycle, so a
// POST for something already provisioned is a sync and answers 200. Only
// a subject this directory has never seen is a create.
func (h *Handler) createUser(w http.ResponseWriter, r *http.Request, s *session) {
	ctx := r.Context()
	var resource SCIMUser
	if !decodeBody(w, r, &resource) {
		return
	}

	email := normalizeEmail(resourceEmail(resource))
	if email == "" {
		writeError(w, http.StatusBadRequest, "userName or emails[0].value is required")
		return
	}
	baseURL := baseURLFromRequest(r, s.provider.Slug)
	assertion := assertionFromResource(resource)

	// Already bound under this external identifier: the directory is
	// re-asserting, not creating.
	if resource.ExternalID != "" {
		existing, err := h.store.FindSCIMUserByExternalID(ctx, s.provider.ID, resource.ExternalID)
		switch {
		case err == nil:
			h.syncSubject(w, r, s, existing.User, resource.ExternalID, assertion, baseURL, http.StatusOK)
			return
		case !store.IsNotFound(err):
			h.logger.Error("scim: failed to resolve external identifier", "error", err)
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}
	}

	if s.provider.AutoLinkByEmail {
		bound, err := h.store.FindSCIMUserByEmail(ctx, s.provider.ID, email)
		switch {
		case err == nil:
			h.syncSubject(w, r, s, bound.User, resource.ExternalID, assertion, baseURL, http.StatusOK)
			return
		case !store.IsNotFound(err):
			h.logger.Error("scim: failed to resolve address", "error", err)
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}

		existing, err := h.store.GetUserByEmail(ctx, email)
		switch {
		case err == nil:
			if !h.mayBindByAddress(ctx, w, s, existing.ID) {
				return
			}
			h.bindExistingSubject(w, r, s, existing, resource, baseURL)
			return
		case !store.IsNotFound(err):
			h.logger.Error("scim: failed to look up subject by address", "error", err)
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}
	}

	h.provisionSubject(w, r, s, resource, email, baseURL)
}

// mayBindByAddress applies the account-takeover guard.
//
// A directory can assert any address. Binding one to an account that is
// ALREADY bound to some other directory would hand that account over,
// and the asserting directory is the very party the guard defends
// against — so its own claim that the address is verified is not a
// backstop. An account with no binding yet is the ordinary invite flow.
// The same invariant governs the SSO auto-link path in internal/idp.
func (h *Handler) mayBindByAddress(ctx context.Context, w http.ResponseWriter, s *session, userID string) bool {
	if s.provider.TrustEmailAssertions {
		return true
	}
	bound, err := h.store.CountIdentityLinksForUser(ctx, userID)
	if err != nil {
		h.logger.Error("scim: failed to count existing bindings", "error", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return false
	}
	if bound > 0 {
		h.logger.Warn("scim: refusing to bind an already-bound account by asserted address")
		writeError(w, http.StatusConflict, "the address already belongs to a bound account; cannot auto-link")
		return false
	}
	return true
}

// bindExistingSubject binds an unbound local account to this directory.
func (h *Handler) bindExistingSubject(w http.ResponseWriter, r *http.Request, s *session, existing store.UserRow, resource SCIMUser, baseURL string) {
	ctx := r.Context()
	linkID := ulid.Make().String()
	at := h.now().UTC()

	_, err := h.store.WithAudit(ctx, h.mutationOp(s), func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		return h.insertBinding(ctx, tx, rec, s, bindingSpec{
			LinkID:      linkID,
			UserID:      existing.ID,
			ExternalID:  resource.ExternalID,
			Email:       existing.Email,
			DisplayName: formatExternalName(resource.Name),
			At:          at,
		})
	})
	if err != nil {
		if store.IsConflict(err) {
			writeError(w, http.StatusConflict, "the external identifier is already bound")
			return
		}
		h.logger.Error("scim: failed to bind existing subject", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to link user")
		return
	}
	writeJSON(w, http.StatusCreated, userResource(existing, resource.ExternalID, baseURL))
}

// provisionSubject creates a subject and its binding.
//
// The subject's data-encryption key is minted FIRST and inside the same
// transaction: the audit record carries the address as class-three
// sealed detail, and sealing needs the key to already exist and to be
// the one erasure will later destroy.
func (h *Handler) provisionSubject(w http.ResponseWriter, r *http.Request, s *session, resource SCIMUser, email, baseURL string) {
	ctx := r.Context()
	userID := ulid.Make().String()
	linkID := ulid.Make().String()
	at := h.now().UTC()

	var created store.UserRow
	_, err := h.store.WithAudit(ctx, h.mutationOp(s), func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		wrapped, err := h.mintSubjectDEK(ctx, tx, userID)
		if err != nil {
			return err
		}
		sealed, err := h.sealForSubject(userID, wrapped, "email", email)
		if err != nil {
			return err
		}

		linuxUID, err := tx.GetNextLinuxUID(ctx)
		if err != nil {
			return err
		}
		linuxUsername := idp.DeriveLinuxUsername(email, resource.UserName)
		if linuxUsername == "" {
			linuxUsername = "user_" + strings.ToLower(userID[:8])
		}

		created, err = tx.InsertUser(ctx, db.InsertUserParams{
			ID:            userID,
			Email:         email,
			DisplayName:   formatExternalName(resource.Name),
			GivenName:     nameField(resource.Name, func(n *SCIMName) string { return n.GivenName }),
			FamilyName:    nameField(resource.Name, func(n *SCIMName) string { return n.FamilyName }),
			LinuxUsername: linuxUsername,
			LinuxUid:      linuxUID,
			CreatedAt:     &at,
		})
		if err != nil {
			return err
		}
		rec.Effect(store.AuditEffect{
			ResourceType:        "user",
			ResourceID:          userID,
			Action:              "CREATE",
			Outcome:             store.EffectApplied,
			ChangedFields:       []string{"email", "display_name", "linux_username", "linux_uid"},
			AfterRef:            &s.provider.ID,
			EvidenceKind:        "email_sha256",
			EvidenceFingerprint: fingerprint(email),
			SealedDetail:        sealed,
			SealedDetailSubject: userID,
		})

		// The provider's default role is the only authority this
		// surface grants at creation. Anything else is an operator
		// decision, made through the role RPCs.
		if s.provider.DefaultRoleID != "" {
			grantID := ulid.Make().String()
			if _, err := tx.InsertUserRoleGrant(ctx, db.InsertUserRoleGrantParams{
				GrantID:    grantID,
				UserID:     userID,
				RoleID:     s.provider.DefaultRoleID,
				AssignedAt: at,
				AssignedBy: actorSCIM,
			}); err != nil {
				return err
			}
			rec.Effect(store.AuditEffect{
				ResourceType: "user_role",
				ResourceID:   grantID,
				Action:       "GRANT",
				Outcome:      store.EffectApplied,
				BeforeRef:    &userID,
				AfterRef:     &s.provider.DefaultRoleID,
			})
		}

		if err := h.applyDeploymentDefaults(ctx, tx, rec, userID, at); err != nil {
			return err
		}

		// A directory may provision a subject already deactivated. The
		// insert carries no such column, so the state is asserted right
		// after it — inside the same transaction, so a deactivated
		// subject is never briefly usable.
		if !resource.IsActive() {
			if _, err := tx.SetUserDisabled(ctx, db.SetUserDisabledParams{
				ID: userID, Disabled: true, UpdatedAt: &at,
			}); err != nil {
				return err
			}
			no, yes := false, true
			rec.Effect(store.AuditEffect{
				ResourceType:  "user",
				ResourceID:    userID,
				Action:        "SET_DISABLED",
				Outcome:       store.EffectApplied,
				ChangedFields: []string{"disabled", "session_version"},
				BeforeFlag:    &no,
				AfterFlag:     &yes,
			})
			created.Disabled = true
		}

		return h.insertBinding(ctx, tx, rec, s, bindingSpec{
			LinkID:      linkID,
			UserID:      userID,
			ExternalID:  resource.ExternalID,
			Email:       email,
			DisplayName: formatExternalName(resource.Name),
			At:          at,
		})
	})
	if err != nil {
		if store.IsConflict(err) {
			writeError(w, http.StatusConflict, "a user with that address already exists")
			return
		}
		h.logger.Error("scim: failed to provision subject", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to create user")
		return
	}

	writeJSON(w, http.StatusCreated, userResource(created, resource.ExternalID, baseURL))
}

// applyDeploymentDefaults applies the deployment-wide switches a newly
// provisioned subject inherits.
func (h *Handler) applyDeploymentDefaults(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder, userID string, at time.Time) error {
	settings, err := tx.GetServerSettings(ctx)
	if err != nil {
		return err
	}
	yes := true
	if settings.UserProvisioningEnabled {
		if _, err := tx.SetUserProvisioningEnabled(ctx, db.SetUserProvisioningEnabledParams{
			ID:                      userID,
			UserProvisioningEnabled: true,
			UpdatedAt:               &at,
		}); err != nil {
			return err
		}
		rec.Effect(store.AuditEffect{
			ResourceType:  "user",
			ResourceID:    userID,
			Action:        "SET_PROVISIONING",
			Outcome:       store.EffectApplied,
			ChangedFields: []string{"user_provisioning_enabled"},
			AfterFlag:     &yes,
		})
	}
	if settings.SshAccessForAll {
		if _, err := tx.UpdateUserSshSettings(ctx, db.UpdateUserSshSettingsParams{
			ID:               userID,
			SshAccessEnabled: true,
			SshAllowPubkey:   true,
			SshAllowPassword: false,
			UpdatedAt:        &at,
		}); err != nil {
			return err
		}
		rec.Effect(store.AuditEffect{
			ResourceType:  "user",
			ResourceID:    userID,
			Action:        "SET_SSH_SETTINGS",
			Outcome:       store.EffectApplied,
			ChangedFields: []string{"ssh_access_enabled", "ssh_allow_pubkey", "ssh_allow_password"},
			AfterFlag:     &yes,
		})
	}
	return nil
}

type bindingSpec struct {
	LinkID      string
	UserID      string
	ExternalID  string
	Email       string
	DisplayName string
	At          time.Time
}

func (h *Handler) insertBinding(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder, s *session, spec bindingSpec) error {
	if _, err := tx.InsertIdentityLink(ctx, db.InsertIdentityLinkParams{
		ID:            spec.LinkID,
		UserID:        spec.UserID,
		ProviderID:    s.provider.ID,
		ExternalID:    spec.ExternalID,
		ExternalEmail: spec.Email,
		ExternalName:  spec.DisplayName,
		LinkedAt:      spec.At,
	}); err != nil {
		return err
	}
	rec.Effect(store.AuditEffect{
		ResourceType:        "identity_link",
		ResourceID:          spec.LinkID,
		Action:              "LINK",
		Outcome:             store.EffectApplied,
		BeforeRef:           &s.provider.ID,
		AfterRef:            &spec.UserID,
		EvidenceKind:        "external_subject_sha256",
		EvidenceFingerprint: fingerprint(spec.ExternalID),
	})
	return nil
}

// ---------------------------------------------------------------------------
// Replace and patch
// ---------------------------------------------------------------------------

// replaceUser handles PUT /Users/{id}.
func (h *Handler) replaceUser(w http.ResponseWriter, r *http.Request, s *session) {
	ctx := r.Context()
	_, before, ok := h.resolveSubject(ctx, w, s, r.PathValue("id"))
	if !ok {
		return
	}
	var resource SCIMUser
	if !decodeBody(w, r, &resource) {
		return
	}
	h.syncSubject(w, r, s, before, resource.ExternalID, assertionFromResource(resource),
		baseURLFromRequest(r, s.provider.Slug), http.StatusOK)
}

// patchUser handles PATCH /Users/{id}.
//
// Every operation in the request is folded into ONE assertion and
// applied in ONE transaction, so a request that changes several
// attributes cannot be observed half-applied.
func (h *Handler) patchUser(w http.ResponseWriter, r *http.Request, s *session) {
	ctx := r.Context()
	_, before, ok := h.resolveSubject(ctx, w, s, r.PathValue("id"))
	if !ok {
		return
	}
	var patch SCIMPatchRequest
	if !decodeBody(w, r, &patch) {
		return
	}

	var assertion subjectAssertion
	for _, op := range patch.Operations {
		// RFC 7644 §3.5.2 defines exactly three verbs. An unknown one
		// is a malformed request; add and remove are valid verbs this
		// resource does not implement, and both are refused rather than
		// accepted and quietly dropped.
		if !op.Op.IsValid() {
			writeError(w, http.StatusBadRequest, "unsupported patch op")
			return
		}
		if op.Op.Normalize() != SCIMPatchOpReplace {
			writeError(w, http.StatusBadRequest, "only the replace op is supported on a user")
			return
		}
		if err := applyUserPatchOp(&assertion, op); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	h.syncSubject(w, r, s, before, "", assertion, baseURLFromRequest(r, s.provider.Slug), http.StatusOK)
}

// syncSubject applies an assertion to a subject and answers with the
// committed state.
//
// Everything the assertion changed, plus the refreshed binding, lands in
// one transaction with one audit operation.
func (h *Handler) syncSubject(
	w http.ResponseWriter,
	r *http.Request,
	s *session,
	before store.UserRow,
	externalID string,
	assertion subjectAssertion,
	baseURL string,
	okStatus int,
) {
	ctx := r.Context()
	at := h.now().UTC()

	_, err := h.store.WithAudit(ctx, h.mutationOp(s), func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		if err := h.applyAssertion(ctx, tx, rec, before, assertion, at); err != nil {
			return err
		}
		if err := h.refreshBinding(ctx, tx, rec, s, before.ID, externalID, assertion); err != nil {
			return err
		}
		return noChangeIfNothingRecorded(rec)
	})
	if err != nil && !errors.Is(err, errNoChange) {
		if store.IsConflict(err) {
			writeError(w, http.StatusConflict, "a user with that address already exists")
			return
		}
		if store.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		h.logger.Error("scim: failed to apply the directory assertion", "route", s.descriptor, "error", err)
		writeError(w, http.StatusInternalServerError, "failed to update user")
		return
	}

	// Re-read so the directory sees committed state rather than what
	// the handler believed it wrote.
	after, err := h.store.GetUser(ctx, before.ID)
	if err != nil {
		h.logger.Error("scim: failed to read back the subject", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to read user")
		return
	}
	link, err := h.store.GetIdentityLinkByProviderAndUser(ctx, s.provider.ID, before.ID)
	if err != nil {
		h.logger.Error("scim: failed to read back the binding", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to read user")
		return
	}
	writeJSON(w, okStatus, userResource(after, link.ExternalID, baseURL))
}

// applyAssertion writes the asserted subject fields. Each statement runs
// only when the assertion actually changes something, so a directory's
// idle sync cycle does not fill the log with no-op effects.
func (h *Handler) applyAssertion(
	ctx context.Context,
	tx *store.Tx,
	rec *store.AuditRecorder,
	before store.UserRow,
	a subjectAssertion,
	at time.Time,
) error {
	if a.Email != nil && *a.Email != "" && *a.Email != before.Email {
		n, err := tx.UpdateUserEmail(ctx, db.UpdateUserEmailParams{
			ID: before.ID, Email: *a.Email, UpdatedAt: &at,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return store.ErrNotFound
		}
		// Both addresses are the evidence and both are personal data,
		// so the readable form is sealed under the subject's own key.
		sealed, err := h.sealTransition(ctx, tx, before.ID, "email", before.Email, *a.Email)
		if err != nil {
			return err
		}
		rec.Effect(store.AuditEffect{
			ResourceType:        "user",
			ResourceID:          before.ID,
			Action:              "UPDATE_EMAIL",
			Outcome:             store.EffectApplied,
			ChangedFields:       []string{"email"},
			EvidenceKind:        "email_sha256",
			EvidenceFingerprint: fingerprint(*a.Email),
			SealedDetail:        sealed,
			SealedDetailSubject: before.ID,
		})
	}

	if a.Active != nil {
		disabled := !*a.Active
		if disabled != before.Disabled {
			// The statement bumps session_version in the same write, so
			// every session issued under the previous state stops
			// validating at once.
			if _, err := tx.SetUserDisabled(ctx, db.SetUserDisabledParams{
				ID: before.ID, Disabled: disabled, UpdatedAt: &at,
			}); err != nil {
				return err
			}
			wasDisabled := before.Disabled
			rec.Effect(store.AuditEffect{
				ResourceType:  "user",
				ResourceID:    before.ID,
				Action:        "SET_DISABLED",
				Outcome:       store.EffectApplied,
				ChangedFields: []string{"disabled", "session_version"},
				BeforeFlag:    &wasDisabled,
				AfterFlag:     &disabled,
			})
		}
	}

	if a.assertsProfile() {
		// The statement rewrites every profile column, so the ones the
		// directory did not assert are carried over from the row rather
		// than cleared as a side effect.
		if _, err := tx.UpdateUserProfile(ctx, db.UpdateUserProfileParams{
			ID:                before.ID,
			DisplayName:       valueOr(a.DisplayName, before.DisplayName),
			GivenName:         valueOr(a.GivenName, before.GivenName),
			FamilyName:        valueOr(a.FamilyName, before.FamilyName),
			PreferredUsername: before.PreferredUsername,
			Picture:           before.Picture,
			Locale:            before.Locale,
			UpdatedAt:         &at,
		}); err != nil {
			return err
		}
		rec.Effect(store.AuditEffect{
			ResourceType:  "user",
			ResourceID:    before.ID,
			Action:        "UPDATE_PROFILE",
			Outcome:       store.EffectApplied,
			ChangedFields: []string{"display_name", "given_name", "family_name"},
		})
	}
	return nil
}

// refreshBinding writes the directory's current view of the subject onto
// the binding, and only when that view differs from what the binding
// already holds.
//
// The external identifier is only overwritten when the directory
// asserted one: a sync keyed on the address must not blank the
// identifier the subject was originally bound under.
func (h *Handler) refreshBinding(
	ctx context.Context,
	tx *store.Tx,
	rec *store.AuditRecorder,
	s *session,
	userID, externalID string,
	a subjectAssertion,
) error {
	link, err := tx.GetIdentityLinkByProviderAndUser(ctx, db.GetIdentityLinkByProviderAndUserParams{
		ProviderID: s.provider.ID,
		UserID:     userID,
	})
	if err != nil {
		return err
	}
	if externalID == "" {
		externalID = link.ExternalID
	}
	email := link.ExternalEmail
	if a.Email != nil && *a.Email != "" {
		email = *a.Email
	}
	name := link.ExternalName
	if a.assertsProfile() {
		name = valueOr(a.DisplayName, "")
	}

	if externalID == link.ExternalID && email == link.ExternalEmail && name == link.ExternalName {
		return nil
	}

	updated, err := tx.UpdateIdentityLinkExternalIdentity(ctx, db.UpdateIdentityLinkExternalIdentityParams{
		ID:            link.ID,
		ExternalID:    externalID,
		ExternalEmail: email,
		ExternalName:  name,
	})
	if err != nil {
		return err
	}
	rec.Effect(store.AuditEffect{
		ResourceType:        "identity_link",
		ResourceID:          updated.ID,
		Action:              "SYNC_LINK",
		Outcome:             store.EffectApplied,
		ChangedFields:       []string{"external_id", "external_email", "external_name"},
		BeforeRef:           &s.provider.ID,
		AfterRef:            &userID,
		EvidenceKind:        "external_subject_sha256",
		EvidenceFingerprint: fingerprint(updated.ExternalID),
	})
	return nil
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

// deleteUser handles DELETE /Users/{id}.
//
// It removes THIS directory's binding. Only when that was the subject's
// last binding is the subject erased: another directory may still
// provision them, and destroying the account because one directory
// stopped listing it would be a deletion nobody asked for.
func (h *Handler) deleteUser(w http.ResponseWriter, r *http.Request, s *session) {
	ctx := r.Context()
	link, before, ok := h.resolveSubject(ctx, w, s, r.PathValue("id"))
	if !ok {
		return
	}

	_, err := h.store.WithAudit(ctx, h.mutationOp(s), func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		removed, err := tx.DeleteIdentityLink(ctx, link.ID)
		if err != nil {
			return err
		}
		rec.Effect(store.AuditEffect{
			ResourceType:        "identity_link",
			ResourceID:          removed.ID,
			Action:              "UNLINK",
			Outcome:             store.EffectApplied,
			BeforeRef:           &removed.UserID,
			AfterRef:            &removed.ProviderID,
			EvidenceKind:        "external_subject_sha256",
			EvidenceFingerprint: fingerprint(removed.ExternalID),
		})

		remaining, err := tx.CountIdentityLinksForUser(ctx, before.ID)
		if err != nil {
			return err
		}
		if remaining > 0 {
			return nil
		}
		return h.eraseSubject(ctx, tx, rec, before)
	})
	if err != nil {
		h.logger.Error("scim: failed to remove the subject binding", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to delete user")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// eraseSubject erases a subject the way the identity surface does: the
// row, their group memberships, their role grants and finally their
// data-encryption key, all in the caller's transaction. Destroying the
// key is what makes every class-three detail ever sealed for them
// permanently unreadable, in live rows, archives and backups at once.
//
// The record therefore carries NO class-three detail of its own: it
// would be sealed under a key this very transaction destroys, and would
// be born unreadable. References and a non-reversible digest are the
// non-personal attribution that must survive.
func (h *Handler) eraseSubject(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder, before store.UserRow) error {
	memberships, err := tx.DeleteUserGroupMembershipsForUser(ctx, before.ID)
	if err != nil {
		return err
	}
	grants, err := tx.DeleteUserRoleGrantsForUser(ctx, before.ID)
	if err != nil {
		return err
	}
	if _, err := tx.DeleteUser(ctx, before.ID); err != nil {
		return err
	}
	keys, err := tx.DeleteUserEncryptionKey(ctx, before.ID)
	if err != nil {
		return err
	}

	rec.Effect(store.AuditEffect{
		ResourceType:        "user",
		ResourceID:          before.ID,
		Action:              "ERASE",
		Outcome:             store.EffectApplied,
		ChangedFields:       []string{"email", "display_name", "linux_username"},
		EvidenceKind:        "email_sha256",
		EvidenceFingerprint: fingerprint(before.Email),
	})
	rec.Effect(store.AuditEffect{
		ResourceType: "user_group_member",
		ResourceID:   before.ID,
		Action:       "ERASE_MEMBERSHIPS",
		Outcome:      store.EffectApplied,
		BeforeCount:  &memberships,
	})
	rec.Effect(store.AuditEffect{
		ResourceType: "user_role",
		ResourceID:   before.ID,
		Action:       "ERASE_GRANTS",
		Outcome:      store.EffectApplied,
		BeforeCount:  &grants,
	})
	rec.Effect(store.AuditEffect{
		ResourceType: "user_encryption_key",
		ResourceID:   before.ID,
		Action:       "DESTROY_KEY",
		Outcome:      store.EffectApplied,
		BeforeCount:  &keys,
	})
	return nil
}

// ---------------------------------------------------------------------------
// Subject keys
// ---------------------------------------------------------------------------

// mintSubjectDEK creates a subject's data-encryption key inside the
// caller's transaction and returns the wrapped form.
//
// The insert is first-write-wins: a key that already exists is kept,
// because replacing one would irreversibly erase everything already
// sealed under it. The wrapped value is read back so the caller seals
// against whichever key actually survived.
func (h *Handler) mintSubjectDEK(ctx context.Context, tx *store.Tx, subjectID string) (string, error) {
	wrapped, err := crypto.GenerateWrappedDEK(h.kek, subjectID)
	if err != nil {
		return "", err
	}
	if _, err := tx.InsertUserEncryptionKey(ctx, db.InsertUserEncryptionKeyParams{
		UserID:     subjectID,
		WrappedDek: wrapped,
	}); err != nil {
		return "", err
	}
	row, err := tx.GetUserEncryptionKey(ctx, subjectID)
	if err != nil {
		return "", err
	}
	return row.WrappedDek, nil
}

// sealForSubject seals a value under a subject's own key, producing
// class-three audit detail: evidence that is only meaningful as its
// value, readable only while the subject's key exists.
func (h *Handler) sealForSubject(subjectID, wrappedDEK, field, value string) ([]byte, error) {
	dek, err := crypto.UnwrapDEK(h.kek, subjectID, wrappedDEK)
	if err != nil {
		return nil, err
	}
	sealed, err := dek.SealField(value, field)
	if err != nil {
		return nil, err
	}
	return []byte(sealed), nil
}

// sealTransition seals a before/after pair.
//
// The key is read INSIDE the caller's transaction: a subject erased
// concurrently would leave no key, and the seal must fail rather than
// silently fall back to recording the values in a readable form.
func (h *Handler) sealTransition(ctx context.Context, tx *store.Tx, subjectID, field, before, after string) ([]byte, error) {
	key, err := tx.GetUserEncryptionKey(ctx, subjectID)
	if err != nil {
		return nil, err
	}
	return h.sealForSubject(subjectID, key.WrappedDek, field, before+" -> "+after)
}

// ---------------------------------------------------------------------------
// Body and value helpers
// ---------------------------------------------------------------------------

// decodeBody reads a size-limited JSON body. A body that does not parse
// is the client's mistake and is reported as one.
func decodeBody(w http.ResponseWriter, r *http.Request, into any) bool {
	limitBody(w, r)
	if err := json.NewDecoder(r.Body).Decode(into); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

func valueOr(v *string, fallback string) string {
	if v == nil {
		return fallback
	}
	return *v
}

func nameField(name *SCIMName, pick func(*SCIMName) string) string {
	if name == nil {
		return ""
	}
	return pick(name)
}
