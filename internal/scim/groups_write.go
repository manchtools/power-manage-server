package scim

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// groupAssertion is what a directory said one of its groups should look
// like. A nil Members means the field was absent — the current set is
// left alone — while an empty non-nil slice is the assertion that the
// group has no members.
type groupAssertion struct {
	DisplayName string
	Members     []string
	// MembersAsserted distinguishes "no members field" from "an empty
	// members field".
	MembersAsserted bool
}

func assertionFromGroup(g SCIMGroup) groupAssertion {
	a := groupAssertion{DisplayName: g.DisplayName}
	if g.Members != nil {
		a.MembersAsserted = true
		a.Members = make([]string, 0, len(g.Members))
		for _, m := range g.Members {
			if m.Value != "" {
				a.Members = append(a.Members, m.Value)
			}
		}
	}
	return a
}

// createGroup handles POST /Groups.
//
// A directory re-asserts its whole group set on every sync cycle, so a
// POST for a group it has already mapped is a sync and answers 200.
func (h *Handler) createGroup(w http.ResponseWriter, r *http.Request, s *session) {
	ctx := r.Context()
	var resource SCIMGroup
	if !decodeBody(w, r, &resource) {
		return
	}
	if resource.DisplayName == "" {
		writeError(w, http.StatusBadRequest, "displayName is required")
		return
	}
	baseURL := baseURLFromRequest(r, s.provider.Slug)
	assertion := assertionFromGroup(resource)

	// The directory's own identifier for the group. Some directories
	// send it as externalId, some as id, and some send neither on the
	// first sync — in which case one is minted so the mapping has a
	// stable key to be found by next time.
	scimGroupID := resource.ExternalID
	if scimGroupID == "" {
		scimGroupID = resource.ID
	}
	if scimGroupID == "" {
		scimGroupID = ulid.Make().String()
	}

	existing, err := h.store.GetSCIMGroupMapping(ctx, s.provider.ID, scimGroupID)
	switch {
	case err == nil:
		if _, groupErr := h.store.GetUserGroup(ctx, existing.UserGroupID); groupErr == nil {
			h.syncGroup(w, r, s, existing, assertion, baseURL, http.StatusOK)
			return
		} else if !store.IsNotFound(groupErr) {
			h.logger.Error("scim: failed to resolve the mapped group", "error", groupErr)
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}
		// The mapping points at a group that has been retired outside
		// this surface. Replacing the pair is what lets the directory's
		// next sync recover; leaving the stale mapping in place would
		// make the group permanently unreachable under its own
		// identifier.
		h.provisionGroup(w, r, s, scimGroupID, assertion, baseURL, &existing)
	case store.IsNotFound(err):
		h.provisionGroup(w, r, s, scimGroupID, assertion, baseURL, nil)
	default:
		h.logger.Error("scim: failed to resolve the group mapping", "error", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
	}
}

// provisionGroup creates the local group, its mapping and its
// membership as one unit. When stale is set, its mapping is removed in
// the same transaction, so one directory identifier never has two
// mappings.
func (h *Handler) provisionGroup(
	w http.ResponseWriter,
	r *http.Request,
	s *session,
	scimGroupID string,
	a groupAssertion,
	baseURL string,
	stale *store.SCIMGroupMappingRow,
) {
	ctx := r.Context()
	groupID := ulid.Make().String()
	mappingID := ulid.Make().String()
	at := h.now().UTC()

	_, err := h.store.WithAudit(ctx, h.mutationOp(s), func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		if stale != nil {
			removed, err := tx.DeleteSCIMGroupMapping(ctx, stale.ID)
			if err != nil {
				return err
			}
			rec.Effect(store.AuditEffect{
				ResourceType: "scim_group_mapping",
				ResourceID:   removed.ID,
				Action:       "UNMAP",
				Outcome:      store.EffectApplied,
				BeforeRef:    &removed.UserGroupID,
				AfterRef:     &s.provider.ID,
			})
		}

		if _, err := tx.InsertUserGroup(ctx, db.InsertUserGroupParams{
			ID:          groupID,
			Name:        a.DisplayName,
			Description: "provisioned by the " + s.provider.Slug + " directory",
			CreatedAt:   at,
			CreatedBy:   actorSCIM,
		}); err != nil {
			return err
		}
		rec.Effect(store.AuditEffect{
			ResourceType:  "user_group",
			ResourceID:    groupID,
			Action:        "CREATE",
			Outcome:       store.EffectApplied,
			ChangedFields: []string{"name", "description"},
			AfterRef:      &s.provider.ID,
		})

		if _, err := tx.InsertSCIMGroupMapping(ctx, db.InsertSCIMGroupMappingParams{
			ID:              mappingID,
			ProviderID:      s.provider.ID,
			ScimGroupID:     scimGroupID,
			ScimDisplayName: a.DisplayName,
			UserGroupID:     groupID,
			CreatedAt:       at,
		}); err != nil {
			return err
		}
		rec.Effect(store.AuditEffect{
			ResourceType:        "scim_group_mapping",
			ResourceID:          mappingID,
			Action:              "MAP",
			Outcome:             store.EffectApplied,
			ChangedFields:       []string{"scim_group_id", "scim_display_name", "user_group_id"},
			BeforeRef:           &s.provider.ID,
			AfterRef:            &groupID,
			EvidenceKind:        "external_group_sha256",
			EvidenceFingerprint: fingerprint(scimGroupID),
		})

		if !a.MembersAsserted {
			return nil
		}
		return h.reconcileMembers(ctx, tx, rec, s, groupID, a.Members, at)
	})
	if err != nil {
		if store.IsConflict(err) {
			writeError(w, http.StatusConflict, "a group with that name already exists")
			return
		}
		h.logger.Error("scim: failed to provision the group", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to create group")
		return
	}

	mapping, err := h.store.GetSCIMGroupMapping(ctx, s.provider.ID, scimGroupID)
	if err != nil {
		h.logger.Error("scim: failed to read back the group mapping", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to read group")
		return
	}
	h.writeGroup(ctx, w, mapping, baseURL, http.StatusCreated)
}

// replaceGroup handles PUT /Groups/{id}.
func (h *Handler) replaceGroup(w http.ResponseWriter, r *http.Request, s *session) {
	ctx := r.Context()
	mapping, ok := h.resolveGroup(ctx, w, s, r.PathValue("id"))
	if !ok {
		return
	}
	if _, err := h.store.GetUserGroup(ctx, mapping.UserGroupID); err != nil {
		if store.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "group not found")
			return
		}
		h.logger.Error("scim: failed to load the mapped group", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get group")
		return
	}
	var resource SCIMGroup
	if !decodeBody(w, r, &resource) {
		return
	}
	h.syncGroup(w, r, s, mapping, assertionFromGroup(resource),
		baseURLFromRequest(r, s.provider.Slug), http.StatusOK)
}

// patchGroup handles PATCH /Groups/{id}.
//
// Every operation in the request is applied in ONE transaction, so a
// request that renames a group and moves members cannot be observed
// half-applied.
func (h *Handler) patchGroup(w http.ResponseWriter, r *http.Request, s *session) {
	ctx := r.Context()
	mapping, ok := h.resolveGroup(ctx, w, s, r.PathValue("id"))
	if !ok {
		return
	}
	group, err := h.store.GetUserGroup(ctx, mapping.UserGroupID)
	if err != nil {
		if store.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "group not found")
			return
		}
		h.logger.Error("scim: failed to load the mapped group", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get group")
		return
	}
	var patch SCIMPatchRequest
	if !decodeBody(w, r, &patch) {
		return
	}
	for _, op := range patch.Operations {
		// RFC 7644 §3.5.2 defines exactly three verbs; an unknown one is
		// a malformed request rather than a silent no-op.
		if !op.Op.IsValid() {
			writeError(w, http.StatusBadRequest, "unsupported patch op")
			return
		}
	}

	baseURL := baseURLFromRequest(r, s.provider.Slug)
	at := h.now().UTC()

	_, err = h.store.WithAudit(ctx, h.mutationOp(s), func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		for _, op := range patch.Operations {
			if err := h.applyGroupPatchOp(ctx, tx, rec, s, mapping, group, op, at); err != nil {
				return err
			}
		}
		return noChangeIfNothingRecorded(rec)
	})
	if err != nil && !errors.Is(err, errNoChange) {
		h.logger.Error("scim: failed to apply the group patch", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to apply patch operation")
		return
	}
	h.writeGroup(ctx, w, mapping, baseURL, http.StatusOK)
}

// applyGroupPatchOp applies one operation to the group.
func (h *Handler) applyGroupPatchOp(
	ctx context.Context,
	tx *store.Tx,
	rec *store.AuditRecorder,
	s *session,
	mapping store.SCIMGroupMappingRow,
	group store.UserGroupRow,
	op SCIMPatchOp,
	at time.Time,
) error {
	path := strings.ToLower(strings.TrimSpace(op.Path))

	switch op.Op.Normalize() {
	case SCIMPatchOpAdd:
		if path != "members" && path != "" {
			return nil
		}
		for _, userID := range patchMemberIDs(op.Value) {
			if err := h.addMember(ctx, tx, rec, s, mapping.UserGroupID, userID, at); err != nil {
				return err
			}
		}

	case SCIMPatchOpRemove:
		// A remove addresses either one member through a value filter,
		// or a list in the value. Removing a member the directory does
		// not own is harmless — it only ever removes what is already
		// there — so the ownership guard applies to adds only.
		if strings.HasPrefix(path, "members[") {
			if userID := memberIDFromFilter(op.Path); userID != "" {
				return h.removeMember(ctx, tx, rec, mapping.UserGroupID, userID, at)
			}
			return nil
		}
		if path != "members" && path != "" {
			return nil
		}
		for _, userID := range patchMemberIDs(op.Value) {
			if err := h.removeMember(ctx, tx, rec, mapping.UserGroupID, userID, at); err != nil {
				return err
			}
		}

	case SCIMPatchOpReplace:
		switch path {
		case "displayname":
			name, ok := op.Value.(string)
			if !ok || name == "" {
				return nil
			}
			return h.renameGroup(ctx, tx, rec, s, mapping, group, name, at)
		case "members":
			return h.reconcileMembers(ctx, tx, rec, s, mapping.UserGroupID, patchMemberIDs(op.Value), at)
		}
	}
	return nil
}

// syncGroup applies a whole-resource assertion to an already-mapped
// group.
func (h *Handler) syncGroup(
	w http.ResponseWriter,
	r *http.Request,
	s *session,
	mapping store.SCIMGroupMappingRow,
	a groupAssertion,
	baseURL string,
	okStatus int,
) {
	ctx := r.Context()
	at := h.now().UTC()

	_, err := h.store.WithAudit(ctx, h.mutationOp(s), func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		group, err := tx.GetUserGroup(ctx, mapping.UserGroupID)
		if err != nil {
			return err
		}
		if a.DisplayName != "" && a.DisplayName != mapping.ScimDisplayName {
			if err := h.renameGroup(ctx, tx, rec, s, mapping, group, a.DisplayName, at); err != nil {
				return err
			}
		}
		if a.MembersAsserted {
			if err := h.reconcileMembers(ctx, tx, rec, s, mapping.UserGroupID, a.Members, at); err != nil {
				return err
			}
		}
		return noChangeIfNothingRecorded(rec)
	})
	if err != nil && !errors.Is(err, errNoChange) {
		if store.IsConflict(err) {
			writeError(w, http.StatusConflict, "a group with that name already exists")
			return
		}
		if store.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "group not found")
			return
		}
		h.logger.Error("scim: failed to apply the group assertion", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to update group")
		return
	}
	h.writeGroup(ctx, w, mapping, baseURL, okStatus)
}

// deleteGroup handles DELETE /Groups/{id}.
//
// It removes the MAPPING only. The local group may carry role grants an
// operator configured, and destroying it because a directory stopped
// listing the group would silently withdraw authority nobody asked to
// withdraw.
func (h *Handler) deleteGroup(w http.ResponseWriter, r *http.Request, s *session) {
	ctx := r.Context()
	mapping, ok := h.resolveGroup(ctx, w, s, r.PathValue("id"))
	if !ok {
		return
	}

	_, err := h.store.WithAudit(ctx, h.mutationOp(s), func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		removed, err := tx.DeleteSCIMGroupMapping(ctx, mapping.ID)
		if err != nil {
			return err
		}
		rec.Effect(store.AuditEffect{
			ResourceType:        "scim_group_mapping",
			ResourceID:          removed.ID,
			Action:              "UNMAP",
			Outcome:             store.EffectApplied,
			BeforeRef:           &removed.UserGroupID,
			AfterRef:            &s.provider.ID,
			EvidenceKind:        "external_group_sha256",
			EvidenceFingerprint: fingerprint(removed.ScimGroupID),
		})
		return nil
	})
	if err != nil {
		h.logger.Error("scim: failed to unmap the group", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to delete group mapping")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Membership
// ---------------------------------------------------------------------------

// reconcileMembers makes the group's membership equal the asserted set.
// The directory is the source of truth for its own groups, so a member
// removed outside this surface is re-added and one the directory
// dropped is removed.
func (h *Handler) reconcileMembers(
	ctx context.Context,
	tx *store.Tx,
	rec *store.AuditRecorder,
	s *session,
	groupID string,
	requested []string,
	at time.Time,
) error {
	current, err := tx.ListUserGroupMemberIDs(ctx, groupID)
	if err != nil {
		return err
	}
	currentSet := make(map[string]bool, len(current))
	for _, id := range current {
		currentSet[id] = true
	}
	requestedSet := make(map[string]bool, len(requested))
	for _, id := range requested {
		requestedSet[id] = true
	}

	// Iterate the request in order so two runs over the same assertion
	// produce the same effect sequence.
	for _, userID := range requested {
		if currentSet[userID] {
			continue
		}
		if err := h.addMember(ctx, tx, rec, s, groupID, userID, at); err != nil {
			return err
		}
	}
	for _, userID := range current {
		if requestedSet[userID] {
			continue
		}
		if err := h.removeMember(ctx, tx, rec, groupID, userID, at); err != nil {
			return err
		}
	}
	return nil
}

// addMember joins a subject to a group.
//
// Membership confers the group's role grants, so a directory may only
// add subjects it is itself bound to: adding somebody else's subject
// would let one directory grant authority to another's account. An
// unowned subject is skipped rather than refused, which keeps the
// member set idempotent the way SCIM expects.
func (h *Handler) addMember(
	ctx context.Context,
	tx *store.Tx,
	rec *store.AuditRecorder,
	s *session,
	groupID, userID string,
	at time.Time,
) error {
	if _, err := tx.GetIdentityLinkByProviderAndUser(ctx, db.GetIdentityLinkByProviderAndUserParams{
		ProviderID: s.provider.ID,
		UserID:     userID,
	}); err != nil {
		if store.IsNotFound(err) {
			h.logger.Warn("scim: skipping a member the directory does not provision", "group_id", groupID)
			return nil
		}
		return err
	}

	n, err := tx.InsertUserGroupMember(ctx, db.InsertUserGroupMemberParams{
		GroupID: groupID,
		UserID:  userID,
		AddedAt: at,
		AddedBy: actorSCIM,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		// Already a member. Re-asserting a membership is not a fresh
		// grant and must not look like one in the record.
		return nil
	}
	rec.Effect(store.AuditEffect{
		ResourceType: "user_group_member",
		ResourceID:   groupID,
		Action:       "JOIN",
		Outcome:      store.EffectApplied,
		AfterRef:     &userID,
	})
	return h.invalidateSubjectSessions(ctx, tx, rec, userID, at)
}

// removeMember withdraws a subject from a group.
func (h *Handler) removeMember(
	ctx context.Context,
	tx *store.Tx,
	rec *store.AuditRecorder,
	groupID, userID string,
	at time.Time,
) error {
	n, err := tx.DeleteUserGroupMember(ctx, db.DeleteUserGroupMemberParams{
		GroupID: groupID,
		UserID:  userID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	rec.Effect(store.AuditEffect{
		ResourceType: "user_group_member",
		ResourceID:   groupID,
		Action:       "LEAVE",
		Outcome:      store.EffectApplied,
		BeforeRef:    &userID,
	})
	return h.invalidateSubjectSessions(ctx, tx, rec, userID, at)
}

// invalidateSubjectSessions bumps a subject's session version. A
// membership change is a change to what the subject may do, so the
// sessions minted under the previous authority stop validating.
func (h *Handler) invalidateSubjectSessions(
	ctx context.Context,
	tx *store.Tx,
	rec *store.AuditRecorder,
	userID string,
	at time.Time,
) error {
	version, err := tx.BumpUserSessionVersion(ctx, db.BumpUserSessionVersionParams{ID: userID, UpdatedAt: &at})
	if err != nil {
		if store.IsNotFound(err) {
			return nil
		}
		return err
	}
	after := int64(version)
	rec.Effect(store.AuditEffect{
		ResourceType:  "user",
		ResourceID:    userID,
		Action:        "INVALIDATE_SESSIONS",
		Outcome:       store.EffectApplied,
		ChangedFields: []string{"session_version"},
		AfterCount:    &after,
	})
	return nil
}

// renameGroup renames the mapping and the local group together.
//
// The change guard reads the MAPPING's name, so a rename that reached
// only one of the two rows would let the next sync see equal names,
// skip, and leave the local group's name wrong forever. One transaction
// makes both land or neither.
func (h *Handler) renameGroup(
	ctx context.Context,
	tx *store.Tx,
	rec *store.AuditRecorder,
	s *session,
	mapping store.SCIMGroupMappingRow,
	group store.UserGroupRow,
	name string,
	at time.Time,
) error {
	if name == mapping.ScimDisplayName && name == group.Name {
		return nil
	}
	if _, err := tx.UpdateSCIMGroupMappingDisplayName(ctx, db.UpdateSCIMGroupMappingDisplayNameParams{
		ProviderID:      s.provider.ID,
		ScimGroupID:     mapping.ScimGroupID,
		ScimDisplayName: name,
	}); err != nil {
		return err
	}
	if _, err := tx.UpdateUserGroupName(ctx, db.UpdateUserGroupNameParams{
		ID:        mapping.UserGroupID,
		Name:      name,
		UpdatedAt: at,
	}); err != nil {
		return err
	}
	rec.Effect(store.AuditEffect{
		ResourceType:  "scim_group_mapping",
		ResourceID:    mapping.ID,
		Action:        "RENAME",
		Outcome:       store.EffectApplied,
		ChangedFields: []string{"scim_display_name"},
		BeforeRef:     &mapping.UserGroupID,
		AfterRef:      &s.provider.ID,
	})
	rec.Effect(store.AuditEffect{
		ResourceType:  "user_group",
		ResourceID:    mapping.UserGroupID,
		Action:        "RENAME",
		Outcome:       store.EffectApplied,
		ChangedFields: []string{"name"},
		AfterRef:      &s.provider.ID,
	})
	return nil
}

// ---------------------------------------------------------------------------
// Response and value helpers
// ---------------------------------------------------------------------------

// writeGroup answers with the group as committed: the local group and
// its membership are re-read rather than reconstructed from what the
// handler believed it wrote.
func (h *Handler) writeGroup(ctx context.Context, w http.ResponseWriter, mapping store.SCIMGroupMappingRow, baseURL string, status int) {
	resource, err := h.groupResource(ctx, mapping, baseURL)
	if err != nil {
		if store.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "group not found")
			return
		}
		h.logger.Error("scim: failed to build the group resource", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to read group")
		return
	}
	writeJSON(w, status, resource)
}

// patchMemberIDs reads member ids out of a patch value, which a
// directory may send as a single member object or as an array of them.
func patchMemberIDs(value any) []string {
	var out []string
	switch v := value.(type) {
	case []any:
		for _, item := range v {
			entry, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if id, ok := entry["value"].(string); ok && id != "" {
				out = append(out, id)
			}
		}
	case map[string]any:
		if id, ok := v["value"].(string); ok && id != "" {
			out = append(out, id)
		}
	}
	return out
}

// memberIDFromFilter reads the subject id out of a member value filter
// such as `members[value eq "01J..."]`.
//
// The structural parts are matched case-insensitively because
// directories vary; the id itself keeps its case, since a ULID is
// case-sensitive as stored.
func memberIDFromFilter(path string) string {
	lower := strings.ToLower(path)
	if !strings.HasPrefix(lower, "members[") {
		return ""
	}
	inner := strings.TrimSuffix(path[len("members["):], "]")
	idx := strings.Index(strings.ToLower(inner), " eq ")
	if idx < 0 {
		return ""
	}
	return strings.Trim(strings.TrimSpace(inner[idx+len(" eq "):]), `"`)
}
