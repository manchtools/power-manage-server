package scim

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/manchtools/power-manage/server/internal/store"
)

// Reading the population a directory provisioned is a bulk read of
// personal data, so it is recorded under the sensitive-read class
// rather than left unaudited.

const (
	defaultPageSize = 100
	maxPageSize     = 200
)

// listUsers handles GET /Users.
func (h *Handler) listUsers(w http.ResponseWriter, r *http.Request, s *session) {
	ctx := r.Context()
	baseURL := baseURLFromRequest(r, s.provider.Slug)
	startIndex, count := pageWindow(r)

	if expr := r.URL.Query().Get("filter"); expr != "" {
		h.listUsersFiltered(w, r, s, expr, startIndex, baseURL)
		return
	}

	total, err := h.store.CountSCIMUsers(ctx, s.provider.ID)
	if err != nil {
		h.logger.Error("scim: failed to count users", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to count users")
		return
	}
	rows, err := h.store.ListSCIMUsers(ctx, s.provider.ID, int32(count), int32(startIndex-1))
	if err != nil {
		h.logger.Error("scim: failed to list users", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to list users")
		return
	}

	resources := make([]any, len(rows))
	for i, row := range rows {
		resources[i] = userResource(row.User, row.ExternalID, baseURL)
	}
	if !h.recordListRead(ctx, w, s, "LIST_USERS", int64(len(rows))) {
		return
	}
	writeJSON(w, http.StatusOK, SCIMListResponse{
		Schemas:      []string{ListResponseSchema},
		TotalResults: int(total),
		StartIndex:   startIndex,
		ItemsPerPage: len(rows),
		Resources:    resources,
	})
}

// listUsersFiltered answers the equality filters a directory uses to
// find out whether it has already provisioned somebody.
func (h *Handler) listUsersFiltered(w http.ResponseWriter, r *http.Request, s *session, expr string, startIndex int, baseURL string) {
	ctx := r.Context()
	f, err := parseFilter(expr)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid filter: %s", err))
		return
	}

	var (
		row     store.SCIMUserRow
		findErr error
	)
	switch f.Attribute {
	case "userName":
		row, findErr = h.store.FindSCIMUserByEmail(ctx, s.provider.ID, normalizeEmail(f.Value))
	case "externalId":
		row, findErr = h.store.FindSCIMUserByExternalID(ctx, s.provider.ID, f.Value)
	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported filter attribute: %s", f.Attribute))
		return
	}

	resources := []any{}
	switch {
	case findErr == nil:
		resources = append(resources, userResource(row.User, row.ExternalID, baseURL))
	case !store.IsNotFound(findErr):
		h.logger.Error("scim: failed to search users", "error", findErr)
		writeError(w, http.StatusInternalServerError, "failed to search users")
		return
	}

	if !h.recordListRead(ctx, w, s, "LIST_USERS", int64(len(resources))) {
		return
	}
	writeJSON(w, http.StatusOK, SCIMListResponse{
		Schemas:      []string{ListResponseSchema},
		TotalResults: len(resources),
		StartIndex:   startIndex,
		ItemsPerPage: len(resources),
		Resources:    resources,
	})
}

// getUser handles GET /Users/{id}.
func (h *Handler) getUser(w http.ResponseWriter, r *http.Request, s *session) {
	ctx := r.Context()
	link, row, ok := h.resolveSubject(ctx, w, s, r.PathValue("id"))
	if !ok {
		return
	}

	if _, err := h.store.RecordOperation(ctx, h.sensitiveReadOp(s), store.AuditEffect{
		ResourceType: "user",
		ResourceID:   row.ID,
		Action:       "READ",
		Outcome:      store.EffectApplied,
		BeforeRef:    &s.provider.ID,
	}); err != nil {
		h.logger.Error("scim: failed to record sensitive read", "route", s.descriptor, "error", err)
		writeError(w, http.StatusInternalServerError, "failed to record the read")
		return
	}
	writeJSON(w, http.StatusOK, userResource(row, link.ExternalID, baseURLFromRequest(r, s.provider.Slug)))
}

// resolveSubject is the shared front half of every subject-target
// route: it resolves the binding this directory holds on the subject,
// and then the subject.
//
// A subject bound to a DIFFERENT directory and a subject that does not
// exist get the same not-found answer. Reporting them differently would
// tell one directory which ids the others had provisioned.
func (h *Handler) resolveSubject(ctx context.Context, w http.ResponseWriter, s *session, userID string) (store.IdentityLinkRow, store.UserRow, bool) {
	if userID == "" {
		writeError(w, http.StatusBadRequest, "missing user id")
		return store.IdentityLinkRow{}, store.UserRow{}, false
	}
	link, err := h.store.GetIdentityLinkByProviderAndUser(ctx, s.provider.ID, userID)
	if err != nil {
		if store.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "user not found")
			return store.IdentityLinkRow{}, store.UserRow{}, false
		}
		h.logger.Error("scim: failed to resolve subject binding", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to resolve user")
		return store.IdentityLinkRow{}, store.UserRow{}, false
	}
	row, err := h.store.GetUser(ctx, userID)
	if err != nil {
		if store.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "user not found")
			return store.IdentityLinkRow{}, store.UserRow{}, false
		}
		h.logger.Error("scim: failed to load subject", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to load user")
		return store.IdentityLinkRow{}, store.UserRow{}, false
	}
	return link, row, true
}

// recordListRead writes the audited operation for a collection read.
//
// The effect names the DIRECTORY rather than each row it returned: an
// effect per subject would put the whole population in the log on every
// sync cycle, while the provider reference plus the count is what an
// investigator actually needs — who read, and how much.
func (h *Handler) recordListRead(ctx context.Context, w http.ResponseWriter, s *session, action string, returned int64) bool {
	if _, err := h.store.RecordOperation(ctx, h.sensitiveReadOp(s), store.AuditEffect{
		ResourceType: "identity_provider",
		ResourceID:   s.provider.ID,
		Action:       action,
		Outcome:      store.EffectApplied,
		AfterCount:   &returned,
	}); err != nil {
		h.logger.Error("scim: failed to record sensitive read", "route", s.descriptor, "error", err)
		writeError(w, http.StatusInternalServerError, "failed to record the read")
		return false
	}
	return true
}

// pageWindow reads the SCIM pagination parameters. startIndex is
// 1-based per RFC 7644; a value the client cannot have meant is
// replaced by the default rather than refused, which is what
// directories expect.
func pageWindow(r *http.Request) (startIndex, count int) {
	startIndex, count = 1, defaultPageSize
	if v, err := strconv.Atoi(r.URL.Query().Get("startIndex")); err == nil && v > 0 {
		startIndex = v
	}
	if v, err := strconv.Atoi(r.URL.Query().Get("count")); err == nil && v >= 0 {
		count = v
	}
	if count > maxPageSize {
		count = maxPageSize
	}
	return startIndex, count
}
