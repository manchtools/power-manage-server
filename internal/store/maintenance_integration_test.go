package store_test

import (
	"context"
	"errors"
	"io"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/archive"
	"github.com/manchtools/power-manage/server/internal/jobs"
	"github.com/manchtools/power-manage/server/internal/maintenance"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/webhook"
)

type prefixFailArchive struct{ archive.ArchiveStore }

type recordingWebhook struct {
	events []webhook.Event
	err    error
}

func (w *recordingWebhook) Send(_ context.Context, event webhook.Event) error {
	w.events = append(w.events, event)
	return w.err
}

func (a prefixFailArchive) Put(ctx context.Context, ref string, src io.Reader) (archive.ArchiveInfo, error) {
	if strings.HasPrefix(ref, "audit-prefix-") {
		return archive.ArchiveInfo{}, errors.New("off-host prefix archive unavailable")
	}
	return a.ArchiveStore.Put(ctx, ref, src)
}

func newMaintenance(t *testing.T, st *store.Store, now time.Time, retention time.Duration) (*maintenance.Service, archive.ArchiveStore) {
	t.Helper()
	archives, err := archive.New(archive.Config{Backend: archive.BackendFilesystem, FilesystemPath: t.TempDir()})
	require.NoError(t, err)
	return maintenance.New(maintenance.Config{
		Store: st, Archive: archives, Retention: retention, Now: func() time.Time { return now },
	}), archives
}

func TestMaintenance_SeedsExactlyOneDurableJobPerKind(t *testing.T) {
	st, raw := setupPostgres(t)
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	service, _ := newMaintenance(t, st, now, 90*24*time.Hour)

	require.NoError(t, service.EnsureScheduled(context.Background()))
	require.NoError(t, service.EnsureScheduled(context.Background()))

	rows, err := raw.Query(context.Background(), `SELECT kind FROM jobs ORDER BY kind`)
	require.NoError(t, err)
	defer rows.Close()
	var kinds []string
	for rows.Next() {
		var kind string
		require.NoError(t, rows.Scan(&kind))
		kinds = append(kinds, kind)
	}
	require.NoError(t, rows.Err())
	want := []string{
		maintenance.KindAuditAnchor, maintenance.KindAuditRetention,
		maintenance.KindAuditVerify, maintenance.KindAuthStateCleanup,
		maintenance.KindSecurityInspect,
	}
	sort.Strings(want)
	assert.Equal(t, want, kinds)
	assert.Len(t, service.Handlers(), len(want))
	assert.Len(t, service.Recurring(), len(want))

	var created int
	require.NoError(t, raw.QueryRow(context.Background(), `
		SELECT count(*) FROM audit_effects WHERE resource_type = 'job' AND action = 'CREATE'
	`).Scan(&created))
	assert.Equal(t, len(want), created)
}

func TestMaintenance_NotifiesOnlyWhenNoEnabledGlobalAdministratorExists(t *testing.T) {
	st, raw := setupPostgres(t)
	ctx := context.Background()
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	notifier := &recordingWebhook{}
	archives, err := archive.New(archive.Config{Backend: archive.BackendFilesystem, FilesystemPath: t.TempDir()})
	require.NoError(t, err)
	service := maintenance.New(maintenance.Config{
		Store: st, Archive: archives, Retention: 90 * 24 * time.Hour,
		Now: func() time.Time { return now }, Notifier: notifier,
	})

	require.NoError(t, service.InspectSecurity(ctx, jobs.Job{}))
	require.Len(t, notifier.events, 1)
	assert.Equal(t, webhook.EventZeroEnabledAdministrators, notifier.events[0].Name)
	assert.Equal(t, now, notifier.events[0].OccurredAt)
	var inspections, intents int
	require.NoError(t, raw.QueryRow(ctx, `SELECT count(*) FROM audit_effects WHERE action = 'INSPECT'`).Scan(&inspections))
	require.NoError(t, raw.QueryRow(ctx, `SELECT count(*) FROM audit_effects WHERE action = 'NOTIFY_INTENT'`).Scan(&intents))
	assert.Equal(t, 1, inspections)
	assert.Equal(t, 1, intents)

	userID := newID()
	_, err = raw.Exec(ctx, `
		INSERT INTO users (id, email, provisioning_source, created_at, updated_at)
		VALUES ($1, 'admin@example.test', 'scim', $2, $2)
	`, userID, now)
	require.NoError(t, err)
	_, err = raw.Exec(ctx, `
		INSERT INTO user_roles (grant_id, user_id, role_id, assigned_at)
		VALUES ($3, $1, '00000000000000000000000001', $2)
	`, userID, now, newID())
	require.NoError(t, err)
	require.NoError(t, service.InspectSecurity(ctx, jobs.Job{}))
	assert.Len(t, notifier.events, 1, "an enabled global administrator suppresses the alert")

	_, err = raw.Exec(ctx, `UPDATE users SET disabled = TRUE WHERE id = $1`, userID)
	require.NoError(t, err)
	require.NoError(t, service.InspectSecurity(ctx, jobs.Job{}))
	assert.Len(t, notifier.events, 2, "a disabled administrator does not provide recovery authority")

	groupID := newID()
	_, err = raw.Exec(ctx, `UPDATE users SET disabled = FALSE WHERE id = $1`, userID)
	require.NoError(t, err)
	_, err = raw.Exec(ctx, `DELETE FROM user_roles WHERE user_id = $1`, userID)
	require.NoError(t, err)
	_, err = raw.Exec(ctx, `INSERT INTO user_groups (id, name) VALUES ($1, 'SCIM administrators')`, groupID)
	require.NoError(t, err)
	_, err = raw.Exec(ctx, `INSERT INTO user_group_members (group_id, user_id) VALUES ($1, $2)`, groupID, userID)
	require.NoError(t, err)
	_, err = raw.Exec(ctx, `
		INSERT INTO user_group_roles (grant_id, group_id, role_id)
		VALUES ($1, $2, '00000000000000000000000001')
	`, newID(), groupID)
	require.NoError(t, err)
	require.NoError(t, service.InspectSecurity(ctx, jobs.Job{}))
	assert.Len(t, notifier.events, 2, "a live SCIM group may confer global administrator authority")
}

func TestMaintenance_WebhookFailureUsesDurableJobRetry(t *testing.T) {
	st, raw := setupPostgres(t)
	notifier := &recordingWebhook{err: errors.New("webhook unavailable")}
	archives, err := archive.New(archive.Config{Backend: archive.BackendFilesystem, FilesystemPath: t.TempDir()})
	require.NoError(t, err)
	service := maintenance.New(maintenance.Config{
		Store: st, Archive: archives, Retention: 90 * 24 * time.Hour, Notifier: notifier,
	})

	assert.ErrorContains(t, service.InspectSecurity(context.Background(), jobs.Job{}), "webhook unavailable")
	var intents int
	require.NoError(t, raw.QueryRow(context.Background(), `
		SELECT count(*) FROM audit_effects WHERE action = 'NOTIFY_INTENT'
	`).Scan(&intents))
	assert.Equal(t, 1, intents, "the committed intent remains attributable while the durable job retries")
}

func TestMaintenance_AuditFailurePreventsWebhook(t *testing.T) {
	st, raw := setupPostgres(t)
	notifier := &recordingWebhook{}
	archives, err := archive.New(archive.Config{Backend: archive.BackendFilesystem, FilesystemPath: t.TempDir()})
	require.NoError(t, err)
	service := maintenance.New(maintenance.Config{
		Store: st, Archive: archives, Retention: 90 * 24 * time.Hour, Notifier: notifier,
	})
	_, err = raw.Exec(context.Background(), `
		ALTER TABLE audit_effects ADD CONSTRAINT reject_webhook_intent CHECK (action <> 'NOTIFY_INTENT')
	`)
	require.NoError(t, err)

	assert.Error(t, service.InspectSecurity(context.Background(), jobs.Job{}))
	assert.Empty(t, notifier.events, "no network effect may precede committed audit evidence")
}

func TestMaintenance_ExternalAnchorAndArchiveBeforeDeleteRunEndToEnd(t *testing.T) {
	st, raw := setupPostgres(t)
	ctx := context.Background()
	seedOperation(t, st)
	seedOperation(t, st)
	now := time.Now().UTC().Add(120 * 24 * time.Hour)
	service, archives := newMaintenance(t, st, now, 90*24*time.Hour)

	require.NoError(t, service.AnchorAudit(ctx, jobs.Job{}))
	seedOperation(t, st)
	require.NoError(t, service.RetainAudit(ctx, jobs.Job{}))
	assert.Zero(t, countRows(t, raw, "audit_operations"))
	assert.Zero(t, countRows(t, raw, "audit_effects"))
	assert.Equal(t, int64(1), countRows(t, raw, "audit_chain_checkpoints"))

	items, err := archives.List(ctx)
	require.NoError(t, err)
	var anchorRef, prefixRef string
	anchorCount := 0
	for _, item := range items {
		if len(item.Ref) >= len("audit-anchor-") && item.Ref[:len("audit-anchor-")] == "audit-anchor-" {
			anchorRef = item.Ref
			anchorCount++
		}
		if len(item.Ref) >= len("audit-prefix-") && item.Ref[:len("audit-prefix-")] == "audit-prefix-" {
			prefixRef = item.Ref
		}
	}
	require.NotEmpty(t, anchorRef)
	assert.Equal(t, 1, anchorCount, "only the newest external head anchor is retained")
	require.NotEmpty(t, prefixRef)
	require.NoError(t, archive.Verify(ctx, archives, anchorRef))
	require.NoError(t, archive.Verify(ctx, archives, prefixRef))
	require.NoError(t, service.VerifyAudit(ctx, jobs.Job{}),
		"the external anchor must authenticate the now-archived boundary through its checkpoint")
}

func TestMaintenance_PrefixArchiveFailureLeavesAuditRowsUntouched(t *testing.T) {
	st, raw := setupPostgres(t)
	seedOperation(t, st)
	now := time.Now().UTC().Add(120 * 24 * time.Hour)
	base, err := archive.New(archive.Config{Backend: archive.BackendFilesystem, FilesystemPath: t.TempDir()})
	require.NoError(t, err)
	service := maintenance.New(maintenance.Config{
		Store: st, Archive: prefixFailArchive{ArchiveStore: base}, Retention: 90 * 24 * time.Hour,
		Now: func() time.Time { return now },
	})

	err = service.RetainAudit(context.Background(), jobs.Job{})
	require.ErrorContains(t, err, "off-host prefix archive unavailable")
	assert.Equal(t, int64(1), countRows(t, raw, "audit_operations"))
	assert.Equal(t, int64(1), countRows(t, raw, "audit_effects"))
	assert.Zero(t, countRows(t, raw, "audit_chain_checkpoints"))
}

func TestMaintenance_CleansExpiredOIDCStateWithAudit(t *testing.T) {
	st, raw := setupPostgres(t)
	ctx := context.Background()
	now := time.Now().UTC()
	providerID := newID()
	_, err := raw.Exec(ctx, `
		INSERT INTO identity_providers (id, name, slug, client_id, issuer_url)
		VALUES ($1, 'oidc', 'oidc', 'client', 'https://idp.example.test')
	`, providerID)
	require.NoError(t, err)
	_, err = raw.Exec(ctx, `
		INSERT INTO auth_states (state, provider_id, expires_at) VALUES
		('expired', $1, $2), ('live', $1, $3)
	`, providerID, now.Add(-time.Minute), now.Add(time.Hour))
	require.NoError(t, err)
	service, _ := newMaintenance(t, st, now, 90*24*time.Hour)

	require.NoError(t, service.CleanupAuthStates(ctx, jobs.Job{}))
	var states []string
	require.NoError(t, raw.QueryRow(ctx, `SELECT array_agg(state ORDER BY state) FROM auth_states`).Scan(&states))
	assert.Equal(t, []string{"live"}, states)
	var effects int
	require.NoError(t, raw.QueryRow(ctx, `
		SELECT count(*) FROM audit_effects
		WHERE resource_type = 'auth_state_collection' AND action = 'CLEANUP'
	`).Scan(&effects))
	assert.Equal(t, 1, effects)
}

func TestMaintenance_AuthStateAuditFailureRollsBackCleanup(t *testing.T) {
	st, raw := setupPostgres(t)
	ctx := context.Background()
	providerID := newID()
	_, err := raw.Exec(ctx, `
		INSERT INTO identity_providers (id, name, slug, client_id, issuer_url)
		VALUES ($1, 'oidc', 'oidc', 'client', 'https://idp.example.test')
	`, providerID)
	require.NoError(t, err)
	_, err = raw.Exec(ctx, `
		INSERT INTO auth_states (state, provider_id, expires_at)
		VALUES ('expired', $1, now() - interval '1 minute')
	`, providerID)
	require.NoError(t, err)
	_, err = raw.Exec(ctx, `ALTER TABLE audit_effects ADD CONSTRAINT reject_auth_cleanup CHECK (action <> 'CLEANUP')`)
	require.NoError(t, err)
	deleted, cleanupErr := st.CleanupExpiredAuthStates(ctx)
	require.Error(t, cleanupErr)
	assert.Zero(t, deleted, "rolled-back rows must not be reported as deleted")
	var count int
	require.NoError(t, raw.QueryRow(ctx, `SELECT count(*) FROM auth_states WHERE state = 'expired'`).Scan(&count))
	assert.Equal(t, 1, count)
}
