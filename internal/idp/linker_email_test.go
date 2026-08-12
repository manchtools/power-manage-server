package idp

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testdb"
)

// A 32-byte KEK in hex; the linker mints each subject's DEK under it.
const linkerTestKEK = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

func newLinkerStore(t *testing.T) (*store.Store, *testdb.DB) {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "power-manage.db")
	st, err := store.New(ctx, path)
	require.NoError(t, err)
	t.Cleanup(st.Close)
	raw, err := testdb.Open(ctx, path)
	require.NoError(t, err)
	t.Cleanup(raw.Close)
	return st, raw
}

func linkerOp() store.AuditOperation {
	return store.AuditOperation{
		Class:                store.ClassMutation,
		ActorType:            SystemActorSSO,
		Origin:               "rpc",
		RequestDescriptor:    "powermanage.v1.ControlService/CompleteOIDCLogin",
		AuthorizationOutcome: store.AuthorizationAllowed,
		AuthorizationDetail:  "oidc",
		Result:               store.ResultSuccess,
		ResultCode:           "OK",
	}
}

func newTestLinker(t *testing.T, at time.Time) *Linker {
	t.Helper()
	kek, err := crypto.NewEncryptor(linkerTestKEK)
	require.NoError(t, err)
	return NewLinker(kek, func() time.Time { return at })
}

// seedProvider inserts the identity_providers row the created identity link
// foreign-keys to, and returns the provider the linker resolves claims against.
func seedProvider(t *testing.T, raw *testdb.DB, autoCreate, autoLink bool) store.IdentityProviderRow {
	t.Helper()
	id := ulid.Make().String()
	_, err := raw.Exec(context.Background(), `
		INSERT INTO identity_providers (id, name, slug, client_id, issuer_url, auto_create_users, auto_link_by_email)
		VALUES ($1, 'Corp', 'corp', 'client', 'https://issuer.example', $2, $3)`,
		id, autoCreate, autoLink)
	require.NoError(t, err)
	return store.IdentityProviderRow{
		ID: id, Slug: "corp", AutoCreateUsers: autoCreate, AutoLinkByEmail: autoLink,
	}
}

// TestLinker_JITStoresNormalizedEmail proves the OIDC JIT write path folds the
// asserted email to the same canonical form SCIM and manual lookups store and
// query by. A mixed-case JIT write that skipped this would be unfindable by a
// normalized GetUserByEmail yet still block re-insert on the COLLATE NOCASE
// active-unique index, leaving the subject permanently unmanageable.
func TestLinker_JITStoresNormalizedEmail(t *testing.T) {
	ctx := context.Background()
	st, raw := newLinkerStore(t)
	at := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	linker := newTestLinker(t, at)

	provider := seedProvider(t, raw, true, false)
	claims := &UserClaims{
		Subject: "ext-jit-1", Email: "First.Last@Company.com",
		Name: "First Last", GivenName: "First", FamilyName: "Last",
	}

	var result *LinkResult
	_, err := st.WithAudit(ctx, linkerOp(), func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		var err error
		result, err = linker.LinkOrCreate(ctx, tx, rec, provider, claims)
		return err
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.IsNew, "an absent subject is provisioned by JIT")

	// Stored normalized: a normalized lookup must resolve the JIT subject.
	user, err := st.GetUserByEmail(ctx, "first.last@company.com")
	require.NoError(t, err, "a normalized lookup must find the JIT-provisioned subject")
	assert.Equal(t, result.UserID, user.ID)
	assert.Equal(t, "first.last@company.com", user.Email, "the JIT write must store the normalized email")
}

// TestLinker_PaddedEmailDerivesUsernameFromNormalizedForm proves the JIT write
// derives the Linux username from the SAME normalized email it stores. A valid
// address with surrounding whitespace ("  Padded.User@Corp.com  ") folds to
// "padded.user@corp.com"; deriving the username from the raw claim instead would
// leak the leading whitespace into it (sanitized to leading underscores),
// producing a username inconsistent with the stored canonical email.
func TestLinker_PaddedEmailDerivesUsernameFromNormalizedForm(t *testing.T) {
	ctx := context.Background()
	st, raw := newLinkerStore(t)
	at := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	linker := newTestLinker(t, at)

	provider := seedProvider(t, raw, true, false)
	claims := &UserClaims{Subject: "ext-padded-1", Email: "  Padded.User@Corp.com  ", Name: "Padded User"}

	var result *LinkResult
	_, err := st.WithAudit(ctx, linkerOp(), func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		var e error
		result, e = linker.LinkOrCreate(ctx, tx, rec, provider, claims)
		return e
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	user, err := st.GetUserByEmail(ctx, "padded.user@corp.com")
	require.NoError(t, err, "the padded email must be stored and found in normalized form")
	assert.Equal(t, "padded.user@corp.com", user.Email)
	assert.Equal(t, DeriveLinuxUsername("padded.user@corp.com", ""), user.LinuxUsername,
		"the Linux username must derive from the normalized email, not the padded raw claim")
}

// TestLinker_AutoLinkFindsNormalizedUser proves the cross-provider auto-link
// guard resolves an existing (unbound) subject even when the asserted email
// differs only in case, because the lookup normalizes first.
func TestLinker_AutoLinkFindsNormalizedUser(t *testing.T) {
	ctx := context.Background()
	st, raw := newLinkerStore(t)
	at := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	linker := newTestLinker(t, at)

	// An invited, unbound subject already stored in canonical form.
	existingID := ulid.Make().String()
	_, err := raw.Exec(ctx, `INSERT INTO users (id, email) VALUES ($1, $2)`,
		existingID, "first.last@company.com")
	require.NoError(t, err)

	provider := seedProvider(t, raw, false, true)
	claims := &UserClaims{Subject: "ext-link-1", Email: "First.Last@Company.com", Name: "First Last"}

	var result *LinkResult
	_, err = st.WithAudit(ctx, linkerOp(), func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		var err error
		result, err = linker.LinkOrCreate(ctx, tx, rec, provider, claims)
		return err
	})
	require.NoError(t, err, "a case-only-different email must resolve the existing subject, not fail to match")
	require.NotNil(t, result)
	assert.Equal(t, existingID, result.UserID, "auto-link must bind the existing normalized subject")
	assert.False(t, result.IsNew, "auto-link must not provision a duplicate subject")
}

// TestLinker_WhitespaceEmailIsRefused proves a whitespace-only email claim is
// treated as no email: it is neither auto-linked nor JIT-provisioned, even with
// both provider modes enabled. The raw claim is non-empty ("   "), so a gate on
// claims.Email alone would provision a subject whose normalized email is empty —
// unfindable by a normalized GetUserByEmail lookup yet still blocking re-insert
// on the active-unique COLLATE NOCASE index.
func TestLinker_WhitespaceEmailIsRefused(t *testing.T) {
	ctx := context.Background()
	st, raw := newLinkerStore(t)
	at := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	linker := newTestLinker(t, at)

	// Both auto-create and auto-link enabled: neither may act on an empty email.
	provider := seedProvider(t, raw, true, true)
	claims := &UserClaims{Subject: "ext-blank-1", Email: "   ", Name: "Blank"}

	_, err := st.WithAudit(ctx, linkerOp(), func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		_, e := linker.LinkOrCreate(ctx, tx, rec, provider, claims)
		return e
	})
	require.Error(t, err, "a whitespace-only email must not provision or link a subject")
	// An empty canonical email is treated as no email: neither auto-link nor
	// auto-create acts, so the login resolves to the same unauthenticated
	// no-matching-account answer as any other unresolvable identity.
	assert.ErrorIs(t, err, ErrNoMatchingAccount)

	// No subject with an empty email may exist. The refusal aborts the audited
	// transaction, so this also confirms createUser never ran.
	var count int
	require.NoError(t, raw.QueryRow(ctx,
		`SELECT count(*) FROM users WHERE email = ''`).Scan(&count))
	assert.Zero(t, count, "no empty-email subject may be created")

	// Auto-link must not have acted either: no identity link may have been
	// created on an empty address.
	var links int
	require.NoError(t, raw.QueryRow(ctx,
		`SELECT count(*) FROM identity_links`).Scan(&links))
	assert.Zero(t, links, "no identity link may be created on an empty email")
}

// The two refusal tests prove an operator reading the refusal can tell WHICH
// auto-create gate stopped the login without reading this package: a disabled
// provider flag and a missing trusted email are different deployment mistakes
// with different fixes. The client-visible answer stays the opaque
// no-matching-account sentinel either way.

func TestLinker_RefusalNamesTheDisabledAutoCreateFlag(t *testing.T) {
	ctx := context.Background()
	st, raw := newLinkerStore(t)
	linker := newTestLinker(t, time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))

	// A fully trusted email cannot help a disabled provider, and the refusal
	// must name the flag, not the email.
	disabled := seedProvider(t, raw, false, false)
	_, err := st.WithAudit(ctx, linkerOp(), func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		_, e := linker.LinkOrCreate(ctx, tx, rec, disabled,
			&UserClaims{Subject: "ext-gate-1", Email: "one@example.com", Name: "One"})
		return e
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoMatchingAccount, "the sentinel must survive wrapping")
	assert.Contains(t, err.Error(), "auto_create_users",
		"a disabled-flag refusal must name the flag")
}

func TestLinker_RefusalNamesTheMissingTrustedEmail(t *testing.T) {
	ctx := context.Background()
	st, raw := newLinkerStore(t)
	linker := newTestLinker(t, time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))

	// Auto-create is enabled but no trusted email survived claim extraction.
	// The refusal must name the missing claim, not the flag.
	enabled := seedProvider(t, raw, true, false)
	_, err := st.WithAudit(ctx, linkerOp(), func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		_, e := linker.LinkOrCreate(ctx, tx, rec, enabled,
			&UserClaims{Subject: "ext-gate-2", Email: "", Name: "Two"})
		return e
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoMatchingAccount, "the sentinel must survive wrapping")
	assert.Contains(t, err.Error(), "trusted email",
		"a missing-claim refusal must name the claim")
}
