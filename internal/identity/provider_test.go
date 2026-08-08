package identity_test

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/crypto"
)

func TestCreateIdentityProvider_SealsTheSecretAndNeverReturnsIt(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admin := f.seedActor(grant{Permissions: []string{"CreateIdentityProvider", "GetIdentityProvider"}})

	const secret = "super-secret-client-value"
	resp, err := f.client.CreateIdentityProvider(f.ctx(), authed(&pmv1.CreateIdentityProviderRequest{
		Name:                 "Corp IdP",
		Slug:                 "corp",
		ProviderType:         pmv1.IdentityProviderType_IDENTITY_PROVIDER_TYPE_OIDC,
		ClientId:             "client-id",
		ClientSecret:         secret,
		IssuerUrl:            "https://idp.example/",
		TrustEmailAssertions: false,
	}, admin.Token))
	require.NoError(t, err)
	created := resp.Msg.Provider
	require.NotNil(t, created)
	assert.Equal(t, "corp", created.Slug)
	assert.False(t, created.TrustEmailAssertions, "the account-takeover guard is off unless asked for")

	// The stored value is ciphertext bound to this provider's own row.
	var stored string
	require.NoError(t, f.raw.QueryRow(f.ctx(),
		`SELECT client_secret_encrypted FROM identity_providers WHERE id = $1`, created.Id).Scan(&stored))
	assert.NotContains(t, stored, secret)
	opened, err := f.kek.DecryptWithContext(stored, crypto.RowAAD(created.Id, crypto.PurposeIdPClientSecret))
	require.NoError(t, err)
	assert.Equal(t, secret, opened)

	// Relocating the ciphertext to another provider's row does not open
	// it: the AAD binds it here.
	_, err = f.kek.DecryptWithContext(stored, crypto.RowAAD(newULID(), crypto.PurposeIdPClientSecret))
	assert.Error(t, err, "a secret sealed for one row must not open in another")

	op := f.onlyOperationFor(powermanagev1connect.ControlServiceCreateIdentityProviderProcedure)
	effect := f.effectWithAction(f.effectsOf(op.OperationID), "CREATE")
	assert.Equal(t, "idp_client_secret_sha256", effect.EvidenceKind)
	assert.Equal(t, sha256Hex(secret), effect.EvidenceFingerprint)
	require.NotNil(t, effect.AfterFlag)
	assert.False(t, *effect.AfterFlag, "the email-assertion switch is recorded explicitly")

	var hits int
	require.NoError(t, f.raw.QueryRow(f.ctx(), `
		SELECT count(*) FROM audit_effects
		 WHERE evidence_fingerprint LIKE '%' || $1 || '%'
		    OR CAST(coalesce(sealed_detail, X'') AS TEXT) LIKE '%' || $1 || '%'`, secret).Scan(&hits))
	assert.Zero(t, hits, "the client secret never reaches the audit log in the clear")
}

func TestCreateIdentityProvider_AcceptsASecretlessCLIOnlyProvider(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admin := f.seedActor(grant{Permissions: []string{"CreateIdentityProvider"}})

	resp, err := f.client.CreateIdentityProvider(f.ctx(), authed(&pmv1.CreateIdentityProviderRequest{
		Name:          "Corp CLI",
		Slug:          "corpcli",
		ProviderType:  pmv1.IdentityProviderType_IDENTITY_PROVIDER_TYPE_OIDC,
		CliClientId:   "powermanage-cli",
		IssuerUrl:     "https://idp.example/",
		DefaultRoleId: auth.AdminRoleID,
	}, admin.Token))
	require.NoError(t, err)
	require.NotNil(t, resp.Msg.Provider)
	assert.Empty(t, resp.Msg.Provider.ClientId)
	assert.Equal(t, "powermanage-cli", resp.Msg.Provider.CliClientId)

	var cliClientID, sealedSecret string
	require.NoError(t, f.raw.QueryRow(f.ctx(),
		`SELECT cli_client_id, client_secret_encrypted FROM identity_providers WHERE id = $1`,
		resp.Msg.Provider.Id).Scan(&cliClientID, &sealedSecret))
	assert.Equal(t, "powermanage-cli", cliClientID)
	assert.Empty(t, sealedSecret)
}

func TestCreateIdentityProvider_RequiresAUsableClientMode(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admin := f.seedActor(grant{Permissions: []string{"CreateIdentityProvider"}})

	for name, mutate := range map[string]func(*pmv1.CreateIdentityProviderRequest){
		"neither client": func(*pmv1.CreateIdentityProviderRequest) {},
		"secret without browser client": func(req *pmv1.CreateIdentityProviderRequest) {
			req.ClientSecret = "orphaned-secret"
		},
	} {
		t.Run(name, func(t *testing.T) {
			req := &pmv1.CreateIdentityProviderRequest{
				Name: "Invalid", Slug: "invalid", ProviderType: pmv1.IdentityProviderType_IDENTITY_PROVIDER_TYPE_OIDC,
				IssuerUrl: "https://idp.example/",
			}
			mutate(req)
			_, err := f.client.CreateIdentityProvider(f.ctx(), authed(req, admin.Token))
			assert.Equal(t, connect.CodeInvalidArgument, connectCodeOf(t, err))
		})
	}
	assert.Zero(t, f.countAuditOperations())
}

func TestCreateIdentityProvider_RejectsADuplicateSlug(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admin := f.seedActor(grant{Permissions: []string{"CreateIdentityProvider"}})
	f.insertProvider("corp", nil)

	_, err := f.client.CreateIdentityProvider(f.ctx(), authed(&pmv1.CreateIdentityProviderRequest{
		Name:         "Another",
		Slug:         "corp",
		ProviderType: pmv1.IdentityProviderType_IDENTITY_PROVIDER_TYPE_OIDC,
		ClientId:     "client",
		ClientSecret: "secret",
		IssuerUrl:    "https://other.example/",
	}, admin.Token))
	assert.Equal(t, connect.CodeAlreadyExists, connectCodeOf(t, err))
}

func TestCreateIdentityProvider_RejectsAMalformedIssuer(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admin := f.seedActor(grant{Permissions: []string{"CreateIdentityProvider"}})

	_, err := f.client.CreateIdentityProvider(f.ctx(), authed(&pmv1.CreateIdentityProviderRequest{
		Name:         "Corp",
		Slug:         "corp",
		ProviderType: pmv1.IdentityProviderType_IDENTITY_PROVIDER_TYPE_OIDC,
		ClientId:     "client",
		ClientSecret: "secret",
		IssuerUrl:    "not a url",
	}, admin.Token))
	assert.Equal(t, connect.CodeInvalidArgument, connectCodeOf(t, err))
	assert.Zero(t, f.countAuditOperations())
}

// An empty client_secret on update means "keep the current one": the
// field is write-only, so a client cannot echo back what it never
// received.
func TestUpdateIdentityProvider_EmptySecretKeepsTheStoredOne(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admin := f.seedActor(grant{Permissions: []string{"UpdateIdentityProvider", "GetIdentityProvider"}})
	providerID := f.insertProvider("corp", func(s *providerSeed) {
		s.Secret = "original-secret"
		s.IssuerURL = "https://idp.example/"
	})

	var before string
	require.NoError(t, f.raw.QueryRow(f.ctx(),
		`SELECT client_secret_encrypted FROM identity_providers WHERE id = $1`, providerID).Scan(&before))

	_, err := f.client.UpdateIdentityProvider(f.ctx(), authed(&pmv1.UpdateIdentityProviderRequest{
		Id:        providerID,
		Name:      "Renamed",
		Enabled:   true,
		ClientId:  "client-id",
		IssuerUrl: "https://idp.example/",
	}, admin.Token))
	require.NoError(t, err)

	var after string
	require.NoError(t, f.raw.QueryRow(f.ctx(),
		`SELECT client_secret_encrypted FROM identity_providers WHERE id = $1`, providerID).Scan(&after))
	assert.Equal(t, before, after, "an omitted secret is kept, not cleared")

	op := f.onlyOperationFor(powermanagev1connect.ControlServiceUpdateIdentityProviderProcedure)
	effect := f.effectWithAction(f.effectsOf(op.OperationID), "UPDATE")
	assert.NotContains(t, effect.ChangedFields, "client_secret_encrypted",
		"the record must not claim a field changed when it did not")
}

func TestUpdateIdentityProvider_DroppingTheBrowserClientClearsItsSecret(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admin := f.seedActor(grant{Permissions: []string{"UpdateIdentityProvider"}})
	providerID := f.insertProvider("corp", func(s *providerSeed) {
		s.CliClientID = "powermanage-cli"
		s.Secret = "browser-secret"
		s.IssuerURL = "https://idp.example/"
	})

	_, err := f.client.UpdateIdentityProvider(f.ctx(), authed(&pmv1.UpdateIdentityProviderRequest{
		Id: providerID, Name: "CLI only", Enabled: true, CliClientId: "powermanage-cli",
		IssuerUrl: "https://idp.example/",
	}, admin.Token))
	require.NoError(t, err)
	var browserClientID, sealedSecret string
	require.NoError(t, f.raw.QueryRow(f.ctx(),
		`SELECT client_id, client_secret_encrypted FROM identity_providers WHERE id = $1`, providerID).
		Scan(&browserClientID, &sealedSecret))
	assert.Empty(t, browserClientID)
	assert.Empty(t, sealedSecret)

	op := f.onlyOperationFor(powermanagev1connect.ControlServiceUpdateIdentityProviderProcedure)
	effect := f.effectWithAction(f.effectsOf(op.OperationID), "UPDATE")
	assert.Contains(t, effect.ChangedFields, "client_secret_encrypted")
	assert.Empty(t, effect.EvidenceKind, "clearing a secret records no credential fingerprint")
}

func TestUpdateIdentityProvider_RecordsTheEmailAssertionTransition(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admin := f.seedActor(grant{Permissions: []string{"UpdateIdentityProvider"}})
	providerID := f.insertProvider("corp", func(s *providerSeed) {
		s.IssuerURL = "https://idp.example/"
		s.TrustEmailAssertions = false
	})

	_, err := f.client.UpdateIdentityProvider(f.ctx(), authed(&pmv1.UpdateIdentityProviderRequest{
		Id:                   providerID,
		Name:                 "Corp",
		Enabled:              true,
		ClientId:             "client-id",
		IssuerUrl:            "https://idp.example/",
		TrustEmailAssertions: true,
	}, admin.Token))
	require.NoError(t, err)

	op := f.onlyOperationFor(powermanagev1connect.ControlServiceUpdateIdentityProviderProcedure)
	effect := f.effectWithAction(f.effectsOf(op.OperationID), "UPDATE")
	require.NotNil(t, effect.BeforeFlag)
	require.NotNil(t, effect.AfterFlag)
	assert.False(t, *effect.BeforeFlag)
	assert.True(t, *effect.AfterFlag,
		"turning the takeover guard off is the single most consequential edit on this row")
}

func TestDeleteIdentityProvider_RetiresTheRowAndLeavesLinksResolvable(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admin := f.seedActor(grant{Permissions: []string{"DeleteIdentityProvider", "GetIdentityProvider"}})
	subject := f.seedSubject()
	providerID := f.insertProvider("corp", nil)
	linkID := f.insertIdentityLink(subject.ID, providerID, "external-1")

	_, err := f.client.DeleteIdentityProvider(f.ctx(), authed(&pmv1.DeleteIdentityProviderRequest{Id: providerID}, admin.Token))
	require.NoError(t, err)

	_, err = f.client.GetIdentityProvider(f.ctx(), authed(&pmv1.GetIdentityProviderRequest{Id: providerID}, admin.Token))
	assert.Equal(t, connect.CodeNotFound, connectCodeOf(t, err))

	link, err := f.store.GetIdentityLink(f.ctx(), linkID)
	require.NoError(t, err, "the link survives: it is evidence of who was bound where")
	assert.Equal(t, providerID, link.ProviderID)
}

func TestEnableSCIM_ShowsTheTokenOnceAndStoresOnlyItsDigest(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admin := f.seedActor(grant{Permissions: []string{
		"EnableSCIM", "DisableSCIM", "RotateSCIMToken", "GetIdentityProvider",
	}})
	providerID := f.insertProvider("corp", nil)

	enabled, err := f.client.EnableSCIM(f.ctx(), authed(&pmv1.EnableSCIMRequest{Id: providerID}, admin.Token))
	require.NoError(t, err)
	require.NotEmpty(t, enabled.Msg.Token)
	assert.Contains(t, enabled.Msg.EndpointUrl, providerID)

	var storedHash string
	require.NoError(t, f.raw.QueryRow(f.ctx(),
		`SELECT scim_token_hash FROM identity_providers WHERE id = $1`, providerID).Scan(&storedHash))
	assert.Equal(t, sha256Hex(enabled.Msg.Token), storedHash)
	assert.NotEqual(t, enabled.Msg.Token, storedHash, "the token itself is never stored")

	// Reading the provider back never re-serves the token.
	got, err := f.client.GetIdentityProvider(f.ctx(), authed(&pmv1.GetIdentityProviderRequest{Id: providerID}, admin.Token))
	require.NoError(t, err)
	assert.True(t, got.Msg.Provider.ScimEnabled)
	assert.NotContains(t, got.Msg.Provider.String(), enabled.Msg.Token)

	// Rotation replaces the digest, so the previous token is dead.
	rotated, err := f.client.RotateSCIMToken(f.ctx(), authed(&pmv1.RotateSCIMTokenRequest{Id: providerID}, admin.Token))
	require.NoError(t, err)
	assert.NotEqual(t, enabled.Msg.Token, rotated.Msg.Token)
	require.NoError(t, f.raw.QueryRow(f.ctx(),
		`SELECT scim_token_hash FROM identity_providers WHERE id = $1`, providerID).Scan(&storedHash))
	assert.Equal(t, sha256Hex(rotated.Msg.Token), storedHash)

	// Disabling clears the digest, so a token issued earlier cannot be
	// replayed if SCIM is turned back on.
	_, err = f.client.DisableSCIM(f.ctx(), authed(&pmv1.DisableSCIMRequest{Id: providerID}, admin.Token))
	require.NoError(t, err)
	require.NoError(t, f.raw.QueryRow(f.ctx(),
		`SELECT scim_token_hash FROM identity_providers WHERE id = $1`, providerID).Scan(&storedHash))
	assert.Empty(t, storedHash)

	enableOp := f.onlyOperationFor(powermanagev1connect.ControlServiceEnableSCIMProcedure)
	enableEffect := f.effectWithAction(f.effectsOf(enableOp.OperationID), "ENABLE_SCIM")
	assert.Equal(t, "scim_token_sha256", enableEffect.EvidenceKind)
	assert.Equal(t, sha256Hex(enabled.Msg.Token), enableEffect.EvidenceFingerprint)

	disableOp := f.onlyOperationFor(powermanagev1connect.ControlServiceDisableSCIMProcedure)
	disableEffect := f.effectWithAction(f.effectsOf(disableOp.OperationID), "DISABLE_SCIM")
	require.NotNil(t, disableEffect.AfterFlag)
	assert.False(t, *disableEffect.AfterFlag)
}

func TestRotateSCIMToken_RefusesWhenSCIMWasNeverEnabled(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admin := f.seedActor(grant{Permissions: []string{"RotateSCIMToken"}})
	providerID := f.insertProvider("corp", nil)

	_, err := f.client.RotateSCIMToken(f.ctx(), authed(&pmv1.RotateSCIMTokenRequest{Id: providerID}, admin.Token))
	assert.Equal(t, connect.CodeFailedPrecondition, connectCodeOf(t, err))
	assert.Zero(t, f.countAuditOperations())
}

func TestIdentityProviderRPCs_ReportAnUnknownProviderAsNotFound(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admin := f.seedActor(grant{Permissions: []string{
		"GetIdentityProvider", "UpdateIdentityProvider", "DeleteIdentityProvider", "EnableSCIM",
	}})
	missing := newULID()

	_, err := f.client.GetIdentityProvider(f.ctx(), authed(&pmv1.GetIdentityProviderRequest{Id: missing}, admin.Token))
	assert.Equal(t, connect.CodeNotFound, connectCodeOf(t, err))

	_, err = f.client.UpdateIdentityProvider(f.ctx(), authed(&pmv1.UpdateIdentityProviderRequest{
		Id: missing, Name: "X",
	}, admin.Token))
	assert.Equal(t, connect.CodeNotFound, connectCodeOf(t, err))

	_, err = f.client.DeleteIdentityProvider(f.ctx(), authed(&pmv1.DeleteIdentityProviderRequest{Id: missing}, admin.Token))
	assert.Equal(t, connect.CodeNotFound, connectCodeOf(t, err))

	_, err = f.client.EnableSCIM(f.ctx(), authed(&pmv1.EnableSCIMRequest{Id: missing}, admin.Token))
	assert.Equal(t, connect.CodeNotFound, connectCodeOf(t, err))
}
