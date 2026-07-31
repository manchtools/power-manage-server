package scim_test

// The credential cluster: what the SCIM bearer gate admits, what it
// refuses, and what a refusal records.

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/scim"
	"github.com/manchtools/power-manage/server/internal/store"
)

func TestAuth_ValidTokenAdmitted(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)

	resp := f.do(http.MethodGet, p.Slug, p.Token, "/Users", nil)
	require.Equal(t, http.StatusOK, resp.Code, "body: %s", resp)
}

// Every malformed or wrong credential is refused with 401. The matrix
// is exhaustive over the branches of the gate, so a branch that stopped
// rejecting is a failing row rather than an untested path.
func TestAuth_RejectionMatrix(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)

	cases := []struct {
		name   string
		header string
	}{
		{"missing_header", ""},
		{"basic_scheme", "Basic " + p.Token},
		{"bare_token_no_scheme", p.Token},
		{"bearer_empty_token", "Bearer "},
		{"wrong_token_bytes", "Bearer not-the-real-token"},
		{"byte_tampered_token", "Bearer " + flipLastChar(p.Token)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := f.rawAuth(http.MethodGet, p.Slug, tc.header, "/Users")
			assert.Equal(t, http.StatusUnauthorized, resp.Code, "body: %s", resp)
		})
	}

	t.Run("unknown_slug", func(t *testing.T) {
		resp := f.rawAuth(http.MethodGet, "no-such-directory", "Bearer "+p.Token, "/Users")
		assert.Equal(t, http.StatusUnauthorized, resp.Code, "body: %s", resp)
	})
}

// A provider disabled for login must reject SCIM even while its token
// is still valid: one switch turns the whole provider off, and a
// directory that kept provisioning through a disabled provider would
// keep minting subjects nobody can sign in as.
func TestAuth_LoginDisabledProviderRejected(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	f.setProviderEnabled(p.ID, false)

	resp := f.do(http.MethodGet, p.Slug, p.Token, "/Users", nil)
	assert.Equal(t, http.StatusUnauthorized, resp.Code, "body: %s", resp)
}

// A provider with SCIM off holds no token digest, so no bearer value
// authenticates against it.
func TestAuth_DisabledSCIMRejectsPreviouslyValidToken(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	require.Equal(t, http.StatusOK, f.do(http.MethodGet, p.Slug, p.Token, "/Users", nil).Code)

	f.disableSCIM(p.ID)

	resp := f.do(http.MethodGet, p.Slug, p.Token, "/Users", nil)
	assert.Equal(t, http.StatusUnauthorized, resp.Code,
		"a provider whose SCIM is off must authenticate no bearer value: %s", resp)
}

// Rotation overwrites the single stored digest, so exactly one token
// authenticates at a time: the one rotation returned.
func TestAuth_RotationInvalidatesTheOldToken(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	old := p.Token

	fresh := f.rotateSCIM(p.ID)
	require.NotEqual(t, old, fresh)

	assert.Equal(t, http.StatusUnauthorized, f.do(http.MethodGet, p.Slug, old, "/Users", nil).Code,
		"the rotated-away token must be refused")
	assert.Equal(t, http.StatusOK, f.do(http.MethodGet, p.Slug, fresh, "/Users", nil).Code,
		"the token rotation returned must be accepted")
}

// The unknown-slug answer and the wrong-token answer are the same
// answer. A client that could tell them apart could enumerate which
// directories are configured.
func TestAuth_NoProviderExistenceOracle(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)

	unknown := f.rawAuth(http.MethodGet, "ghost-directory", "Bearer "+p.Token, "/Users")
	wrongToken := f.rawAuth(http.MethodGet, p.Slug, "Bearer definitely-wrong", "/Users")

	require.Equal(t, http.StatusUnauthorized, unknown.Code)
	require.Equal(t, http.StatusUnauthorized, wrongToken.Code)
	assert.Equal(t, wrongToken.String(), unknown.String(),
		"the body must be identical across unknown-slug and wrong-token")
	assert.Contains(t, unknown.String(), "invalid credentials")
}

// A refused credential is recorded under the dedicated
// rejected-authentication class, with no actor id, the presented token
// only as a digest, and the peer address only as a digest.
func TestAuth_RejectionIsAudited(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)

	const presented = "definitely-wrong"
	require.Equal(t, http.StatusUnauthorized,
		f.do(http.MethodGet, p.Slug, presented, "/Users", nil).Code)

	rejected := f.rejections(scim.DescUsersList)
	require.Len(t, rejected, 1, "a refused SCIM credential must record exactly one rejection")
	op := rejected[0]

	assert.Equal(t, string(store.ClassRejectedAuthentication), op.Class)
	assert.Equal(t, auth.AnonymousActorType, op.ActorType,
		"an attempt that never authenticated has no principal kind of its own")
	assert.Empty(t, op.ActorID, "a rejected attempt must not claim an actor id")
	assert.Equal(t, scim.Origin, op.Origin)
	assert.Equal(t, scim.DescUsersList, op.RequestDescriptor)
	assert.Equal(t, string(store.AuthorizationDenied), op.AuthorizationOutcome)
	assert.Equal(t, string(store.ResultRejected), op.Result)
	assert.Equal(t, sha256Hex(presented), op.ActorFingerprint,
		"the presented token must appear only as its digest")
	assert.NotContains(t, op.ActorFingerprint, presented)
	assert.NotEmpty(t, op.OriginFingerprint, "the peer address must be recorded as a digest")
	assert.Regexp(t, `^[0-9a-f]{64}$`, op.OriginFingerprint)

	assert.Empty(t, f.effectsOf(op.OperationID),
		"a refused credential affected no resource, so it records no effect")
}

// A credential that was never presented has no digest to record:
// "absent" and "present but empty" must not collide.
func TestAuth_MissingCredentialRecordsNoTokenDigest(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)

	require.Equal(t, http.StatusUnauthorized,
		f.rawAuth(http.MethodGet, p.Slug, "", "/Users").Code)

	rejected := f.rejections(scim.DescUsersList)
	require.Len(t, rejected, 1)
	assert.Empty(t, rejected[0].ActorFingerprint)
}

// An admitted request is attributed to the directory that made it: the
// provider's own ULID as the actor, and the token's digest as proof of
// which credential acted.
func TestAuth_AdmittedRequestIsAttributedToTheProvider(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)

	require.Equal(t, http.StatusOK, f.do(http.MethodGet, p.Slug, p.Token, "/Users", nil).Code)

	op := f.onlyOperationFor(scim.DescUsersList)
	assert.Equal(t, string(store.ClassSensitiveRead), op.Class)
	assert.Equal(t, scim.ActorTypeProvider, op.ActorType)
	assert.Equal(t, p.ID, op.ActorID)
	assert.Equal(t, sha256Hex(p.Token), op.ActorFingerprint)
	assert.Equal(t, scim.Origin, op.Origin)
	assert.Equal(t, scim.AuthorizationDetail, op.AuthorizationDetail)
	assert.Equal(t, string(store.AuthorizationAllowed), op.AuthorizationOutcome)
	assert.Equal(t, string(store.ResultSuccess), op.Result)
}

// Content type is a request-shape rule, so it is enforced before the
// credential is looked at.
func TestAuth_UnsupportedContentTypeRefused(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)

	req, err := http.NewRequestWithContext(f.ctx(), http.MethodPost,
		f.server.URL+"/scim/v2/"+p.Slug+"/Users", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+p.Token)
	req.Header.Set("Content-Type", "text/plain")

	assert.Equal(t, http.StatusUnsupportedMediaType, f.send(req).Code)
}

// Discovery sits behind the same credential as everything else: the
// responses confirm a slug exists, and an anonymous caller must not be
// able to enumerate configured directories that way.
func TestAuth_DiscoveryRequiresCredential(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)

	for _, path := range []string{"/ServiceProviderConfig", "/Schemas", "/ResourceTypes"} {
		t.Run(path, func(t *testing.T) {
			assert.Equal(t, http.StatusUnauthorized, f.rawAuth(http.MethodGet, p.Slug, "", path).Code)
			assert.Equal(t, http.StatusOK, f.do(http.MethodGet, p.Slug, p.Token, path, nil).Code)
		})
	}
}

// Discovery describes the service, not any subject, so it records
// nothing: an audited operation per poll would be volume without
// evidence.
func TestAuth_DiscoveryRecordsNothing(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)

	require.Equal(t, http.StatusOK, f.do(http.MethodGet, p.Slug, p.Token, "/Schemas", nil).Code)
	assert.Empty(t, f.operationsFor(scim.DescSchemas))
}

func flipLastChar(s string) string {
	if s == "" {
		return s
	}
	b := []byte(s)
	if b[len(b)-1] == 'a' {
		b[len(b)-1] = 'b'
	} else {
		b[len(b)-1] = 'a'
	}
	return string(b)
}

func sha256Hex(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}
