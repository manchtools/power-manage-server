package scim_test

// The request-boundary fixture: real SCIM routes, real HTTP transport,
// real SQLite, and the real ControlService identity handlers that
// own the SCIM token lifecycle.
//
// Nothing here stubs the store or the credential gate. A test that
// wants a valid bearer token calls the real EnableSCIM RPC and uses
// what it returned; a test that wants the token invalidated calls the
// real RotateSCIMToken.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/manchtools/power-manage/server/internal/testdb"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/require"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/identity"
	"github.com/manchtools/power-manage/server/internal/scim"
	"github.com/manchtools/power-manage/server/internal/store"
)

// testKEK is a fixed 32-byte key. It is a TEST key: the fixture needs a
// deterministic KEK so a sealed value can be re-opened in an assertion,
// and nothing outside this binary ever sees it.
const testKEK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

const testBaseURL = "https://control.test.example"

type fixture struct {
	t       *testing.T
	store   *store.Store
	raw     *testdb.DB
	kek     *crypto.Encryptor
	handler *scim.Handler
	server  *httptest.Server
	client  *http.Client
	mounted []string
	now     time.Time

	// control is the real ControlService client, used for the SCIM
	// token lifecycle (enable, rotate, disable).
	control powermanagev1connect.ControlServiceClient
	// adminToken is a session token for a subject holding every
	// permission, so a lifecycle call in a fixture helper is never the
	// thing under test.
	adminToken string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	st, raw := setupSQLite(t)

	now := time.Now().UTC().Truncate(time.Microsecond)
	tick := func() time.Time { return now }

	kek, err := crypto.NewEncryptor(testKEK)
	require.NoError(t, err)

	_, priv, err := auth.GenerateSessionKey()
	require.NoError(t, err)
	jwt, err := auth.NewJWTManager(auth.JWTConfig{PrivateKey: priv, Now: tick})
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	idHandlers := identity.New(identity.Config{
		Store:         st,
		Logger:        logger,
		JWT:           jwt,
		KEK:           kek,
		PublicBaseURL: testBaseURL,
		Now:           tick,
	})
	scimHandler := scim.New(scim.Config{
		Store:  st,
		Logger: logger,
		KEK:    kek,
		Now:    tick,
	})
	t.Cleanup(scimHandler.Close)

	mux := http.NewServeMux()
	idHandlers.Mount(mux, connect.WithInterceptors(
		identity.NewValidationInterceptor(),
		auth.NewAuthInterceptor(logger, jwt, auth.RateLimiters{}, auth.NewRejectionRecorder(st)),
		auth.NewAuthzInterceptor(),
	))
	mounted := scimHandler.Mount(mux)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	f := &fixture{
		t:       t,
		store:   st,
		raw:     raw,
		kek:     kek,
		handler: scimHandler,
		server:  srv,
		client:  srv.Client(),
		mounted: mounted,
		now:     now,
		control: powermanagev1connect.NewControlServiceClient(srv.Client(), srv.URL),
	}
	f.adminToken = f.seedAdmin(jwt)
	return f
}

func (f *fixture) ctx() context.Context { return f.t.Context() }

// seedAdmin plants a subject holding every registered permission and
// mints a session token for them by resolving their authority through
// the REAL store queries.
func (f *fixture) seedAdmin(jwt *auth.JWTManager) string {
	f.t.Helper()
	userID := newULID()
	email := "scim-admin-" + strings.ToLower(userID[20:]) + "@test.example"
	f.insertUser(userID, email)

	roleID := newULID()
	_, err := f.raw.Exec(f.ctx(),
		`INSERT INTO roles (id, name, description, permissions, is_system, created_at, updated_at)
		 VALUES ($1, $2, '', $3, FALSE, $4, $4)`,
		roleID, "scim-admin-role-"+roleID[18:], allPermissionKeys(), f.now)
	require.NoError(f.t, err)
	_, err = f.raw.Exec(f.ctx(),
		`INSERT INTO user_roles (grant_id, user_id, role_id, assigned_at, assigned_by)
		 VALUES ($1, $2, $3, $4, '')`,
		newULID(), userID, roleID, f.now)
	require.NoError(f.t, err)

	perms, err := f.store.ListUserPermissions(f.ctx(), userID)
	require.NoError(f.t, err)
	state, err := f.store.GetUserSessionState(f.ctx(), userID)
	require.NoError(f.t, err)
	pair, err := jwt.GenerateTokens(userID, email, perms, nil, state.SessionVersion)
	require.NoError(f.t, err)
	return pair.AccessToken
}

// ---------------------------------------------------------------------------
// Seeding
// ---------------------------------------------------------------------------

func (f *fixture) insertUser(id, email string) {
	f.insertUserWithSource(id, email, "scim")
}

func (f *fixture) insertUserWithSource(id, email, source string) {
	f.t.Helper()
	_, err := f.raw.Exec(f.ctx(),
		`INSERT INTO users (id, email, provisioning_source, created_at, updated_at) VALUES ($1, $2, $3, $4, $4)`,
		id, email, source, f.now)
	require.NoError(f.t, err)
	// Every subject owns a data-encryption key from the moment they
	// exist; without one, class-three audit detail about them could not
	// be sealed and the handler would fail closed.
	wrapped, err := crypto.GenerateWrappedDEK(f.kek, id)
	require.NoError(f.t, err)
	_, err = f.raw.Exec(f.ctx(),
		`INSERT INTO user_encryption_keys (user_id, wrapped_dek) VALUES ($1, $2)`, id, wrapped)
	require.NoError(f.t, err)
}

type providerSeed struct {
	Enabled              bool
	AutoCreateUsers      bool
	AutoLinkByEmail      bool
	TrustEmailAssertions bool
	DefaultRoleID        string
}

// provider is a seeded directory: its row, its slug and, once
// seedProvider has enabled SCIM through the real RPC, its bearer token.
type provider struct {
	ID    string
	Slug  string
	Token string
}

// seedProvider plants an identity provider and turns SCIM on through
// the real EnableSCIM RPC, so the token a test presents is one the
// production mint produced.
func (f *fixture) seedProvider(mutate func(*providerSeed)) *provider {
	f.t.Helper()
	seed := providerSeed{Enabled: true}
	if mutate != nil {
		mutate(&seed)
	}
	providerID := newULID()
	slug := "dir-" + strings.ToLower(providerID[16:])
	sealed, err := f.kek.EncryptWithContext("client-secret", crypto.RowAAD(providerID, crypto.PurposeIdPClientSecret))
	require.NoError(f.t, err)
	_, err = f.raw.Exec(f.ctx(),
		`INSERT INTO identity_providers
		   (id, name, slug, provider_type, enabled, client_id, client_secret_encrypted, issuer_url,
		    auto_create_users, auto_link_by_email, trust_email_assertions, default_role_id,
		    group_claim, group_mapping, created_at, updated_at)
		 VALUES ($1, $2, $3, 'oidc', $4, 'client-id', $5, 'https://idp.test.example',
		         $6, $7, $8, $9, '', '{}', $10, $10)`,
		providerID, "provider-"+slug, slug, seed.Enabled, sealed,
		seed.AutoCreateUsers, seed.AutoLinkByEmail, seed.TrustEmailAssertions, seed.DefaultRoleID,
		f.now)
	require.NoError(f.t, err)

	return &provider{ID: providerID, Slug: slug, Token: f.enableSCIM(providerID)}
}

// setProviderEnabled toggles the provider's login switch directly. It
// models an operator disabling the provider outside the SCIM surface.
func (f *fixture) setProviderEnabled(providerID string, enabled bool) {
	f.t.Helper()
	_, err := f.raw.Exec(f.ctx(),
		`UPDATE identity_providers SET enabled = $2 WHERE id = $1`, providerID, enabled)
	require.NoError(f.t, err)
}

func (f *fixture) insertRole(perms []string) string {
	f.t.Helper()
	roleID := newULID()
	_, err := f.raw.Exec(f.ctx(),
		`INSERT INTO roles (id, name, description, permissions, is_system, created_at, updated_at)
		 VALUES ($1, $2, '', $3, FALSE, $4, $4)`,
		roleID, "role-"+roleID[18:], perms, f.now)
	require.NoError(f.t, err)
	return roleID
}

// grantRoleToUserGroup attaches a role to a user group, which is how an
// operator gives a SCIM-provisioned group its authority. Membership is
// what confers it on the subject.
func (f *fixture) grantRoleToUserGroup(groupID, roleID string) {
	f.t.Helper()
	_, err := f.raw.Exec(f.ctx(),
		`INSERT INTO user_group_roles (grant_id, group_id, role_id, assigned_at, assigned_by)
		 VALUES ($1, $2, $3, $4, '')`,
		newULID(), groupID, roleID, f.now)
	require.NoError(f.t, err)
}

// ---------------------------------------------------------------------------
// SCIM token lifecycle, through the real RPCs
// ---------------------------------------------------------------------------

func (f *fixture) enableSCIM(providerID string) string {
	f.t.Helper()
	resp, err := f.control.EnableSCIM(f.ctx(), authed(&pmv1.EnableSCIMRequest{Id: providerID}, f.adminToken))
	require.NoError(f.t, err)
	require.NotEmpty(f.t, resp.Msg.Token)
	return resp.Msg.Token
}

func (f *fixture) rotateSCIM(providerID string) string {
	f.t.Helper()
	resp, err := f.control.RotateSCIMToken(f.ctx(), authed(&pmv1.RotateSCIMTokenRequest{Id: providerID}, f.adminToken))
	require.NoError(f.t, err)
	require.NotEmpty(f.t, resp.Msg.Token)
	return resp.Msg.Token
}

func (f *fixture) disableSCIM(providerID string) {
	f.t.Helper()
	_, err := f.control.DisableSCIM(f.ctx(), authed(&pmv1.DisableSCIMRequest{Id: providerID}, f.adminToken))
	require.NoError(f.t, err)
}

// authed wraps a ControlService request with a bearer token.
func authed[T any](msg *T, token string) *connect.Request[T] {
	req := connect.NewRequest(msg)
	req.Header().Set("Authorization", "Bearer "+token)
	return req
}

// ---------------------------------------------------------------------------
// SCIM requests
// ---------------------------------------------------------------------------

// do issues a SCIM request over the real transport as the given
// (slug, token) pair.
func (f *fixture) do(method, slug, token, path string, body any) *response {
	f.t.Helper()
	var payload io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(f.t, err)
		payload = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(f.ctx(), method, f.server.URL+"/scim/v2/"+slug+path, payload)
	require.NoError(f.t, err)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	return f.send(req)
}

// raw issues a SCIM request with an explicit Authorization header
// value, so a test can present a malformed credential.
func (f *fixture) rawAuth(method, slug, header, path string) *response {
	f.t.Helper()
	req, err := http.NewRequestWithContext(f.ctx(), method, f.server.URL+"/scim/v2/"+slug+path, nil)
	require.NoError(f.t, err)
	if header != "" {
		req.Header.Set("Authorization", header)
	}
	return f.send(req)
}

func (f *fixture) send(req *http.Request) *response {
	f.t.Helper()
	resp, err := f.client.Do(req)
	require.NoError(f.t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(f.t, err)
	return &response{t: f.t, Code: resp.StatusCode, Body: body}
}

type response struct {
	t    *testing.T
	Code int
	Body []byte
}

// JSON decodes the response body into a generic map.
func (r *response) JSON() map[string]any {
	r.t.Helper()
	var out map[string]any
	require.NoError(r.t, json.Unmarshal(r.Body, &out), "body: %s", r.Body)
	return out
}

func (r *response) String() string { return string(r.Body) }

// ---------------------------------------------------------------------------
// Audit assertions
// ---------------------------------------------------------------------------

type auditOperation struct {
	OperationID          string
	Class                string
	ActorType            string
	ActorID              string
	ActorFingerprint     string
	Origin               string
	OriginFingerprint    string
	RequestDescriptor    string
	AuthorizationOutcome string
	AuthorizationDetail  string
	Result               string
	ResultCode           string
}

type auditEffect struct {
	ResourceType        string
	ResourceID          string
	Action              string
	Outcome             string
	ChangedFields       []string
	BeforeRef           *string
	AfterRef            *string
	BeforeFlag          *bool
	AfterFlag           *bool
	BeforeCount         *int64
	AfterCount          *int64
	EvidenceKind        string
	EvidenceFingerprint string
	SealedDetail        []byte
	SealedDetailSubject *string
}

func (f *fixture) operationsFor(descriptor string) []auditOperation {
	f.t.Helper()
	rows, err := f.raw.Query(f.ctx(),
		`SELECT operation_id, operation_class, actor_type, actor_id, actor_fingerprint,
		        origin, origin_fingerprint, request_descriptor, authorization_outcome,
		        authorization_detail, result, result_code
		   FROM audit_operations WHERE request_descriptor = $1 ORDER BY chain_seq`, descriptor)
	require.NoError(f.t, err)
	defer rows.Close()

	var out []auditOperation
	for rows.Next() {
		var op auditOperation
		require.NoError(f.t, rows.Scan(
			&op.OperationID, &op.Class, &op.ActorType, &op.ActorID, &op.ActorFingerprint,
			&op.Origin, &op.OriginFingerprint, &op.RequestDescriptor, &op.AuthorizationOutcome,
			&op.AuthorizationDetail, &op.Result, &op.ResultCode))
		out = append(out, op)
	}
	require.NoError(f.t, rows.Err())
	return out
}

func (f *fixture) onlyOperationFor(descriptor string) auditOperation {
	f.t.Helper()
	ops := f.operationsFor(descriptor)
	require.Len(f.t, ops, 1, "expected exactly one audit operation for %s", descriptor)
	return ops[0]
}

func (f *fixture) effectsOf(operationID string) []auditEffect {
	f.t.Helper()
	rows, err := f.raw.Query(f.ctx(),
		`SELECT resource_type, resource_id, action, outcome, changed_fields,
		        before_ref, after_ref, before_flag, after_flag, before_count, after_count,
		        evidence_kind, evidence_fingerprint, sealed_detail, sealed_detail_subject
		   FROM audit_effects WHERE operation_id = $1 ORDER BY effect_seq`, operationID)
	require.NoError(f.t, err)
	defer rows.Close()

	var out []auditEffect
	for rows.Next() {
		var e auditEffect
		require.NoError(f.t, rows.Scan(
			&e.ResourceType, &e.ResourceID, &e.Action, &e.Outcome, &e.ChangedFields,
			&e.BeforeRef, &e.AfterRef, &e.BeforeFlag, &e.AfterFlag, &e.BeforeCount, &e.AfterCount,
			&e.EvidenceKind, &e.EvidenceFingerprint, &e.SealedDetail, &e.SealedDetailSubject))
		out = append(out, e)
	}
	require.NoError(f.t, rows.Err())
	return out
}

// effectWithAction finds the single effect carrying an action, failing
// if there is not exactly one.
func (f *fixture) effectWithAction(effects []auditEffect, action string) auditEffect {
	f.t.Helper()
	var found []auditEffect
	for _, e := range effects {
		if e.Action == action {
			found = append(found, e)
		}
	}
	require.Len(f.t, found, 1, "expected exactly one %s effect, got %d in %+v", action, len(found), effects)
	return found[0]
}

func (f *fixture) hasEffectWithAction(effects []auditEffect, action string) bool {
	for _, e := range effects {
		if e.Action == action {
			return true
		}
	}
	return false
}

// rejections returns every recorded rejected-authentication operation
// for a route, oldest first.
func (f *fixture) rejections(descriptor string) []auditOperation {
	f.t.Helper()
	var out []auditOperation
	for _, op := range f.operationsFor(descriptor) {
		if op.Class == string(store.ClassRejectedAuthentication) {
			out = append(out, op)
		}
	}
	return out
}

// openSealedDetail decrypts class-three audit detail with the subject's
// own key.
func (f *fixture) openSealedDetail(subjectID string, sealed []byte, field string) (string, error) {
	f.t.Helper()
	var wrapped string
	if err := f.raw.QueryRow(f.ctx(),
		`SELECT wrapped_dek FROM user_encryption_keys WHERE user_id = $1`, subjectID).Scan(&wrapped); err != nil {
		return "", err
	}
	dek, err := crypto.UnwrapDEK(f.kek, subjectID, wrapped)
	if err != nil {
		return "", err
	}
	return dek.OpenField(string(sealed), field)
}

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

func newULID() string { return ulid.Make().String() }

func allPermissionKeys() []string {
	all := auth.AllPermissions()
	keys := make([]string, len(all))
	for i, p := range all {
		keys[i] = p.Key
	}
	return keys
}
