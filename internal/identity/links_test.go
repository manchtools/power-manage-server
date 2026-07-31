package identity_test

import (
	"sync"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
)

func TestListIdentityLinks_ReturnsOnlyTheCallersOwnBindings(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	caller := f.seedActor(grant{Permissions: []string{"ListIdentityLinks"}})
	other := f.seedSubject()
	provider := f.insertProvider("corp", nil)
	f.insertIdentityLink(caller.ID, provider, "caller-subject")
	f.insertIdentityLink(other.ID, provider, "other-subject")

	resp, err := f.client.ListIdentityLinks(f.ctx(), authed(&pmv1.ListIdentityLinksRequest{}, caller.Token))
	require.NoError(t, err)
	require.Len(t, resp.Msg.Links, 1, "the RPC takes no subject, so there is nothing to substitute")
	assert.Equal(t, caller.ID, resp.Msg.Links[0].UserId)
	assert.Equal(t, "corp", resp.Msg.Links[0].ProviderSlug)
}

func TestUnlinkIdentity_RemovesTheCallersOwnBinding(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	caller := f.seedActor(grant{Permissions: []string{"UnlinkIdentity", "ListIdentityLinks"}})
	first := f.insertProvider("first", nil)
	second := f.insertProvider("second", nil)
	doomed := f.insertIdentityLink(caller.ID, first, "first-subject")
	f.insertIdentityLink(caller.ID, second, "second-subject")

	_, err := f.client.UnlinkIdentity(f.ctx(), authed(&pmv1.UnlinkIdentityRequest{LinkId: doomed}, caller.Token))
	require.NoError(t, err)

	links, err := f.store.ListIdentityLinksForUser(f.ctx(), caller.ID)
	require.NoError(t, err)
	require.Len(t, links, 1)
	assert.Equal(t, second, links[0].ProviderID)

	op := f.onlyOperationFor(powermanagev1connect.ControlServiceUnlinkIdentityProcedure)
	assert.Equal(t, caller.ID, op.ActorID)
	effect := f.effectWithAction(f.effectsOf(op.OperationID), "UNLINK")
	assert.Equal(t, "external_subject_sha256", effect.EvidenceKind)
	assert.Equal(t, sha256Hex("first-subject"), effect.EvidenceFingerprint)
}

// Human sign-in is OIDC only, so removing the last binding would lock
// the subject out of their own account with nothing to fall back on.
func TestUnlinkIdentity_RefusesToRemoveTheLastSignInMethod(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	caller := f.seedActor(grant{Permissions: []string{"UnlinkIdentity"}})
	provider := f.insertProvider("corp", nil)
	only := f.insertIdentityLink(caller.ID, provider, "corp-subject")

	_, err := f.client.UnlinkIdentity(f.ctx(), authed(&pmv1.UnlinkIdentityRequest{LinkId: only}, caller.Token))
	assert.Equal(t, connect.CodeFailedPrecondition, connectCodeOf(t, err))

	links, err := f.store.ListIdentityLinksForUser(f.ctx(), caller.ID)
	require.NoError(t, err)
	assert.Len(t, links, 1, "the refused request removed nothing")
}

// Another subject's binding reads as absent, so the id space cannot be
// probed for who is linked where.
func TestUnlinkIdentity_ReportsAnotherSubjectsBindingAsNotFound(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	caller := f.seedActor(grant{Permissions: []string{"UnlinkIdentity"}})
	victim := f.seedSubject()
	provider := f.insertProvider("corp", nil)
	f.insertIdentityLink(caller.ID, provider, "caller-subject")
	f.insertIdentityLink(caller.ID, f.insertProvider("second", nil), "caller-second")
	victimLink := f.insertIdentityLink(victim.ID, provider, "victim-subject")

	_, err := f.client.UnlinkIdentity(f.ctx(), authed(&pmv1.UnlinkIdentityRequest{LinkId: victimLink}, caller.Token))
	assert.Equal(t, connect.CodeNotFound, connectCodeOf(t, err))

	links, err := f.store.ListIdentityLinksForUser(f.ctx(), victim.ID)
	require.NoError(t, err)
	assert.Len(t, links, 1)
}

// Two callers presenting the SAME refresh token at the same time: the
// rotation is a conditional insert, so exactly one may win. Without it
// both would mint a session from one credential.
func TestRefreshToken_ConcurrentPresentationsOfOneTokenYieldOneSession(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	subject := f.seedActor(grant{Permissions: []string{"GetCurrentUser"}})
	pair := f.mintPair(subject.ID, subject.Email)

	const racers = 6
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		accepted int
		refused  int
	)
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := f.client.RefreshToken(f.ctx(), connect.NewRequest(&pmv1.RefreshTokenRequest{
				RefreshToken: pair.RefreshToken,
			}))
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				accepted++
			} else {
				refused++
			}
		}()
	}
	close(start)
	wg.Wait()

	assert.Equal(t, 1, accepted, "one refresh token yields exactly one new session, however many present it")
	assert.Equal(t, racers-1, refused)
}
