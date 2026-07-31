package handler

// Spec 41 criterion 14: an agent built before this change must fail cleanly with
// a clear error when it reaches the new control, rather than hang. Pre-alpha
// agents are reinstalled, not migrated — this is about a legible failure, not
// compatibility.
//
// The handshake cannot carry that failure, and the test below proves it rather
// than assuming it: `Hello` is byte-identical across the change (sdk
// proto/pm/v1/agent.proto is unchanged in that message), so a pre-spec-41 agent
// connects, is verified, gets its per-device worker, and receives a Welcome. To
// control it looks exactly like a current agent. The only thing that differs at
// connect is `agent_version`, a self-reported build string that is "dev" on
// every source build — gating on it is neither sound nor the version
// negotiation this spec declines to build.
//
// The first frame that CAN only have come from a pre-spec-41 agent is an
// ActionResult carrying `lps.rotations` metadata. That agent had no
// authenticated channel of its own: the gateway relayed its results, so it
// sealed every rotated LPS password to control's X25519 key and smuggled the
// batch out through the result (agent main:internal/executor/lps.go — `metadata
// := map[string]string{"lps.rotations": ...}`). The post-spec-41 agent sends
// StoreLpsPasswordsRequest on this stream and deliberately emits no metadata,
// "because emitting it would only be a second copy of a credential travelling a
// path with no reader". The key's only reader was the gateway hop at server
// main:internal/handler/agent.go:623, deleted with the tier.
//
// So without a gate the frame is ACCEPTED: the stream stays up, nothing is
// logged, and the batch is marshalled straight into the execution-result payload
// the deleted code deliberately stripped it from. The device has already changed
// those local passwords; control never records them; the operator loses the
// accounts and no error is raised anywhere. That silence is the illegible
// failure criterion 14 forbids.

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

// preSpec41RotationsMetadata is one rotation batch in exactly the shape the
// pre-spec-41 agent emitted: a JSON array under `lps.rotations`, each entry
// carrying the base64 of an X25519-sealed password. The blob is synthetic
// padding of the right construction length (32 ephemeral || 12 nonce || ct ||
// 16 tag) — nothing here is or ever was a live credential; what matters is the
// key and the shape, which is what identifies the agent generation.
const preSpec41RotationsMetadata = `[{"username":"alice",` +
	`"sealed_password":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",` +
	`"rotated_at":"2026-07-31T10:00:00Z","reason":"scheduled"}]`

// TestStream_PreSpec41AgentIsRefusedWithAClearError drives the real
// control-hosted AgentService through a real bidi stream and asserts the
// criterion at the level that matters: not "a warning was logged" but "the agent
// was told, in bounded time, that this server cannot serve it".
//
// The context deadline is the "rather than hanging" half. A handler that neither
// answers nor closes surfaces here as CodeDeadlineExceeded, which fails the
// assertion rather than wedging the run.
func TestStream_PreSpec41AgentIsRefusedWithAClearError(t *testing.T) {
	const deviceID = "01HZX9PRE41000000000000000"
	const actionID = "01HZX9LPSRTN00000000000000"

	f := newStreamFixture(t, false)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream := f.client.Stream(ctx)
	require.NoError(t, stream.Send(&pm.AgentMessage{
		Id: "01HZX9PRE41HELLO0000000000",
		Payload: &pm.AgentMessage_Hello{Hello: &pm.Hello{
			DeviceId:     &pm.DeviceId{Value: deviceID},
			AgentVersion: "2026.07.03",
			Hostname:     "pre-spec41-host",
			Arch:         "amd64",
		}},
	}))

	// The handshake is indistinguishable, and that is a finding rather than a
	// setup step: it is precisely why the refusal cannot live at Hello.
	welcome, err := stream.Receive()
	require.NoError(t, err,
		"the pre-spec-41 handshake is byte-identical, so control must still accept it here — "+
			"if this ever fails, the discrimination point moved and this test is testing the wrong frame")
	require.NotNil(t, welcome.GetWelcome())

	// The frame a pre-spec-41 agent sends after an LPS run. It does NOT close its
	// request side afterwards — a real agent keeps streaming — so a server that
	// simply accepts this leaves the connection sitting there, which is the
	// silence being asserted against.
	require.NoError(t, stream.Send(&pm.AgentMessage{
		Id: "01HZX9PRE41RESULT000000000",
		Payload: &pm.AgentMessage_ActionResult{ActionResult: &pm.ActionResult{
			ActionId: &pm.ActionId{Value: actionID},
			Status:   pm.ExecutionStatus_EXECUTION_STATUS_SUCCESS,
			Changed:  true,
			Metadata: map[string]string{"lps.rotations": preSpec41RotationsMetadata},
		}},
	}))

	err = recvErr(stream)
	require.Error(t, err,
		"control ended the stream cleanly instead of refusing it: a pre-spec-41 LPS report was accepted "+
			"and acknowledged, so the agent believes rotated passwords were stored that control never saw")
	require.NotEqual(t, connect.CodeDeadlineExceeded, connect.CodeOf(err),
		"control neither answered nor closed: it accepted a pre-spec-41 LPS report and left the agent "+
			"waiting. Criterion 14 requires a clear error rather than a hang, and silence is the failure it names")
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err),
		"refusing an agent generation this server cannot serve is a precondition failure, not a transport fault")

	// Legible to the operator reading it off the agent: it must name the thing
	// that is wrong and what to do, not just fail.
	assert.Contains(t, err.Error(), "lps.rotations",
		"the error must name the pre-spec-41 mechanism it refused, or the operator cannot tell "+
			"an outdated agent from a broken one")
	assert.Contains(t, err.Error(), "einstall",
		"the error must say the agent is reinstalled — criterion 14 is explicit that agents are "+
			"reinstalled, not migrated, and an error that omits the remedy is not a clear one")

	// The other half of "not silently accepted": the credential-bearing batch
	// must not reach the control inbox. Its last enqueue must still be the Hello
	// from connect — the deleted gateway hop stripped this key before forwarding,
	// and nothing downstream reads it now.
	last := f.queue.lastCall(t)
	assert.Equal(t, taskqueue.TypeDeviceHello, last.taskType,
		"a refused pre-spec-41 result was still forwarded to control: the sealed rotation batch now "+
			"rides on inside the execution-result payload that the gateway hop used to strip")
}
