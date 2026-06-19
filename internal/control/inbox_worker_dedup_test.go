package control

// WS1b #3 — the derived-execution dedup id is built over a length-prefixed,
// domain-separated pre-image (mirroring the signing digest's framing) instead
// of a ':'-joined, time-formatted string. The old `"exec:"+dev+":"+act+":"+ts`
// pre-image had two latent ambiguities this charter pins shut:
//   - field-boundary collision: ('a:b','c') and ('a','b:c') hashed identically;
//   - mixed pre-image domains: an RFC3339Nano timestamp and a `dur:status`
//     fallback shared one unframed string space with no variant tag.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

func TestStableExecutionID_FramedAndDomainSeparated(t *testing.T) {
	ts := timestamppb.New(time.Unix(1_700_000_000, 123))
	ok := pm.ExecutionStatus_EXECUTION_STATUS_SUCCESS

	// FRAMING: a delimiter inside one field must not let it alias an adjacent
	// field. The adversarial inputs are sourced from intent — device/action ids
	// are externally supplied and CAN contain ':'. Old code collided these.
	a := stableExecutionID("dev:a", "act", ts, 0, ok)
	b := stableExecutionID("dev", "a:act", ts, 0, ok)
	assert.NotEqual(t, a, b, "a ':' in deviceID must not alias the actionID boundary")

	c := stableExecutionID("dev", "act:x", ts, 0, ok)
	d := stableExecutionID("dev", "act", ts, 0, ok)
	assert.NotEqual(t, c, d, "a ':' in actionID must not alias the completion boundary")

	// DETERMINISM (retry stability): identical inputs → identical id.
	assert.Equal(t, a, stableExecutionID("dev:a", "act", ts, 0, ok),
		"same result must dedup to the same id across retries")

	// DOMAIN SEPARATION: the timestamp variant and the duration/status fallback
	// variant must not alias, even with identical device/action.
	tsVariant := stableExecutionID("dev", "act", ts, 0, ok)
	durVariant := stableExecutionID("dev", "act", nil, 1500, ok)
	assert.NotEqual(t, tsVariant, durVariant,
		"timestamp and duration/status variants must carry distinct domain tags")

	// Distinct timestamps → distinct ids (separate runs of the same action).
	ts2 := timestamppb.New(time.Unix(1_700_000_001, 0))
	assert.NotEqual(t, tsVariant, stableExecutionID("dev", "act", ts2, 0, ok),
		"distinct completion timestamps must yield distinct ids")

	// Sub-second precision is preserved — keying off (seconds, nanos) not a
	// formatted string that could drop precision.
	tsNanos := timestamppb.New(time.Unix(1_700_000_000, 124))
	assert.NotEqual(t, tsVariant, stableExecutionID("dev", "act", tsNanos, 0, ok),
		"a one-nanosecond difference must yield a distinct id")

	// In the fallback, BOTH duration and status are bound (and framed apart).
	assert.NotEqual(t, durVariant, stableExecutionID("dev", "act", nil, 1501, ok),
		"distinct duration in the fallback must yield a distinct id")
	assert.NotEqual(t, durVariant, stableExecutionID("dev", "act", nil, 1500, pm.ExecutionStatus_EXECUTION_STATUS_FAILED),
		"distinct status in the fallback must yield a distinct id")

	// The result is a valid 26-char ULID string.
	require.Len(t, a, 26, "stableExecutionID must return a ULID string")
}
