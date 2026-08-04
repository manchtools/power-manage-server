package delivery_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/manchtools/power-manage/server/internal/delivery"
	"github.com/manchtools/power-manage/server/internal/store"
)

// TestSendable pins the single availability/epoch predicate the dispatcher and
// the agent sync path both consult. A future PENDING row stays scheduled; only
// a PUSHED row awaiting redelivery on a strictly newer epoch bypasses its
// retry delay.
func TestSendable(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Minute)
	future := now.Add(time.Hour)

	row := func(state string, availableAt time.Time, pushEpoch int64) store.DeliveryRow {
		return store.DeliveryRow{State: state, AvailableAt: availableAt, PushEpoch: pushEpoch}
	}

	cases := []struct {
		name  string
		row   store.DeliveryRow
		epoch int64
		want  bool
	}{
		{"due pending", row(delivery.StatePending, past, 0), 5, true},
		{"pending available_at exactly now", row(delivery.StatePending, now, 0), 5, true},
		{"due pushed", row(delivery.StatePushed, past, 3), 5, true},
		{"future pending never pulled forward", row(delivery.StatePending, future, 0), 5, false},
		{"future pushed newer epoch redelivers", row(delivery.StatePushed, future, 3), 5, true},
		{"future pushed same epoch waits", row(delivery.StatePushed, future, 5), 5, false},
		{"future pushed older epoch waits", row(delivery.StatePushed, future, 9), 5, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, delivery.Sendable(tc.row, tc.epoch, now))
		})
	}
}
