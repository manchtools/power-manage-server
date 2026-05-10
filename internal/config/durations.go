// Package config file durations.go — duration clamping helpers
// shared between cmd/control and cmd/gateway (audit F017 / N022).
//
// Two distinct shapes:
//
//   - ClampInterval enforces min/max bounds on a duration. The
//     special-case sentinel `0 == disabled` is preserved so feature
//     flags that gate on "interval > 0" keep working unchanged.
//   - ClampDurationFloor enforces a minimum but treats zero/negative
//     as "use the default" rather than "disabled". Used for fields
//     where a zero context.WithTimeout would silently break the
//     safety net.
package config

import "time"

// ClampInterval enforces minDur ≤ *target ≤ maxDur on a duration
// while preserving the "zero means disabled" sentinel and the
// "negative means disabled" defensive collapse.
func ClampInterval(target *time.Duration, minDur, maxDur time.Duration) {
	if *target < 0 {
		*target = 0
		return
	}
	if *target == 0 {
		return
	}
	if *target < minDur {
		*target = minDur
	} else if *target > maxDur {
		*target = maxDur
	}
}

// ClampDurationFloor enforces a minimum on a duration, falling back
// to def when the input is zero or negative. Use this for fields
// where "no value" should NOT mean "feature disabled" but instead
// "use the default" — the system-action reconcile timeout is the
// canonical case (zero would silently break the safety net via
// context.WithTimeout returning an already-cancelled context).
func ClampDurationFloor(target *time.Duration, def, minDur time.Duration) {
	if *target <= 0 {
		*target = def
		return
	}
	if *target < minDur {
		*target = minDur
	}
}
