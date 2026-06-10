package projectors

import (
	"encoding/json"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/store"
)

// totpEventPayload covers every field the TOTP projector reads
// across the five event types. Per-event derivation funcs below
// pick the subset they need.
type totpEventPayload struct {
	SecretEncrypted string   `json:"secret_encrypted"`
	BackupCodesHash []string `json:"backup_codes_hash"`
	Index           *int     `json:"index"`
}

// decodeTotpPayload returns the parsed event data + the standard
// invariant fields (sequence_num for projection_version, occurred_at
// for updated_at). Centralised so each per-event helper doesn't
// re-derive them.
func decodeTotpPayload(e store.PersistedEvent) (totpEventPayload, error) {
	if e.StreamType != "totp" {
		return totpEventPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		// Empty payload (e.g. TOTPVerified, TOTPDisabled). Still
		// valid — return zero-value payload, the per-event helper
		// only reads the fields it needs.
		return totpEventPayload{}, nil
	}
	var p totpEventPayload
	if err := json.Unmarshal(e.Data, &p); err != nil {
		return totpEventPayload{}, fmt.Errorf("projector: invalid TOTP event payload: %w", err)
	}
	return p, nil
}
