package projectors

import (
	"fmt"
	"time"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
)

// TokenCreatedPayload covers the fields the token projector reads
// from a TokenCreated event. Pointer fields for ExpiresAt and OwnerID
// preserve "absent" vs "explicitly null" — the column accepts NULL
// and the deleted PL/pgSQL projector relied on that.
type TokenCreatedPayload struct {
	ID        string
	ValueHash string
	Name      string
	OneTime   bool
	MaxUses   int32
	ExpiresAt *time.Time
	OwnerID   *string
	CreatedBy string
}

// TokenRenamedPayload — sole field is the new name.
type TokenRenamedPayload struct {
	ID   string
	Name string
}

type tokenCreatedRaw struct {
	ValueHash string  `json:"value_hash"`
	Name      *string `json:"name,omitempty"`
	OneTime   *bool   `json:"one_time,omitempty"`
	MaxUses   *int32  `json:"max_uses,omitempty"`
	ExpiresAt *string `json:"expires_at,omitempty"`
	OwnerID   *string `json:"owner_id,omitempty"`
}

// TokenCreatedFromEvent decodes TokenCreated. Defaults match the
// PL/pgSQL projector: missing name → "" (empty string); missing one_time → false;
// missing max_uses → 0; missing expires_at → nil (stays NULL); missing
// owner_id → nil. value_hash is required (UNIQUE NOT NULL).
func TokenCreatedFromEvent(e store.PersistedEvent) (TokenCreatedPayload, error) {
	raw, err := decodePayload[tokenCreatedRaw](e, "token", eventtypes.TokenCreated)
	if err != nil {
		return TokenCreatedPayload{}, err
	}
	if raw.ValueHash == "" {
		return TokenCreatedPayload{}, fmt.Errorf("projector: TokenCreated requires value_hash")
	}
	out := TokenCreatedPayload{
		ID:        e.StreamID,
		ValueHash: raw.ValueHash,
		CreatedBy: e.ActorID,
	}
	if raw.Name != nil {
		out.Name = *raw.Name
	}
	if raw.OneTime != nil {
		out.OneTime = *raw.OneTime
	}
	if raw.MaxUses != nil {
		out.MaxUses = *raw.MaxUses
	}
	if raw.ExpiresAt != nil && *raw.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, *raw.ExpiresAt)
		if err != nil {
			t, err = time.Parse(time.RFC3339Nano, *raw.ExpiresAt)
			if err != nil {
				return TokenCreatedPayload{}, fmt.Errorf("projector: TokenCreated has invalid expires_at %q: %w", *raw.ExpiresAt, err)
			}
		}
		out.ExpiresAt = &t
	}
	out.OwnerID = raw.OwnerID
	return out, nil
}

// TokenRenamedFromEvent decodes TokenRenamed. Name is required —
// the rename handler always supplies it; an empty payload would be
// a programmer error.
func TokenRenamedFromEvent(e store.PersistedEvent) (TokenRenamedPayload, error) {
	raw, err := decodePayload[struct {
		Name string `json:"name"`
	}](e, "token", eventtypes.TokenRenamed)
	if err != nil {
		return TokenRenamedPayload{}, err
	}
	if raw.Name == "" {
		return TokenRenamedPayload{}, fmt.Errorf("projector: TokenRenamed requires name")
	}
	return TokenRenamedPayload{ID: e.StreamID, Name: raw.Name}, nil
}
