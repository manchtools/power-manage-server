package projectors

import (
	"fmt"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
)

// x25519PublicKeySize is the raw X25519 public key length the payload must
// carry — anything else could not have been produced by GenerateX25519 and
// would poison the projection with an unusable key.
const x25519PublicKeySize = 32

// LpsKeypairGeneratedPayload aliases the shared wire struct so projector-side
// code keeps the Payload-suffix convention; payloads.LpsKeypairGenerated is
// the canonical handle for the emit site (api.EnsureLpsKeypair).
type LpsKeypairGeneratedPayload = payloads.LpsKeypairGenerated

// LpsKeypairGeneratedFromEvent decodes the singleton LpsKeypairGenerated
// event (#495). Returns ErrIgnoredEvent for any event the lps_keypair
// projector does not act on.
//
// Pure: no I/O, deterministic, depends only on the event's fields.
func LpsKeypairGeneratedFromEvent(e store.PersistedEvent) (LpsKeypairGeneratedPayload, error) {
	p, err := decodePayload[LpsKeypairGeneratedPayload](e, "lps_keypair", eventtypes.LpsKeypairGenerated)
	if err != nil {
		return LpsKeypairGeneratedPayload{}, err
	}
	// The projection row is useless without both halves, and a wrong-size
	// public key cannot pair with the private key it claims to accompany —
	// fail loudly in the listener log rather than projecting a poisoned row.
	switch {
	case len(p.PublicKey) != x25519PublicKeySize:
		return LpsKeypairGeneratedPayload{}, fmt.Errorf("projector: LpsKeypairGenerated requires a %d-byte public_key (got %d)", x25519PublicKeySize, len(p.PublicKey))
	case p.PrivateKeyEnc == "":
		return LpsKeypairGeneratedPayload{}, fmt.Errorf("projector: LpsKeypairGenerated requires private_key_enc")
	}
	return p, nil
}
