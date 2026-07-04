package pii

import (
	"context"
	"errors"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/store"
)

// ErrErased marks a payload whose subject's DEK row is MISSING — the
// graceful crypto-shredded state (spec 19 AC 9). Callers (the
// UserDeleted projector path, PR B) project the redaction sentinel and
// continue. Distinct from an unwrap FAILURE, which is a fault that
// must abort (AC 10) so a KEK misconfiguration can never masquerade as
// mass erasure.
var ErrErased = errors.New("pii: subject's encryption key is gone (crypto-shredded)")

// Opener decrypts sealed PII on decoded payload structs at
// projection-build time. Mirrors the Sealer's subject resolution.
type Opener struct {
	kek  *crypto.Encryptor
	keys store.UserEncryptionKeyRepo
}

// NewOpener builds the opener; both dependencies are mandatory.
func NewOpener(kek *crypto.Encryptor, keys store.UserEncryptionKeyRepo) (*Opener, error) {
	if kek == nil {
		return nil, errors.New("pii: opener requires the at-rest KEK")
	}
	if keys == nil {
		return nil, errors.New("pii: opener requires the user_encryption_keys repo")
	}
	return &Opener{kek: kek, keys: keys}, nil
}

// OpenDecoded opens every sealed PII field of the decoded payload IN
// PLACE (payload must be a pointer to the wire struct).
//
//   - No tagged fields, or no field holding pii:v1 ciphertext →
//     no-op (legacy plaintext events, factory-seeded maps).
//   - Subject's DEK row MISSING → ErrErased (the graceful erased
//     state; the caller decides how to project — AC 9).
//   - DEK present but unwrappable, or ciphertext that fails to open →
//     a real error; the projection/rebuild must ABORT (AC 10).
func (o *Opener) OpenDecoded(ctx context.Context, streamType, streamID string, payload any) error {
	if !crypto.HasSealedPII(payload) {
		return nil
	}
	subject, err := ResolveSubject(streamType, streamID, payload)
	if err != nil {
		return err
	}
	rec, err := o.keys.Get(ctx, subject)
	if err != nil {
		if store.IsNotFound(err) {
			return fmt.Errorf("%w (user %s)", ErrErased, subject)
		}
		return fmt.Errorf("pii: load encryption key for %s: %w", subject, err)
	}
	dek, err := crypto.UnwrapDEK(o.kek, subject, rec.WrappedDEK)
	if err != nil {
		return fmt.Errorf("pii: key for user %s exists but does not unwrap — NOT projecting a sentinel (a KEK fault must never masquerade as erasure): %w", subject, err)
	}
	if err := crypto.OpenPayloadPII(dek, payload); err != nil {
		return fmt.Errorf("pii: open PII for %s: %w", subject, err)
	}
	return nil
}
