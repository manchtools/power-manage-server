// Package pii wires the spec-19 envelope-encryption crypto to the
// event store: the Sealer encrypts pii:"true" payload fields under the
// subject user's DEK before append (store.PIISealer), and the Opener
// decrypts them at projection-build time (projectors' decode hook).
//
// Subject resolution (spec 19): a payload on the "user" stream belongs
// to the user the stream is about — subject = stream_id. Off-stream
// PII (identity links, terminal-admin membership) must carry the
// owning user in a `user_id` payload field; a PII-bearing payload that
// resolves NO subject is a programming error and fails closed.
package pii

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/store"
)

// subjectFieldJSON is the json wire name of the payload field carrying
// the owning user's ULID for off-stream PII payloads. Pinned by the
// AC 3 guard (piiRegistry subjects) on the payloads side.
const subjectFieldJSON = "user_id"

// userStreamType is the stream whose stream_id IS the subject.
const userStreamType = "user"

// Sealer implements store.PIISealer: it resolves the subject user,
// loads + unwraps their DEK, and seals every tagged payload field.
// FAIL-CLOSED everywhere (AC 6): missing DEK, unwrappable DEK, or an
// unresolvable subject abort the append — plaintext PII never reaches
// the immutable log as a fallback.
type Sealer struct {
	kek  *crypto.Encryptor
	keys store.UserEncryptionKeyRepo
}

// NewSealer builds the sealer. Both dependencies are mandatory: a nil
// KEK cannot unwrap any DEK and would turn every PII append into an
// error at best.
func NewSealer(kek *crypto.Encryptor, keys store.UserEncryptionKeyRepo) (*Sealer, error) {
	if kek == nil {
		return nil, errors.New("pii: sealer requires the at-rest KEK")
	}
	if keys == nil {
		return nil, errors.New("pii: sealer requires the user_encryption_keys repo")
	}
	return &Sealer{kek: kek, keys: keys}, nil
}

// SealEvent implements store.PIISealer.
func (s *Sealer) SealEvent(ctx context.Context, e store.Event) (store.Event, error) {
	if e.Data == nil || len(crypto.PIIFieldNames(e.Data)) == 0 {
		return e, nil // no tagged fields — nothing to seal
	}
	subject, err := ResolveSubject(e.StreamType, e.StreamID, e.Data)
	if err != nil {
		return store.Event{}, err
	}
	dek, err := s.dekFor(ctx, subject)
	if err != nil {
		return store.Event{}, err
	}
	sealed, err := crypto.SealPayloadPII(dek, e.Data)
	if err != nil {
		return store.Event{}, fmt.Errorf("pii: seal %s for %s: %w", e.EventType, subject, err)
	}
	e.Data = sealed
	return e, nil
}

// dekFor loads and unwraps the subject's DEK. A missing row and an
// unwrappable row are BOTH append-time faults (AC 6): the subject is a
// live user being written about, so their key must exist and open.
func (s *Sealer) dekFor(ctx context.Context, userID string) (*crypto.DEK, error) {
	rec, err := s.keys.Get(ctx, userID)
	if err != nil {
		if store.IsNotFound(err) {
			return nil, fmt.Errorf("pii: cannot encrypt PII — no encryption key for user %s (mint one at user creation; appending plaintext PII is refused)", userID)
		}
		return nil, fmt.Errorf("pii: load encryption key for %s: %w", userID, err)
	}
	dek, err := crypto.UnwrapDEK(s.kek, userID, rec.WrappedDEK)
	if err != nil {
		return nil, fmt.Errorf("pii: cannot encrypt PII — key for user %s exists but does not unwrap (KEK mismatch/corruption): %w", userID, err)
	}
	return dek, nil
}

// ResolveSubject returns the owning user for a PII-bearing payload:
// stream_id on the user stream, else the payload's user_id field.
// Exported for the projector-side opener, which applies the same rule.
func ResolveSubject(streamType, streamID string, payload any) (string, error) {
	if streamType == userStreamType {
		if streamID == "" {
			return "", errors.New("pii: user-stream event without a stream_id")
		}
		return streamID, nil
	}
	v := reflect.ValueOf(payload)
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return "", errors.New("pii: nil payload cannot resolve a subject")
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return "", fmt.Errorf("pii: payload %T cannot resolve a subject", payload)
	}
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		name := tag
		if idx := strings.Index(tag, ","); idx >= 0 {
			name = tag[:idx]
		}
		if name != subjectFieldJSON {
			continue
		}
		f := v.Field(i)
		if f.Kind() == reflect.Pointer && !f.IsNil() {
			f = f.Elem()
		}
		if f.Kind() == reflect.String && f.String() != "" {
			return f.String(), nil
		}
	}
	return "", fmt.Errorf("pii: payload %T carries PII but resolves no subject — off-stream PII must populate a user_id field (spec 19 AC 3)", payload)
}

// Minter mints per-user DEKs at user creation (spec 19 AC 1). One
// narrow dependency handed to every user-provisioning path — the API
// handler, SCIM, the SSO linker, and the bootstrap admin seed — so a
// creation path can never forget the key the sealer will fail-closed
// without.
type Minter struct {
	kek  *crypto.Encryptor
	keys store.UserEncryptionKeyRepo
}

// NewMinter builds the minter; both dependencies are mandatory.
func NewMinter(kek *crypto.Encryptor, keys store.UserEncryptionKeyRepo) (*Minter, error) {
	if kek == nil {
		return nil, errors.New("pii: minter requires the at-rest KEK")
	}
	if keys == nil {
		return nil, errors.New("pii: minter requires the user_encryption_keys repo")
	}
	return &Minter{kek: kek, keys: keys}, nil
}

// MintUserDEK mints and stores a wrapped DEK for a new user. Must run
// BEFORE the user's first event is appended (the creation event itself
// carries PII the sealer needs the key for). First-write-wins under
// the hood: re-running for an existing user never replaces a key that
// may already have sealed PII.
func (m *Minter) MintUserDEK(ctx context.Context, userID string) error {
	wrapped, err := crypto.GenerateWrappedDEK(m.kek, userID)
	if err != nil {
		return err
	}
	if _, err := m.keys.Mint(ctx, userID, wrapped); err != nil {
		return err
	}
	return nil
}
