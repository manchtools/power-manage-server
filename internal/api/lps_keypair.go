package api

import (
	"context"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"fmt"

	sdkcrypto "github.com/manchtools/power-manage-sdk/crypto"
	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/verify"

	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// lpsKeypairStreamType / lpsKeypairStreamID name the singleton event stream
// the keypair is sourced from (#495). Mirrors the server_settings "global"
// singleton convention: fixed stream type, fixed stream id, so the
// UNIQUE(stream_type, stream_id, stream_version) constraint on events makes
// the version-1 append first-writer-wins across replicas — the OCC append
// replaces the pre-#495 advisory lock + direct INSERT.
const (
	lpsKeypairStreamType = "lps_keypair"
	lpsKeypairStreamID   = "global"
)

// lpsKeypairAAD binds the at-rest private key to its row. The keypair is a
// single global row, so a fixed context suffices — it still domain-separates
// the LPS private key from every other enc:v1 secret (LUKS/LPS passwords keyed
// by device|action|type).
func lpsKeypairAAD() []byte {
	return crypto.SecretAAD("global", "lps-keypair", "lps-keypair-priv")
}

// EnsureLpsKeypair loads the control server's LPS sealing keypair, generating
// it on first boot. The private key is stored ONLY in enc:v1 form (AAD-bound);
// a nil encryptor is refused because the key cannot be protected at rest.
//
// Event-sourced (#495): the ONLY write is an LpsKeypairGenerated append at
// stream version 1 — the events UNIQUE(stream_type, stream_id, stream_version)
// constraint is the cross-replica first-writer-wins, and the lps_keypair table
// is a projection materialised by projectors.LpsKeypairListener (so replay
// reproduces it 1:1). A losing replica's append fails with ErrVersionConflict
// and it adopts the winner's keypair FROM THE STREAM — not from the projection
// row, which the winner's post-commit listener may not have written yet.
//
// Upgrade path: a pre-#495 deployment has the row but no stream. The row's
// content is backfilled as a synthetic LpsKeypairGenerated (idempotent — a
// concurrent replica's backfill winning the version-1 slot is fine) so the
// replay guarantee holds for upgraded deployments too.
//
// MUST run after projectors.WireAll (the #317 bootstrap ordering): the
// generation append relies on the synchronous listener to materialise the
// projection row.
//
// Returns the parsed private key (for unsealing) and the raw 32-byte public
// key (for signed distribution to agents).
func EnsureLpsKeypair(ctx context.Context, st *store.Store, enc *crypto.Encryptor) (*ecdh.PrivateKey, []byte, error) {
	if st == nil {
		return nil, nil, errors.New("lps keypair: nil store")
	}
	// The at-rest private key MUST be encrypted. WS11 made encryption
	// mandatory (no plaintext, even by accident); a nil encryptor here is a
	// wiring/config failure, not a mode — fail closed rather than persist a
	// bare private key.
	if enc == nil {
		return nil, nil, errors.New("lps keypair: encryptor required to protect the private key at rest")
	}

	// Fast path: projection row exists (normal restarts).
	if row, gerr := st.Queries().GetLpsKeypair(ctx); gerr == nil {
		if err := backfillLpsKeypairStream(ctx, st, row); err != nil {
			return nil, nil, err
		}
		return decodeLpsKeypair(enc, row.PublicKey, row.PrivateKeyEnc)
	} else if !store.IsNotFound(gerr) {
		return nil, nil, fmt.Errorf("load lps keypair: %w", gerr)
	}

	// First boot: generate, encrypt the private key, append at version 1.
	newPriv, gerr := sdkcrypto.GenerateX25519()
	if gerr != nil {
		return nil, nil, fmt.Errorf("generate lps keypair: %w", gerr)
	}
	pubRaw := newPriv.PublicKey().Bytes()
	privEnc, gerr := enc.EncryptWithContext(string(newPriv.Bytes()), lpsKeypairAAD())
	if gerr != nil {
		return nil, nil, fmt.Errorf("encrypt lps private key: %w", gerr)
	}

	appendErr := st.AppendEventWithVersion(ctx, store.Event{
		StreamType: lpsKeypairStreamType,
		StreamID:   lpsKeypairStreamID,
		EventType:  string(eventtypes.LpsKeypairGenerated),
		Data: payloads.LpsKeypairGenerated{
			PublicKey:     pubRaw,
			PrivateKeyEnc: privEnc,
		},
		ActorType: "system",
		ActorID:   "system",
	}, 1)
	if appendErr == nil {
		// We won the version-1 slot; the synchronous listener has already
		// materialised the projection row.
		return newPriv, pubRaw, nil
	}
	if !errors.Is(appendErr, store.ErrVersionConflict) {
		return nil, nil, fmt.Errorf("persist lps keypair event: %w", appendErr)
	}
	// Lost the race: another replica's LpsKeypairGenerated owns version 1.
	// Our generated key is discarded; adopt the winner's from the stream.
	return adoptLpsKeypairFromStream(ctx, st, enc)
}

// backfillLpsKeypairStream materialises the #495 upgrade path: a pre-#495
// deployment carries the lps_keypair row but no lps_keypair/global stream.
// Appending a synthetic LpsKeypairGenerated with the row's exact content
// (including its original created_at) makes the replay guarantee hold for
// upgraded deployments — the projector reproduces the row byte-for-byte.
// Idempotent: once the stream exists this is a no-op, and a concurrent
// replica winning the version-1 slot is indistinguishable from ours winning
// (both carry the same row content).
func backfillLpsKeypairStream(ctx context.Context, st *store.Store, row db.GetLpsKeypairRow) error {
	events, err := st.LoadStream(ctx, lpsKeypairStreamType, lpsKeypairStreamID)
	if err != nil {
		return fmt.Errorf("load lps keypair stream: %w", err)
	}
	if len(events) > 0 {
		return nil
	}
	payload := payloads.LpsKeypairGenerated{
		PublicKey:     row.PublicKey,
		PrivateKeyEnc: row.PrivateKeyEnc,
	}
	if row.CreatedAt.Valid {
		t := row.CreatedAt.Time
		payload.CreatedAt = &t
	}
	appendErr := st.AppendEventWithVersion(ctx, store.Event{
		StreamType: lpsKeypairStreamType,
		StreamID:   lpsKeypairStreamID,
		EventType:  string(eventtypes.LpsKeypairGenerated),
		Data:       payload,
		ActorType:  "system",
		ActorID:    "system",
	}, 1)
	if appendErr != nil && !errors.Is(appendErr, store.ErrVersionConflict) {
		return fmt.Errorf("backfill lps keypair event: %w", appendErr)
	}
	return nil
}

// adoptLpsKeypairFromStream decodes the winning replica's keypair from the
// event stream. Reading the STREAM rather than the projection row closes the
// cross-replica window where the winner's event is committed but its
// post-commit listener has not yet written the row.
func adoptLpsKeypairFromStream(ctx context.Context, st *store.Store, enc *crypto.Encryptor) (*ecdh.PrivateKey, []byte, error) {
	events, err := st.LoadStream(ctx, lpsKeypairStreamType, lpsKeypairStreamID)
	if err != nil {
		return nil, nil, fmt.Errorf("load lps keypair stream: %w", err)
	}
	if len(events) == 0 {
		return nil, nil, errors.New("lps keypair: version conflict but stream is empty")
	}
	first := events[0]
	if first.EventType != string(eventtypes.LpsKeypairGenerated) {
		return nil, nil, fmt.Errorf("lps keypair: unexpected first stream event %q", first.EventType)
	}
	var p payloads.LpsKeypairGenerated
	if err := json.Unmarshal(first.Data, &p); err != nil {
		return nil, nil, fmt.Errorf("decode LpsKeypairGenerated payload: %w", err)
	}
	return decodeLpsKeypair(enc, p.PublicKey, p.PrivateKeyEnc)
}

// decodeLpsKeypair reconstructs the private key from a stored row: decrypt the
// enc:v1 private key, parse both halves.
func decodeLpsKeypair(enc *crypto.Encryptor, pubRaw []byte, privEnc string) (*ecdh.PrivateKey, []byte, error) {
	privBytes, err := enc.DecryptWithContext(privEnc, lpsKeypairAAD())
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt lps private key: %w", err)
	}
	priv, err := ecdh.X25519().NewPrivateKey([]byte(privBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("parse lps private key: %w", err)
	}
	// Sanity: the stored public key must match the private key it pairs with,
	// or a corrupted/mismatched row would silently hand agents a key control
	// can't decrypt to.
	if !priv.PublicKey().Equal(mustPublic(pubRaw)) {
		return nil, nil, errors.New("lps keypair: stored public key does not match private key")
	}
	return priv, pubRaw, nil
}

// mustPublic parses a raw public key, returning a zero key on malformed input
// so the Equal check in decodeLpsKeypair fails closed rather than panicking.
func mustPublic(raw []byte) *ecdh.PublicKey {
	pub, err := sdkcrypto.ParseX25519PublicKey(raw)
	if err != nil {
		return &ecdh.PublicKey{}
	}
	return pub
}

// BuildSignedLpsPublicKey mints the CA-signed LpsPublicKey the sync response
// carries. The agent verifies this signature against its enrollment CA before
// trusting the key, so a relaying gateway cannot substitute its own key. Signed
// once at boot (the CA key and the LPS key are both stable) and cached.
func BuildSignedLpsPublicKey(publicKey []byte, signer ca.ActionSigner) (*pm.LpsPublicKey, error) {
	if signer == nil {
		return nil, errors.New("lps keypair: nil signer; cannot sign public key for distribution")
	}
	// Parse before signing: reject a nil/malformed key up front (never
	// distribute a CA-signed unusable key), and use the parsed key's own
	// Bytes() so the signed message owns a copy — a later mutation of the
	// caller's slice cannot desync the bytes from the signature.
	pub, err := sdkcrypto.ParseX25519PublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("parse lps public key for signing: %w", err)
	}
	msg := &pm.LpsPublicKey{PublicKey: pub.Bytes()}
	canonical, err := verify.LpsPublicKeyCanonical(msg)
	if err != nil {
		return nil, fmt.Errorf("canonicalize lps public key: %w", err)
	}
	sig, err := signer.SignDomain(verify.LpsPublicKeySignatureDomain, canonical)
	if err != nil {
		return nil, fmt.Errorf("sign lps public key: %w", err)
	}
	msg.Signature = sig
	return msg, nil
}
