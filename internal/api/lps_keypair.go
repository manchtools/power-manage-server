package api

import (
	"context"
	"crypto/ecdh"
	"errors"
	"fmt"

	sdkcrypto "github.com/manchtools/power-manage-sdk/crypto"
	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/verify"

	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// advisoryKeyLpsKeypair serializes EnsureLpsKeypair across control replicas so
// two booting instances cannot both generate and race to insert a keypair. The
// value is "lpskey" in hex; it only needs to be a stable constant distinct from
// any other advisory lock.
const advisoryKeyLpsKeypair int64 = 0x6c70736b6579

// lpsKeypairAAD binds the at-rest private key to its row. The keypair is a
// single global row, so a fixed context suffices — it still domain-separates
// the LPS private key from every other enc:v2 secret (LUKS/LPS passwords keyed
// by device|action|type).
func lpsKeypairAAD() []byte {
	return crypto.SecretAAD("global", "lps-keypair", "lps-keypair-priv")
}

// EnsureLpsKeypair loads the control server's LPS sealing keypair, generating
// and persisting it on first boot. The private key is stored ONLY in enc:v2
// form (AAD-bound); a nil encryptor is refused because the key cannot be
// protected at rest. Generation is serialized by an advisory lock and the
// INSERT is first-writer-wins (ON CONFLICT DO NOTHING), so concurrent replicas
// converge on a single keypair — a lost race re-reads the winner rather than
// clobbering it. Returns the parsed private key (for unsealing) and the raw
// 32-byte public key (for signed distribution to agents).
func EnsureLpsKeypair(ctx context.Context, st *store.Store, enc *crypto.Encryptor) (priv *ecdh.PrivateKey, publicKey []byte, err error) {
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

	lockErr := st.WithAdvisoryLock(ctx, advisoryKeyLpsKeypair, func() error {
		// Fast path: already generated.
		if row, gerr := st.Queries().GetLpsKeypair(ctx); gerr == nil {
			priv, publicKey, err = decodeLpsKeypair(enc, row.PublicKey, row.PrivateKeyEnc)
			return err
		} else if !store.IsNotFound(gerr) {
			return fmt.Errorf("load lps keypair: %w", gerr)
		}

		// First boot: generate, encrypt the private key, persist.
		newPriv, gerr := sdkcrypto.GenerateX25519()
		if gerr != nil {
			return fmt.Errorf("generate lps keypair: %w", gerr)
		}
		pubRaw := newPriv.PublicKey().Bytes()
		privEnc, gerr := enc.EncryptWithContext(string(newPriv.Bytes()), lpsKeypairAAD())
		if gerr != nil {
			return fmt.Errorf("encrypt lps private key: %w", gerr)
		}

		n, gerr := st.Queries().InsertLpsKeypair(ctx, db.InsertLpsKeypairParams{
			PublicKey:     pubRaw,
			PrivateKeyEnc: privEnc,
		})
		if gerr != nil {
			return fmt.Errorf("persist lps keypair: %w", gerr)
		}
		if n == 0 {
			// Another writer won between our read and insert; re-read the
			// persisted winner so every replica converges on the same key.
			row, rerr := st.Queries().GetLpsKeypair(ctx)
			if rerr != nil {
				return fmt.Errorf("reload lps keypair after conflict: %w", rerr)
			}
			priv, publicKey, err = decodeLpsKeypair(enc, row.PublicKey, row.PrivateKeyEnc)
			return err
		}
		priv, publicKey = newPriv, pubRaw
		return nil
	})
	if lockErr != nil {
		return nil, nil, lockErr
	}
	return priv, publicKey, err
}

// decodeLpsKeypair reconstructs the private key from a stored row: decrypt the
// enc:v2 private key, parse both halves.
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
	msg := &pm.LpsPublicKey{PublicKey: publicKey}
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
