package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Spec 19 stage A — per-user PII envelope encryption ("crypto-shred").
//
// Every user gets one random 32-byte data-encryption key (DEK), stored
// KEK-wrapped in user_encryption_keys. PII fields on typed event
// payloads (tagged pii:"true") are sealed under the SUBJECT user's DEK
// before append; projectors unseal at projection-build time. Deleting
// the user destroys the DEK row, which makes every copy of their PII —
// live log, cold archives, future rebuilds — permanently unreadable at
// once, without ever mutating the append-only event log.

// piiPrefix tags a DEK-sealed PII field value. Distinct from the
// at-rest "enc:v1:" tag so a projector (and a human reading an event
// row) can tell DEK-sealed PII from KEK-sealed secrets and from
// legacy plaintext.
const piiPrefix = "pii:v1:"

// PurposeUserDEK is the RowAAD purpose binding a wrapped DEK to its
// owning user row in user_encryption_keys.
const PurposeUserDEK = "user-dek"

// DEK is one user's unwrapped data-encryption key, ready to seal/open
// PII field values. Obtain via UnwrapDEK; never persist it — only the
// KEK-wrapped form (GenerateWrappedDEK) touches the database.
type DEK struct {
	gcm cipher.AEAD
}

// GenerateWrappedDEK mints a fresh random 32-byte DEK for userID and
// returns it KEK-wrapped in the single at-rest format ("enc:v1:",
// AAD-bound to the owning user via RowAAD(userID, PurposeUserDEK)).
// The plaintext DEK never leaves this function. A nil KEK is refused:
// persisting unprotected key material would silently void the entire
// envelope (fail closed).
func GenerateWrappedDEK(kek *Encryptor, userID string) (string, error) {
	if kek == nil {
		return "", errors.New("crypto: refusing to mint a DEK without a KEK — the wrapped key would be stored unprotected")
	}
	if userID == "" {
		return "", errors.New("crypto: refusing to mint a DEK without an owning user id")
	}
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", fmt.Errorf("generate DEK: %w", err)
	}
	wrapped, err := kek.EncryptWithContext(base64.StdEncoding.EncodeToString(raw), RowAAD(userID, PurposeUserDEK))
	if err != nil {
		return "", fmt.Errorf("wrap DEK: %w", err)
	}
	return wrapped, nil
}

// UnwrapDEK opens a KEK-wrapped DEK for userID. A wrap that fails to
// open (wrong KEK, wrong user binding, corruption) is a FAULT the
// caller must treat as such — spec 19 AC 10: only a MISSING DEK row is
// the graceful erased state; a present-but-unwrappable one must never
// masquerade as erasure.
func UnwrapDEK(kek *Encryptor, userID, wrapped string) (*DEK, error) {
	if kek == nil {
		return nil, errors.New("crypto: cannot unwrap a DEK without a KEK")
	}
	b64, err := kek.DecryptWithContext(wrapped, RowAAD(userID, PurposeUserDEK))
	if err != nil {
		return nil, fmt.Errorf("unwrap DEK for %s: %w", userID, err)
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("unwrap DEK for %s: invalid key material", userID)
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, fmt.Errorf("unwrap DEK for %s: %w", userID, err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("unwrap DEK for %s: %w", userID, err)
	}
	return &DEK{gcm: gcm}, nil
}

// SealField encrypts one PII field value under the DEK, AAD-bound to
// the field name so a sealed value cannot be relocated to a different
// field. Empty values pass through empty (omitempty wire compat — an
// absent optional field must not materialise as ciphertext).
func (d *DEK) SealField(plaintext, field string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	if field == "" {
		return "", errors.New("crypto: refusing to seal PII without a field binding")
	}
	nonce := make([]byte, d.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	ct := d.gcm.Seal(nonce, nonce, []byte(plaintext), []byte(field))
	return piiPrefix + base64.StdEncoding.EncodeToString(ct), nil
}

// OpenField decrypts one sealed PII field value. A value without the
// pii prefix passes through unchanged: events appended before envelope
// encryption carry plaintext PII and must keep projecting (documented
// beta stance — no backfill).
func (d *DEK) OpenField(value, field string) (string, error) {
	if !strings.HasPrefix(value, piiPrefix) {
		return value, nil
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, piiPrefix))
	if err != nil {
		return "", fmt.Errorf("decode PII ciphertext: %w", err)
	}
	nonceSize := d.gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("PII ciphertext too short")
	}
	nonce, ct := data[:nonceSize], data[nonceSize:]
	pt, err := d.gcm.Open(nil, nonce, ct, []byte(field))
	if err != nil {
		return "", fmt.Errorf("open PII field %s: %w", field, err)
	}
	return string(pt), nil
}
