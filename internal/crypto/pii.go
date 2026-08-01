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

// Per-user PII envelope encryption provides crypto-shred for audit detail.
// Every user gets one random DEK, KEK-wrapped in user_encryption_keys. Audit
// fields classified as personal detail are sealed under that subject's DEK.
// Deleting the user destroys the DEK row and makes retained detail unreadable.

// piiPrefix tags a DEK-sealed PII field value. Distinct from the
// at-rest "enc:v1:" tag so the two encryption layers cannot be confused.
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
// caller must treat as such. Only a missing DEK row is the graceful erased
// state; a present-but-unwrappable one must never
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
// field. Empty values stay empty because absent detail must not materialize as
// ciphertext.
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

// OpenField decrypts one sealed PII field value. Plaintext fails closed.
func (d *DEK) OpenField(value, field string) (string, error) {
	if value == "" {
		return "", nil
	}
	if !strings.HasPrefix(value, piiPrefix) {
		return "", errors.New("crypto: plaintext PII rejected")
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
