// Package crypto provides application-level encryption for sensitive data
// stored in the database (LUKS passphrases, LPS passwords, IdP client
// secrets, TOTP secrets).
//
// ONE at-rest format (spec 20, closes audit F-06 / the WS10 deferral):
// AAD-bound AES-256-GCM under the prefix "enc:v1:". Every ciphertext is
// bound to its row context via additional authenticated data, so a
// DB-level attacker cannot relocate a secret from one row (or purpose)
// to another and have it decrypt. There is deliberately NO nil-AAD API:
// the naked Encrypt/Decrypt pair was removed so a new call site cannot
// regress to unbound ciphertext (a guard test additionally pins that
// AEAD primitives are not used outside this package).
//
// The encryption key is shared between the control server and gateway
// server via environment variable (CONTROL_ENCRYPTION_KEY, mandatory
// since WS11).
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

// prefix identifies AAD-bound AES-256-GCM ciphertext — the single
// at-rest format. Values carrying any OTHER "enc:*" prefix (the retired
// nil-AAD v1 or the pre-rename "enc:v2") fail loudly: the beta Path-A
// migration is a reprovision, and silently passing unknown ciphertext
// through as plaintext would be far worse than an error.
const prefix = "enc:v1:"

// Purpose tags for RowAAD — shared constants so the write and read
// paths can never drift apart on the AAD purpose dimension.
const (
	PurposeIdPClientSecret = "idp-client-secret"
	PurposeTOTPSecret      = "totp-secret"
)

// SecretAAD builds the additional-authenticated-data that binds a
// device-scoped at-rest secret to its row context. deviceID and actionID
// are ULIDs (Crockford base32 — they can never contain the '|'
// separator), and secretType is a fixed literal ("luks" / "lps"), so the
// concatenation is unambiguous.
func SecretAAD(deviceID, actionID, secretType string) []byte {
	return []byte(deviceID + "|" + actionID + "|" + secretType)
}

// RowAAD builds the AAD for a secret owned by a single row: the owning
// row's ULID plus a fixed purpose literal (see the Purpose* constants).
// Mirrors SecretAAD's unambiguous '|' concatenation; the two shapes
// cannot collide because SecretAAD always has three segments.
func RowAAD(rowID, purpose string) []byte {
	return []byte(rowID + "|" + purpose)
}

// Encryptor handles AES-256-GCM encryption and decryption of secret values.
type Encryptor struct {
	gcm cipher.AEAD
}

// NewEncryptor creates a new Encryptor from a hex-encoded 32-byte key.
// Returns nil if keyHex is empty (encryption disabled).
func NewEncryptor(keyHex string) (*Encryptor, error) {
	if keyHex == "" {
		return nil, nil
	}

	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid encryption key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes (64 hex chars), got %d bytes", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	return &Encryptor{gcm: gcm}, nil
}

// EncryptWithContext encrypts plaintext bound to aad and returns an
// "enc:v1:<base64>" string. The aad is authenticated (not stored in the
// ciphertext) — DecryptWithContext must be given the SAME aad to open
// it, so a secret sealed for one row context cannot be opened in
// another. An empty aad is refused (fail-closed): unbound ciphertext is
// exactly the regression this package's single-format contract forbids.
// Returns plaintext unchanged if e is nil (encryption disabled) or
// plaintext is empty.
func (e *Encryptor) EncryptWithContext(plaintext string, aad []byte) (string, error) {
	if e == nil || plaintext == "" {
		return plaintext, nil
	}
	if len(aad) == 0 {
		return "", errors.New("crypto: refusing to encrypt without an AAD context (nil-AAD path was removed — spec 20 / F-06)")
	}

	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := e.gcm.Seal(nonce, nonce, []byte(plaintext), aad)
	return prefix + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptWithContext decrypts an "enc:v1:<base64>" AAD-bound value.
//
//   - "enc:v1:" values open with the SAME aad they were sealed under;
//     a mismatched aad or tampered ciphertext fails GCM authentication.
//   - any OTHER "enc:*" prefix is a loud error: it is ciphertext from a
//     retired format (pre-spec-20 nil-AAD v1 or "enc:v2"); the deployment
//     must be reprovisioned (beta Path A), never silently mis-read.
//   - a non-prefixed value is returned unchanged (pre-encryption
//     plaintext; also the round-trip identity for the empty string).
//   - if e is nil (encryption disabled) the input passes through.
func (e *Encryptor) DecryptWithContext(value string, aad []byte) (string, error) {
	if e == nil {
		return value, nil
	}
	switch {
	case strings.HasPrefix(value, prefix):
		data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, prefix))
		if err != nil {
			return "", fmt.Errorf("decode ciphertext: %w", err)
		}
		nonceSize := e.gcm.NonceSize()
		if len(data) < nonceSize {
			return "", errors.New("ciphertext too short")
		}
		nonce, ciphertext := data[:nonceSize], data[nonceSize:]
		plaintext, err := e.gcm.Open(nil, nonce, ciphertext, aad)
		if err != nil {
			return "", fmt.Errorf("decrypt: %w", err)
		}
		return string(plaintext), nil
	case strings.HasPrefix(value, "enc:"):
		// Retired wire format (nil-AAD v1 or pre-rename enc:v2). Report
		// only the format tag, never ciphertext bytes.
		tag := value
		if i := strings.Index(value[len("enc:"):], ":"); i >= 0 {
			tag = value[:len("enc:")+i]
		}
		return "", fmt.Errorf("crypto: unsupported at-rest format %q — pre-spec-20 ciphertext requires reprovisioning (beta Path A), refusing to mis-read it", tag)
	default:
		// Pre-encryption plaintext.
		return value, nil
	}
}
