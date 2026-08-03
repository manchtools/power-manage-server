// Package crypto provides application-level encryption for sensitive data
// stored in the database: LUKS passphrases, LPS passwords, IdP client secrets,
// and per-subject audit-detail keys.
//
// The at-rest format is AAD-bound AES-256-GCM under the prefix "enc:v1:". Every ciphertext is
// bound to its row context via additional authenticated data, so a
// DB-level attacker cannot relocate a secret from one row (or purpose)
// to another and have it decrypt. There is deliberately NO nil-AAD API:
// the naked Encrypt/Decrypt pair was removed so a new call site cannot
// regress to unbound ciphertext (a guard test additionally pins that
// AEAD primitives are not used outside this package).
//
// The encryption key is loaded by the control server from its configured secret
// file or deployment override.
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

// prefix identifies the single AAD-bound AES-256-GCM at-rest format.
// Values carrying any other format, including plaintext, fail closed.
const prefix = "enc:v1:"

// Purpose tags for RowAAD — shared constants so the write and read
// paths can never drift apart on the AAD purpose dimension.
const (
	PurposeIdPClientSecret = "idp-client-secret"
)

// SecretAAD builds the additional-authenticated-data that binds a
// device-scoped at-rest secret to its row context. deviceID and actionID
// are ULIDs (Crockford base32 — they can never contain the '|'
// separator), and secretType is a fixed literal ("luks" / "lps"), so the
// concatenation is unambiguous.
func SecretAAD(deviceID, actionID, secretType string) []byte {
	return []byte(deviceID + "|" + actionID + "|" + secretType)
}

// SecretAADForRow extends SecretAAD with the per-row discriminator that
// distinguishes sibling secrets sharing one (deviceID, actionID). The
// discriminator is the secret row's immutable ULID primary key. LPS and LUKS
// keep MULTIPLE rotation rows per (deviceID, actionID, username|device_path) —
// the current row plus its history — so the username or device_path is NOT a
// unique per-row discriminator: every rotation row for one username shares it,
// leaving their ciphertexts interchangeable. The globally-unique row id is, so
// a DB-level attacker cannot relocate a ciphertext onto a sibling row (a later
// rotation of the same username included) and have it decrypt under that row's
// context.
//
// deviceID, actionID, and the discriminator are all ULIDs and secretType is a
// fixed literal, so no '|'-separated segment ever contains '|' and the four-
// segment concatenation is unambiguous. The four-segment form also cannot
// collide with SecretAAD's three-segment form.
func SecretAADForRow(deviceID, actionID, secretType, discriminator string) []byte {
	return []byte(deviceID + "|" + actionID + "|" + secretType + "|" + discriminator)
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
// An empty key is rejected; control cannot run without at-rest encryption.
func NewEncryptor(keyHex string) (*Encryptor, error) {
	if keyHex == "" {
		return nil, errors.New("encryption key is required")
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
// another. A missing encryptor or empty AAD is refused. Empty plaintext remains
// empty, but non-empty plaintext always becomes ciphertext.
func (e *Encryptor) EncryptWithContext(plaintext string, aad []byte) (string, error) {
	if e == nil {
		return "", errors.New("crypto: encryptor is required")
	}
	if len(aad) == 0 {
		return "", errors.New("crypto: AAD context is required")
	}
	if plaintext == "" {
		return "", nil
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
//   - any other "enc:*" prefix is rejected;
//   - non-empty plaintext is rejected; and
//   - an empty value round-trips as empty.
func (e *Encryptor) DecryptWithContext(value string, aad []byte) (string, error) {
	if e == nil {
		return "", errors.New("crypto: encryptor is required")
	}
	if len(aad) == 0 {
		return "", errors.New("crypto: AAD context is required")
	}
	if value == "" {
		return "", nil
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
		// Report only the format tag, never ciphertext bytes.
		tag := value
		if i := strings.Index(value[len("enc:"):], ":"); i >= 0 {
			tag = value[:len("enc:")+i]
		}
		return "", fmt.Errorf("crypto: unsupported at-rest format %q", tag)
	default:
		return "", errors.New("crypto: plaintext value rejected")
	}
}
