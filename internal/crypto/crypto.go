// Package crypto provides application-level encryption for sensitive data
// stored in the database (LUKS passphrases, LPS passwords).
//
// Uses AES-256-GCM with random nonces. The encryption key is shared between
// the control server and gateway server via environment variable.
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

const (
	// prefix (v1) identifies encrypted values sealed with NIL AAD. Kept for
	// backward compatibility: every row written before the AAD-binding change
	// (WS5 #8) carries this prefix and must keep decrypting.
	prefix = "enc:v1:"
	// prefixV2 identifies values sealed WITH context AAD (EncryptWithContext).
	// The AAD binds the ciphertext to its row context (device|action|type), so
	// a DB-level attacker cannot relocate a secret from one row to another and
	// have it decrypt.
	prefixV2 = "enc:v2:"
)

// SecretAAD builds the additional-authenticated-data that binds an at-rest
// secret to its row context. deviceID and actionID are ULIDs (Crockford
// base32 — they can never contain the '|' separator), and secretType is a fixed
// literal ("luks" / "lps"), so the concatenation is unambiguous.
func SecretAAD(deviceID, actionID, secretType string) []byte {
	return []byte(deviceID + "|" + actionID + "|" + secretType)
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

// Encrypt encrypts plaintext and returns an "enc:v1:<base64>" string.
// Returns plaintext unchanged if e is nil (encryption disabled).
func (e *Encryptor) Encrypt(plaintext string) (string, error) {
	if e == nil || plaintext == "" {
		return plaintext, nil
	}

	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := e.gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return prefix + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// EncryptWithContext encrypts plaintext bound to aad and returns an
// "enc:v2:<base64>" string. The aad is authenticated (not stored in the
// ciphertext) — DecryptWithContext must be given the SAME aad to open it, so a
// secret sealed for one row context cannot be opened in another. Returns
// plaintext unchanged if e is nil (encryption disabled) or plaintext is empty.
func (e *Encryptor) EncryptWithContext(plaintext string, aad []byte) (string, error) {
	if e == nil || plaintext == "" {
		return plaintext, nil
	}

	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := e.gcm.Seal(nonce, nonce, []byte(plaintext), aad)
	return prefixV2 + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts an "enc:v1:<base64>" string back to plaintext.
// Returns the input unchanged if it doesn't have the encryption prefix
// (supports reading pre-encryption plaintext data).
// Returns the input unchanged if e is nil (encryption disabled).
func (e *Encryptor) Decrypt(value string) (string, error) {
	if e == nil {
		return value, nil
	}
	if !strings.HasPrefix(value, prefix) {
		// Not encrypted — return as-is (pre-migration data)
		return value, nil
	}

	data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, prefix))
	if err != nil {
		return "", fmt.Errorf("decode ciphertext: %w", err)
	}

	nonceSize := e.gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := e.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}

	return string(plaintext), nil
}

// DecryptWithContext decrypts a value that may be either AAD-bound (enc:v2,
// opened with aad) or legacy nil-AAD (enc:v1, opened with no aad). A
// non-prefixed value is returned unchanged (pre-encryption plaintext). This is
// the read path for the LUKS/LPS at-rest secrets: new rows are enc:v2 bound to
// SecretAAD(device, action, type); rows written before the migration are still
// enc:v1 and open via the legacy fallback — no backfill required.
func (e *Encryptor) DecryptWithContext(value string, aad []byte) (string, error) {
	if e == nil {
		return value, nil
	}
	switch {
	case strings.HasPrefix(value, prefixV2):
		data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, prefixV2))
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
	case strings.HasPrefix(value, prefix):
		// Legacy nil-AAD ciphertext (written before WS5 #8).
		return e.Decrypt(value)
	default:
		// Pre-encryption plaintext.
		return value, nil
	}
}
