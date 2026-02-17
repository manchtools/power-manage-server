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
	// prefix identifies encrypted values so they can be distinguished
	// from plaintext during migration.
	prefix = "enc:v1:"
)

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
