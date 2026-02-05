package auth

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

const bcryptCost = 14

// DummyHash is a pre-computed bcrypt hash used for constant-time login checks
// when the user does not exist, preventing timing-based user enumeration.
var DummyHash = func() string {
	h, _ := bcrypt.GenerateFromPassword([]byte("dummy-password-for-timing"), bcryptCost)
	return string(h)
}()

// HashPassword hashes a password using bcrypt.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(hash), nil
}

// VerifyPassword checks if a password matches a hash.
func VerifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
