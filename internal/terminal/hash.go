package terminal

import (
	"crypto/sha256"
	"encoding/hex"
)

// hashToken returns the hex-encoded SHA-256 of the bearer token.
// Used to store and compare tokens at rest without persisting the
// plaintext anywhere.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
