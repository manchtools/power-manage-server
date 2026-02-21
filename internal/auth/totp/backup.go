package totp

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const (
	// BackupCodeCount is the number of backup codes generated.
	BackupCodeCount = 10
	// BackupCodeLength is the byte length of each backup code (8 hex chars).
	BackupCodeLength = 4
	bcryptCost       = 12
)

// GenerateBackupCodes creates a set of random backup codes and their bcrypt hashes.
// Returns (plaintext codes, bcrypt hashes, error).
func GenerateBackupCodes() ([]string, []string, error) {
	codes := make([]string, BackupCodeCount)
	hashes := make([]string, BackupCodeCount)

	for i := range BackupCodeCount {
		b := make([]byte, BackupCodeLength)
		if _, err := rand.Read(b); err != nil {
			return nil, nil, fmt.Errorf("generate backup code: %w", err)
		}
		code := hex.EncodeToString(b)
		codes[i] = code

		hash, err := bcrypt.GenerateFromPassword([]byte(code), bcryptCost)
		if err != nil {
			return nil, nil, fmt.Errorf("hash backup code: %w", err)
		}
		hashes[i] = string(hash)
	}

	return codes, hashes, nil
}

// VerifyBackupCode checks a code against a list of bcrypt hashes and returns
// the index of the matching code, or -1 if no match. Only unused codes
// (where used[i] == false) are checked.
func VerifyBackupCode(code string, hashes []string, used []bool) int {
	code = strings.TrimSpace(code)
	for i, hash := range hashes {
		if i < len(used) && used[i] {
			continue
		}
		if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(code)); err == nil {
			return i
		}
	}
	return -1
}
