// Package totp provides TOTP two-factor authentication functionality.
package totp

import (
	"fmt"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// DefaultIssuer is the default TOTP issuer name shown in authenticator apps.
const DefaultIssuer = "PowerManage"

// GenerateKey creates a new TOTP secret key for the given account.
func GenerateKey(issuer, account string) (*otp.Key, error) {
	if issuer == "" {
		issuer = DefaultIssuer
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: account,
	})
	if err != nil {
		return nil, fmt.Errorf("generate TOTP key: %w", err)
	}
	return key, nil
}

// ValidateCode validates a 6-digit TOTP code against the secret.
func ValidateCode(code, secret string) bool {
	return totp.Validate(code, secret)
}
