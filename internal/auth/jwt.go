// Package auth provides authentication and authorization for the control server.
package auth

import (
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/oklog/ulid/v2"
)

// TokenType distinguishes between access and refresh tokens.
type TokenType string

const (
	TokenTypeAccess        TokenType = "access"
	TokenTypeRefresh       TokenType = "refresh"
	TokenTypeTOTPChallenge TokenType = "totp_challenge"
)

// Claims represents the JWT claims for user authentication.
type Claims struct {
	jwt.RegisteredClaims
	UserID         string        `json:"uid"`
	Email          string        `json:"email"`
	Permissions    []string      `json:"perms,omitempty"`
	ScopedGrants   []ScopedGrant `json:"sgrants,omitempty"`
	TokenType      TokenType     `json:"type"`
	SessionVersion int32         `json:"sv,omitempty"`
}

// JWTConfig holds JWT configuration.
type JWTConfig struct {
	Secret             []byte
	AccessTokenExpiry  time.Duration
	RefreshTokenExpiry time.Duration
	Issuer             string
	// Now is the clock seam. Defaults to time.Now when nil; tests
	// inject a fixed clock to pin token issue/expiry timestamps.
	Now func() time.Time
}

// JWTManager handles JWT token generation and validation.
type JWTManager struct {
	config JWTConfig
}

// NewJWTManager creates a new JWT manager.
//
// AccessTokenExpiry defaults to 5 minutes (audit F-01 follow-up).
// The shorter window bounds permission-revocation staleness: when an
// admin revokes a user's permissions or disables their account, the
// existing access token continues to authorise the embedded
// permissions until it expires. 15 min was the prior default; 5 min
// is the SOC2-compatible upper bound for "access propagation" without
// needing a real-time revocation deny-list. Silent refresh on the
// client side keeps the user experience unchanged.
//
// RefreshTokenExpiry stays at 7 days — the refresh path consults the
// session-version table on every call, so revocation propagates to
// every refresh within the same window regardless of access-token
// TTL.
func NewJWTManager(config JWTConfig) *JWTManager {
	if config.AccessTokenExpiry == 0 {
		config.AccessTokenExpiry = 5 * time.Minute
	}
	if config.RefreshTokenExpiry == 0 {
		config.RefreshTokenExpiry = 7 * 24 * time.Hour
	}
	if config.Issuer == "" {
		config.Issuer = "power-manage"
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &JWTManager{config: config}
}

// TokenPair represents an access/refresh token pair.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

// GenerateTokens creates a new access/refresh token pair.
// Permissions and scoped grants are only embedded in the access token,
// not the refresh token.
func (m *JWTManager) GenerateTokens(userID, email string, permissions []string, scopedGrants []ScopedGrant, sessionVersion int32) (*TokenPair, error) {
	now := m.config.Now()
	accessExpiry := now.Add(m.config.AccessTokenExpiry)
	entropy := ulid.Monotonic(rand.Reader, 0)

	accessJTI := ulid.MustNew(ulid.Timestamp(now), entropy).String()
	accessClaims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        accessJTI,
			Issuer:    m.config.Issuer,
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(accessExpiry),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		UserID:         userID,
		Email:          email,
		Permissions:    permissions,
		ScopedGrants:   scopedGrants,
		TokenType:      TokenTypeAccess,
		SessionVersion: sessionVersion,
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(m.config.Secret)
	if err != nil {
		return nil, fmt.Errorf("sign access token: %w", err)
	}

	refreshJTI := ulid.MustNew(ulid.Timestamp(now), entropy).String()
	refreshClaims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        refreshJTI,
			Issuer:    m.config.Issuer,
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(now.Add(m.config.RefreshTokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		UserID:         userID,
		Email:          email,
		TokenType:      TokenTypeRefresh,
		SessionVersion: sessionVersion,
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(m.config.Secret)
	if err != nil {
		return nil, fmt.Errorf("sign refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessTokenString,
		RefreshToken: refreshTokenString,
		ExpiresAt:    accessExpiry,
	}, nil
}

// GenerateTOTPChallenge creates a short-lived JWT (5 minutes) for TOTP verification during login.
func (m *JWTManager) GenerateTOTPChallenge(userID, email string, sessionVersion int32) (string, error) {
	now := m.config.Now()
	entropy := ulid.Monotonic(rand.Reader, 0)
	jti := ulid.MustNew(ulid.Timestamp(now), entropy).String()

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Issuer:    m.config.Issuer,
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		UserID:         userID,
		Email:          email,
		TokenType:      TokenTypeTOTPChallenge,
		SessionVersion: sessionVersion,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(m.config.Secret)
	if err != nil {
		return "", fmt.Errorf("sign TOTP challenge token: %w", err)
	}
	return tokenString, nil
}

// ValidateToken validates a JWT token and returns the claims.
func (m *JWTManager) ValidateToken(tokenString string, expectedType TokenType) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Pin the algorithm to HS256 (audit F-14). Accepting any
		// HMAC family lets an attacker forge a token under HS384 /
		// HS512 if the shared secret length supports it — issuance
		// always uses HS256 (jwt.SigningMethodHS256 in GenerateAccessToken
		// / GenerateRefreshToken / TOTP challenge), so anything else
		// is by definition forged.
		if token.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.config.Secret, nil
	})
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	if claims.TokenType != expectedType {
		return nil, fmt.Errorf("unexpected token type: expected %s, got %s", expectedType, claims.TokenType)
	}

	return claims, nil
}

// RefreshResult contains the parsed refresh claims and the old refresh token's JTI for revocation.
// The caller is responsible for resolving fresh permissions from DB and calling GenerateTokens.
type RefreshResult struct {
	Claims *Claims
	OldJTI string
	OldExp time.Time
}

// ValidateRefreshToken validates a refresh token, checks revocation, and returns its claims.
// The caller should then resolve fresh permissions from DB and generate new tokens.
func (m *JWTManager) ValidateRefreshToken(refreshTokenString string, isRevoked func(string) (bool, error)) (*RefreshResult, error) {
	claims, err := m.ValidateToken(refreshTokenString, TokenTypeRefresh)
	if err != nil {
		return nil, fmt.Errorf("validate refresh token: %w", err)
	}

	// Check if this refresh token has been revoked
	if claims.ID != "" && isRevoked != nil {
		revoked, err := isRevoked(claims.ID)
		if err != nil {
			return nil, fmt.Errorf("check token revocation: %w", err)
		}
		if revoked {
			return nil, errors.New("refresh token has been revoked")
		}
	}

	return &RefreshResult{
		Claims: claims,
		OldJTI: claims.ID,
		OldExp: claims.ExpiresAt.Time,
	}, nil
}
