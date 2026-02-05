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
	TokenTypeAccess  TokenType = "access"
	TokenTypeRefresh TokenType = "refresh"
)

// Claims represents the JWT claims for user authentication.
type Claims struct {
	jwt.RegisteredClaims
	UserID         string    `json:"uid"`
	Email          string    `json:"email"`
	Role           string    `json:"role"`
	TokenType      TokenType `json:"type"`
	SessionVersion int32     `json:"sv,omitempty"`
}

// JWTConfig holds JWT configuration.
type JWTConfig struct {
	Secret             []byte
	AccessTokenExpiry  time.Duration
	RefreshTokenExpiry time.Duration
	Issuer             string
}

// JWTManager handles JWT token generation and validation.
type JWTManager struct {
	config JWTConfig
}

// NewJWTManager creates a new JWT manager.
func NewJWTManager(config JWTConfig) *JWTManager {
	if config.AccessTokenExpiry == 0 {
		config.AccessTokenExpiry = 15 * time.Minute
	}
	if config.RefreshTokenExpiry == 0 {
		config.RefreshTokenExpiry = 7 * 24 * time.Hour
	}
	if config.Issuer == "" {
		config.Issuer = "power-manage"
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
func (m *JWTManager) GenerateTokens(userID, email, role string, sessionVersion int32) (*TokenPair, error) {
	now := time.Now()
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
		Role:           role,
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
		Role:           role,
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

// ValidateToken validates a JWT token and returns the claims.
func (m *JWTManager) ValidateToken(tokenString string, expectedType TokenType) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
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

// RefreshResult contains the new token pair, the parsed refresh claims, and the old refresh token's JTI for revocation.
type RefreshResult struct {
	Tokens *TokenPair
	Claims *Claims
	OldJTI string
	OldExp time.Time
}

// RefreshAccessToken validates a refresh token, checks revocation, and generates a new token pair.
// The isRevoked callback checks whether the token's JTI has been revoked.
func (m *JWTManager) RefreshAccessToken(refreshTokenString string, isRevoked func(string) (bool, error)) (*RefreshResult, error) {
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

	tokens, err := m.GenerateTokens(claims.UserID, claims.Email, claims.Role, claims.SessionVersion)
	if err != nil {
		return nil, err
	}

	return &RefreshResult{
		Tokens: tokens,
		Claims: claims,
		OldJTI: claims.ID,
		OldExp: claims.ExpiresAt.Time,
	}, nil
}

// ValidateRefreshToken validates a refresh token and returns its claims.
// Used by the logout handler to extract the JTI for revocation.
func (m *JWTManager) ValidateRefreshToken(refreshTokenString string) (*Claims, error) {
	return m.ValidateToken(refreshTokenString, TokenTypeRefresh)
}
