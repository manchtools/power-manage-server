// Package auth provides authentication and authorization for the control server.
package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/oklog/ulid/v2"
)

// TokenType distinguishes an access token from a refresh token. The
// type is part of the claims, so a refresh token presented as a bearer
// credential is rejected by the type check rather than admitted because
// its signature happens to verify.
type TokenType string

const (
	TokenTypeAccess  TokenType = "access"
	TokenTypeRefresh TokenType = "refresh"
)

// SigningAlgorithm is the one algorithm session tokens are signed with.
// Ed25519 is also the CA and leaf certificate algorithm, so the
// deployment has exactly one signature primitive to reason about.
var SigningAlgorithm = jwt.SigningMethodEdDSA

// ErrNoSigningKey is returned when a manager is constructed without
// usable key material. Minting or verifying without a key would either
// panic or accept anything, so both fail closed here.
var ErrNoSigningKey = errors.New("auth: no Ed25519 session signing key")

// Claims are the session-token claims.
type Claims struct {
	jwt.RegisteredClaims
	UserID         string        `json:"uid"`
	Email          string        `json:"email"`
	Permissions    []string      `json:"perms,omitempty"`
	ScopedGrants   []ScopedGrant `json:"sgrants,omitempty"`
	TokenType      TokenType     `json:"type"`
	SessionVersion int32         `json:"sv,omitempty"`
}

// JWTConfig holds the session-token configuration.
type JWTConfig struct {
	// PrivateKey signs. PublicKey verifies; it is derived from
	// PrivateKey when left nil.
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey

	AccessTokenExpiry  time.Duration
	RefreshTokenExpiry time.Duration
	Issuer             string
	// Now is the clock seam. Defaults to time.Now when nil; tests
	// inject a fixed clock to pin token issue/expiry timestamps.
	Now func() time.Time
}

// JWTManager mints and validates session tokens.
type JWTManager struct {
	config JWTConfig
}

// Session-token lifetimes.
//
// The access token carries the caller's permission set, so its lifetime
// bounds how long a revoked permission keeps working. Five minutes is
// short enough that no separate access-token deny-list is needed.
//
// The refresh token lives far longer, but every refresh re-reads the
// subject's session_version, disabled flag and permissions from the
// database, so a revocation propagates on the next refresh regardless.
const (
	DefaultAccessTokenExpiry  = 5 * time.Minute
	DefaultRefreshTokenExpiry = 7 * 24 * time.Hour
	// DefaultIssuer is the `iss` claim; validation requires it.
	DefaultIssuer = "power-manage"
)

// NewJWTManager creates a session-token manager. It refuses to build
// one without a usable Ed25519 private key: a manager with no key
// could neither sign nor verify, and returning one would push the
// failure to the first request instead of to startup.
func NewJWTManager(config JWTConfig) (*JWTManager, error) {
	if len(config.PrivateKey) != ed25519.PrivateKeySize {
		return nil, ErrNoSigningKey
	}
	if config.PublicKey == nil {
		pub, ok := config.PrivateKey.Public().(ed25519.PublicKey)
		if !ok {
			return nil, ErrNoSigningKey
		}
		config.PublicKey = pub
	}
	if config.AccessTokenExpiry == 0 {
		config.AccessTokenExpiry = DefaultAccessTokenExpiry
	}
	if config.RefreshTokenExpiry == 0 {
		config.RefreshTokenExpiry = DefaultRefreshTokenExpiry
	}
	if config.Issuer == "" {
		config.Issuer = DefaultIssuer
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &JWTManager{config: config}, nil
}

// GenerateSessionKey mints a fresh Ed25519 session-signing key.
func GenerateSessionKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate session signing key: %w", err)
	}
	return pub, priv, nil
}

// TokenPair is an access/refresh token pair.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

// AccessTokenTTL reports the configured access-token lifetime.
func (m *JWTManager) AccessTokenTTL() time.Duration { return m.config.AccessTokenExpiry }

// GenerateTokens mints an access/refresh pair for a subject.
//
// Permissions and scoped grants ride only on the access token: the
// refresh token is an identity assertion, and the authority it produces
// is resolved from the database at refresh time.
func (m *JWTManager) GenerateTokens(userID, email string, permissions []string, scopedGrants []ScopedGrant, sessionVersion int32) (*TokenPair, error) {
	now := m.config.Now()
	accessExpiry := now.Add(m.config.AccessTokenExpiry)
	entropy := ulid.Monotonic(rand.Reader, 0)

	accessJTI, err := ulid.New(ulid.Timestamp(now), entropy)
	if err != nil {
		return nil, fmt.Errorf("mint access token id: %w", err)
	}
	accessClaims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        accessJTI.String(),
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
	accessToken, err := jwt.NewWithClaims(SigningAlgorithm, accessClaims).SignedString(m.config.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("sign access token: %w", err)
	}

	refreshJTI, err := ulid.New(ulid.Timestamp(now), entropy)
	if err != nil {
		return nil, fmt.Errorf("mint refresh token id: %w", err)
	}
	refreshClaims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        refreshJTI.String(),
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
	refreshToken, err := jwt.NewWithClaims(SigningAlgorithm, refreshClaims).SignedString(m.config.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("sign refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    accessExpiry,
	}, nil
}

// ValidateToken parses and verifies a session token of the expected
// type.
//
// The signing method is pinned to EdDSA and the key is the Ed25519
// public key, so neither an algorithm substitution ("none", or an HMAC
// header verified against the public key as a shared secret) nor a
// token signed by another key can validate. Issuer and expiry are
// required.
func (m *JWTManager) ValidateToken(tokenString string, expectedType TokenType) (*Claims, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&Claims{},
		func(t *jwt.Token) (any, error) {
			if t.Method != jwt.SigningMethod(SigningAlgorithm) {
				return nil, fmt.Errorf("unexpected signing method %q", t.Method.Alg())
			}
			return m.config.PublicKey, nil
		},
		jwt.WithValidMethods([]string{SigningAlgorithm.Alg()}),
		jwt.WithIssuer(m.config.Issuer),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(m.config.Now),
	)
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
	if claims.UserID == "" {
		return nil, errors.New("token carries no subject")
	}
	return claims, nil
}

// RefreshResult carries the validated refresh claims plus the old
// token's identity, which the caller revokes before minting the
// replacement.
type RefreshResult struct {
	Claims *Claims
	OldJTI string
	OldExp time.Time
}

// ValidateRefreshToken validates a refresh token and checks it against
// the revocation list. isRevoked may be nil only in tests that do not
// exercise revocation; a nil check in production would make rotation
// replayable.
func (m *JWTManager) ValidateRefreshToken(refreshTokenString string, isRevoked func(string) (bool, error)) (*RefreshResult, error) {
	claims, err := m.ValidateToken(refreshTokenString, TokenTypeRefresh)
	if err != nil {
		return nil, fmt.Errorf("validate refresh token: %w", err)
	}
	if claims.ID == "" {
		return nil, errors.New("refresh token carries no id")
	}
	if isRevoked != nil {
		revoked, err := isRevoked(claims.ID)
		if err != nil {
			return nil, fmt.Errorf("check token revocation: %w", err)
		}
		if revoked {
			return nil, errors.New("refresh token has been revoked")
		}
	}
	var exp time.Time
	if claims.ExpiresAt != nil {
		exp = claims.ExpiresAt.Time
	}
	return &RefreshResult{Claims: claims, OldJTI: claims.ID, OldExp: exp}, nil
}
