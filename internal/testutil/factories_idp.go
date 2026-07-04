package testutil

// Identity-provider, identity-link, SCIM, TOTP, and Encryptor
// fixtures. Everything that touches the SSO + 2FA + SCIM surface
// lives here so the file boundary mirrors the IdP code organization
// in internal/idp + internal/scim.

import (
	"context"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/manchtools/power-manage/server/internal/auth/totp"
	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
)

// NewEncryptor creates an Encryptor with a test key.
func NewEncryptor(t *testing.T) *crypto.Encryptor {
	t.Helper()
	// 32-byte hex key (64 hex chars)
	enc, err := crypto.NewEncryptor("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("create test encryptor: %v", err)
	}
	return enc
}

// SetupTOTP enables TOTP for a user and returns the TOTP secret.
// It creates the TOTPSetupInitiated and TOTPVerified events.
func SetupTOTP(t *testing.T, st *store.Store, enc *crypto.Encryptor, userID, email string) string {
	t.Helper()
	ctx := context.Background()

	key, err := totp.GenerateKey("Test", email)
	if err != nil {
		t.Fatalf("generate TOTP key: %v", err)
	}

	encryptedSecret, err := enc.EncryptWithContext(key.Secret(), crypto.RowAAD(userID, crypto.PurposeTOTPSecret))
	if err != nil {
		t.Fatalf("encrypt TOTP secret: %v", err)
	}

	// Generate backup codes
	_, hashes, err := totp.GenerateBackupCodes()
	if err != nil {
		t.Fatalf("generate backup codes: %v", err)
	}

	if err := st.AppendEvent(ctx, store.Event{
		StreamType: "totp",
		StreamID:   userID,
		EventType:  string(eventtypes.TOTPSetupInitiated),
		Data: map[string]any{
			"secret_encrypted":  encryptedSecret,
			"backup_codes_hash": hashes,
		},
		ActorType: "user",
		ActorID:   userID,
	}); err != nil {
		t.Fatalf("setup TOTP: %v", err)
	}

	if err := st.AppendEvent(ctx, store.Event{
		StreamType: "totp",
		StreamID:   userID,
		EventType:  string(eventtypes.TOTPVerified),
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userID,
	}); err != nil {
		t.Fatalf("verify TOTP: %v", err)
	}

	return key.Secret()
}

// SetupTOTPCheapBackup enables TOTP for a user with a SINGLE backup code whose
// hash uses bcrypt.MinCost, and returns the plaintext secret. Use it in tests
// that drive many FAILED VerifyLoginTOTP attempts: SetupTOTP provisions
// BackupCodeCount codes at the production bcrypt cost, so every failed attempt
// runs that many slow bcrypt compares (~seconds each). One MinCost code keeps
// the backup-code path valid — an empty array fails the TOTP projection's
// NOT NULL array column — while making each failed attempt cheap.
func SetupTOTPCheapBackup(t *testing.T, st *store.Store, enc *crypto.Encryptor, userID, email string) string {
	t.Helper()
	ctx := context.Background()

	key, err := totp.GenerateKey("Test", email)
	if err != nil {
		t.Fatalf("generate TOTP key: %v", err)
	}
	encryptedSecret, err := enc.EncryptWithContext(key.Secret(), crypto.RowAAD(userID, crypto.PurposeTOTPSecret))
	if err != nil {
		t.Fatalf("encrypt TOTP secret: %v", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte("unused-test-backup-code"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash backup code: %v", err)
	}

	if err := st.AppendEvent(ctx, store.Event{
		StreamType: "totp",
		StreamID:   userID,
		EventType:  string(eventtypes.TOTPSetupInitiated),
		Data: map[string]any{
			"secret_encrypted":  encryptedSecret,
			"backup_codes_hash": []string{string(hash)},
		},
		ActorType: "user",
		ActorID:   userID,
	}); err != nil {
		t.Fatalf("setup TOTP (cheap backup): %v", err)
	}
	if err := st.AppendEvent(ctx, store.Event{
		StreamType: "totp",
		StreamID:   userID,
		EventType:  string(eventtypes.TOTPVerified),
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userID,
	}); err != nil {
		t.Fatalf("verify TOTP (cheap backup): %v", err)
	}

	return key.Secret()
}

// CreateTestIdentityProvider creates an identity provider via events and returns the provider ID.
func CreateTestIdentityProvider(t *testing.T, st *store.Store, enc *crypto.Encryptor, actorID, name, slug string) string {
	t.Helper()
	ctx := context.Background()
	id := NewID()

	encSecret, err := enc.EncryptWithContext("test-client-secret", crypto.RowAAD(id, crypto.PurposeIdPClientSecret))
	if err != nil {
		t.Fatalf("encrypt test secret: %v", err)
	}

	err = st.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider",
		StreamID:   id,
		EventType:  string(eventtypes.IdentityProviderCreated),
		Data: map[string]any{
			"name":                    name,
			"slug":                    slug,
			"provider_type":           "oidc",
			"client_id":               "test-client-id",
			"client_secret_encrypted": encSecret,
			"issuer_url":              "https://idp.example.com",
			"scopes":                  []string{"openid", "profile", "email"},
			"auto_create_users":       false,
			"auto_link_by_email":      false,
		},
		ActorType: "user",
		ActorID:   actorID,
	})
	if err != nil {
		t.Fatalf("create test identity provider: %v", err)
	}

	return id
}

// CreateTestIdentityLink creates an identity link via events and returns the link ID.
func CreateTestIdentityLink(t *testing.T, st *store.Store, userID, providerID, externalID, externalEmail string) string {
	t.Helper()
	ctx := context.Background()
	id := NewID()

	err := st.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider",
		StreamID:   id,
		EventType:  string(eventtypes.IdentityLinked),
		Data: map[string]any{
			"user_id":        userID,
			"provider_id":    providerID,
			"external_id":    externalID,
			"external_email": externalEmail,
			"external_name":  "Test User",
		},
		ActorType: "system",
		ActorID:   "sso",
	})
	if err != nil {
		t.Fatalf("create test identity link: %v", err)
	}

	return id
}

// EnableSCIMForProvider enables SCIM on an identity provider and returns the plaintext bearer token.
func EnableSCIMForProvider(t *testing.T, st *store.Store, actorID, providerID string) string {
	t.Helper()
	ctx := context.Background()

	token := "scim-test-token-" + NewID()
	hash, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash SCIM token: %v", err)
	}

	err = st.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider",
		StreamID:   providerID,
		EventType:  string(eventtypes.IdentityProviderSCIMEnabled),
		Data: map[string]any{
			"scim_token_hash": string(hash),
		},
		ActorType: "user",
		ActorID:   actorID,
	})
	if err != nil {
		t.Fatalf("enable SCIM for provider: %v", err)
	}

	return token
}
