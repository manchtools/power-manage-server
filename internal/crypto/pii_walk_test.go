package crypto_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/crypto"
)

// The walker seals/opens exactly the pii:"true"-tagged string fields
// of a typed payload struct, leaving everything else untouched. It is
// the mechanism behind spec 19 AC 2/3: the PII set is code-declared on
// the payload structs and self-discovered by reflection — never a
// hand-maintained list.

type walkFixture struct {
	Email       string  `json:"email" pii:"true"`
	DisplayName *string `json:"display_name,omitempty" pii:"true"`
	Untagged    string  `json:"untagged"`
	Count       int     `json:"count"`
}

func mintDEK(t *testing.T, userID string) *crypto.DEK {
	t.Helper()
	kek := newKEK(t)
	wrapped, err := crypto.GenerateWrappedDEK(kek, userID)
	require.NoError(t, err)
	dek, err := crypto.UnwrapDEK(kek, userID, wrapped)
	require.NoError(t, err)
	return dek
}

func TestPIIFieldNames_SelfDiscovered(t *testing.T) {
	names := crypto.PIIFieldNames(walkFixture{})
	assert.ElementsMatch(t, []string{"email", "display_name"}, names,
		"the PII set is exactly the pii-tagged fields, keyed by json name")
	assert.Empty(t, crypto.PIIFieldNames(struct {
		A string `json:"a"`
	}{}), "a payload without tags has no PII fields")
}

func TestSealPayloadPII_RoundTrip(t *testing.T) {
	dek := mintDEK(t, userA)
	name := "Alice Example"
	in := walkFixture{Email: "alice@example.com", DisplayName: &name, Untagged: "keep", Count: 7}

	sealed, err := crypto.SealPayloadPII(dek, in)
	require.NoError(t, err)
	out, ok := sealed.(walkFixture)
	require.True(t, ok, "sealing returns the same concrete type")

	assert.NotEqual(t, in.Email, out.Email, "tagged field must be ciphertext")
	assert.Contains(t, out.Email, "pii:v1:")
	require.NotNil(t, out.DisplayName)
	assert.Contains(t, *out.DisplayName, "pii:v1:")
	assert.Equal(t, "keep", out.Untagged, "untagged fields pass through untouched")
	assert.Equal(t, 7, out.Count)

	// The ORIGINAL must be unmodified (no aliasing through pointers).
	assert.Equal(t, "alice@example.com", in.Email)
	assert.Equal(t, "Alice Example", *in.DisplayName)

	require.NoError(t, crypto.OpenPayloadPII(dek, &out))
	assert.Equal(t, "alice@example.com", out.Email)
	assert.Equal(t, "Alice Example", *out.DisplayName)
}

func TestSealPayloadPII_NilAndEmptyFields(t *testing.T) {
	dek := mintDEK(t, userA)
	in := walkFixture{Email: "", DisplayName: nil, Untagged: "x"}
	sealed, err := crypto.SealPayloadPII(dek, in)
	require.NoError(t, err)
	out := sealed.(walkFixture)
	assert.Equal(t, "", out.Email, "empty tagged fields stay empty")
	assert.Nil(t, out.DisplayName, "nil optional tagged fields stay nil")
}

func TestSealPayloadPII_NoTagsIsIdentity(t *testing.T) {
	dek := mintDEK(t, userA)
	type plain struct {
		A string `json:"a"`
	}
	in := plain{A: "x"}
	sealed, err := crypto.SealPayloadPII(dek, in)
	require.NoError(t, err)
	assert.Equal(t, in, sealed.(plain))
}

func TestOpenPayloadPII_WrongDEKFails(t *testing.T) {
	dekA := mintDEK(t, userA)
	dekB := mintDEK(t, userB)
	in := walkFixture{Email: "alice@example.com"}
	sealed, err := crypto.SealPayloadPII(dekA, in)
	require.NoError(t, err)
	out := sealed.(walkFixture)
	require.Error(t, crypto.OpenPayloadPII(dekB, &out),
		"opening under another user's DEK must fail, never return garbage")
}

func TestRedactPayloadPII_SetsSentinelOnTaggedFieldsOnly(t *testing.T) {
	name := "Alice Example"
	p := walkFixture{Email: "alice@example.com", DisplayName: &name, Untagged: "keep", Count: 7}
	require.NoError(t, crypto.RedactPayloadPII(&p))
	assert.Equal(t, crypto.RedactionSentinel, p.Email, "tagged string field collapses to the sentinel")
	require.NotNil(t, p.DisplayName)
	assert.Equal(t, crypto.RedactionSentinel, *p.DisplayName, "tagged pointer field collapses to the sentinel")
	assert.Equal(t, "keep", p.Untagged, "untagged fields are untouched")
	assert.Equal(t, 7, p.Count)
}

func TestRedactPayloadPII_NilPointerFieldStaysNil(t *testing.T) {
	p := walkFixture{Email: "x@y.com", DisplayName: nil}
	require.NoError(t, crypto.RedactPayloadPII(&p))
	assert.Equal(t, crypto.RedactionSentinel, p.Email)
	assert.Nil(t, p.DisplayName, "an absent optional PII field has nothing to redact")
}

func TestRedactPayloadPII_RejectsNonPointer(t *testing.T) {
	require.Error(t, crypto.RedactPayloadPII(walkFixture{}), "must be a non-nil pointer to a struct")
}

func TestRedactPayloadPII_FailsClosedOnUnsupportedKind(t *testing.T) {
	// A tagged field that is neither string nor *string must error,
	// matching walkPII — never leave real PII in an "erased" row.
	type bad struct {
		Nums []string `json:"nums" pii:"true"`
	}
	require.Error(t, crypto.RedactPayloadPII(&bad{Nums: []string{"secret"}}),
		"an unsupported tagged kind must fail closed, not be silently skipped")
}
