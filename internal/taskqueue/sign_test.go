package taskqueue

// Pure-Go tests for the Asynq task-envelope signer (audit F-02).
//
// The wire format is `[32 bytes HMAC-SHA256][payload]`. These tests
// lock in:
//   - parse-time validation of the hex key (wrong length, malformed
//     hex, empty disables);
//   - round-trip: a Wrapped payload Verifies cleanly back to the
//     original bytes;
//   - rejection: tampered prefix, tampered payload, truncated
//     envelope, and unsigned envelope each return a typed error;
//   - nil-safety: a nil Signer is a no-op for both Wrap and Verify
//     so tests that don't care about signing don't need to plumb
//     one in.

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestNewSigner_ParsesValidKey(t *testing.T) {
	s, err := NewSigner(testKeyHex)
	require.NoError(t, err)
	require.NotNil(t, s)
	assert.Equal(t, signatureSize, len(s.key))
}

func TestNewSigner_EmptyKeyReturnsNilNil(t *testing.T) {
	s, err := NewSigner("")
	require.NoError(t, err)
	assert.Nil(t, s, "empty key string means 'signing disabled' — caller decides whether that's fatal at boot")
}

func TestNewSigner_WrongLengthRejected(t *testing.T) {
	cases := []string{
		"00",
		strings.Repeat("ab", 31), // 31 bytes
		strings.Repeat("ab", 33), // 33 bytes
	}
	for _, k := range cases {
		t.Run(k[:min(8, len(k))], func(t *testing.T) {
			_, err := NewSigner(k)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "bytes")
		})
	}
}

func TestNewSigner_MalformedHexRejected(t *testing.T) {
	_, err := NewSigner("not-hex-at-all-not-hex-at-all-not-hex-at-all-not-hex-at-all-zzzz")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "valid hex")
}

func TestSigner_WrapVerifyRoundTrip(t *testing.T) {
	s, err := NewSigner(testKeyHex)
	require.NoError(t, err)

	cases := [][]byte{
		[]byte(""),
		[]byte("{}"),
		[]byte(`{"device_id":"abc","action_type":1}`),
		[]byte(strings.Repeat("payload bytes ", 100)),
	}
	for _, payload := range cases {
		wrapped := s.Wrap(payload)
		assert.Equal(t, signatureSize+len(payload), len(wrapped),
			"wrapped envelope = 32-byte HMAC prefix + payload")
		out, err := s.Verify(wrapped)
		require.NoError(t, err)
		assert.Equal(t, payload, out)
	}
}

func TestSigner_VerifyRejectsTamperedSignature(t *testing.T) {
	s, err := NewSigner(testKeyHex)
	require.NoError(t, err)
	wrapped := s.Wrap([]byte(`{"x":1}`))
	wrapped[0] ^= 0xFF // flip the first byte of the HMAC

	_, err = s.Verify(wrapped)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSignatureMismatch),
		"tampered signature must return ErrSignatureMismatch")
}

func TestSigner_VerifyRejectsTamperedPayload(t *testing.T) {
	s, err := NewSigner(testKeyHex)
	require.NoError(t, err)
	wrapped := s.Wrap([]byte(`{"x":1}`))
	// Modify the last byte of the payload, leaving the HMAC intact.
	wrapped[len(wrapped)-1] = '2'

	_, err = s.Verify(wrapped)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSignatureMismatch))
}

func TestSigner_VerifyRejectsTruncatedEnvelope(t *testing.T) {
	s, err := NewSigner(testKeyHex)
	require.NoError(t, err)
	short := []byte{1, 2, 3}

	_, err = s.Verify(short)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnsignedTask),
		"envelopes shorter than the signature prefix are classified as unsigned")
}

func TestSigner_VerifyRejectsUnsignedEnvelope(t *testing.T) {
	// An envelope produced by an older / misconfigured producer that
	// didn't wrap: the bytes are pure JSON, no HMAC prefix. The
	// recognizer treats the first 32 bytes as the HMAC, finds they
	// don't verify, and returns SignatureMismatch.
	s, err := NewSigner(testKeyHex)
	require.NoError(t, err)
	unsigned := []byte(strings.Repeat(`{"a":"b"} `, 5)) // 50 bytes — enough that the prefix is treated as a (bogus) HMAC

	_, err = s.Verify(unsigned)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSignatureMismatch),
		"an unsigned payload that's long enough to have a 'prefix' must fail the HMAC compare, not pass through")
}

func TestSigner_VerifyRejectsKeyMismatch(t *testing.T) {
	producer, err := NewSigner(testKeyHex)
	require.NoError(t, err)
	wrapped := producer.Wrap([]byte("hello"))

	consumer, err := NewSigner(strings.Repeat("ff", 32))
	require.NoError(t, err)
	_, err = consumer.Verify(wrapped)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSignatureMismatch))
}

func TestSigner_NilSafetyOnBothSides(t *testing.T) {
	var s *Signer
	payload := []byte(`{"x":1}`)

	wrapped := s.Wrap(payload)
	assert.Equal(t, payload, wrapped, "nil Signer Wrap is a passthrough")

	out, err := s.Verify(payload)
	require.NoError(t, err)
	assert.Equal(t, payload, out, "nil Signer Verify is a passthrough")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
