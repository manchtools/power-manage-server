package taskqueue

// Pure-Go tests for the versioned, metadata-bound Asynq task-envelope signer
// (audit F-02; spec 29). The wire format is
// `[1 byte version][32 bytes HMAC-SHA256][payload]`, with the HMAC bound to
// (version, direction, exact queue, task type, payload). These tests lock in the
// key parsing, round-trip, and the full rejection matrix: tampered signature /
// payload / version, replay under a different queue / direction / task type,
// unknown queue class, truncated envelope, wrong key, and a legacy payload-only
// envelope (which must NOT pass through any compatibility fallback).

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// A valid queue+type pair for round-trips: a device queue (control→device).
const (
	testQueue = "device:dev-1"
	testType  = "action:dispatch"
)

func clone(b []byte) []byte { return append([]byte(nil), b...) }

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
	for _, k := range []string{"00", strings.Repeat("ab", 31), strings.Repeat("ab", 33)} {
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

// AC1: round-trip with known queue/type metadata returns the original payload.
func TestSigner_WrapVerifyRoundTrip(t *testing.T) {
	s, err := NewSigner(testKeyHex)
	require.NoError(t, err)

	for _, payload := range [][]byte{
		[]byte(""),
		[]byte("{}"),
		[]byte(`{"device_id":"abc","action_type":1}`),
		[]byte(strings.Repeat("payload bytes ", 100)),
	} {
		env, err := s.Wrap(testQueue, testType, payload)
		require.NoError(t, err)
		assert.Equal(t, 1+signatureSize+len(payload), len(env), "envelope = version + 32-byte HMAC + payload")
		assert.Equal(t, envelopeVersion, env[0])

		out, err := s.Verify(testQueue, testType, env)
		require.NoError(t, err)
		assert.Equal(t, payload, out)
	}
}

// AC2: independently changing any bound field rejects the task.
func TestSigner_VerifyRejectsEachTamperedOrReplayedField(t *testing.T) {
	s, err := NewSigner(testKeyHex)
	require.NoError(t, err)
	payload := []byte(`{"x":1}`)
	env, err := s.Wrap(testQueue, testType, payload)
	require.NoError(t, err)

	cases := []struct {
		name    string
		verify  func() ([]byte, error)
		wantErr error
	}{
		{"tampered signature", func() ([]byte, error) {
			e := clone(env)
			e[1] ^= 0xFF
			return s.Verify(testQueue, testType, e)
		}, ErrSignatureMismatch},
		{"tampered payload", func() ([]byte, error) {
			e := clone(env)
			e[len(e)-1] ^= 0xFF
			return s.Verify(testQueue, testType, e)
		}, ErrSignatureMismatch},
		{"tampered version", func() ([]byte, error) {
			e := clone(env)
			e[0] = envelopeVersion + 1
			return s.Verify(testQueue, testType, e)
		}, ErrUnsupportedVersion},
		{"replayed under a different exact queue (cross-device)", func() ([]byte, error) {
			return s.Verify("device:dev-2", testType, env)
		}, ErrSignatureMismatch},
		{"replayed under a different direction (control inbox)", func() ([]byte, error) {
			return s.Verify(ControlInboxQueue, testType, env)
		}, ErrSignatureMismatch},
		{"replayed under a different task type", func() ([]byte, error) {
			return s.Verify(testQueue, "other:type", env)
		}, ErrSignatureMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.verify()
			require.Error(t, err)
			assert.Truef(t, errors.Is(err, tc.wantErr), "got %v, want %v", err, tc.wantErr)
		})
	}
}

// AC3: an unknown queue class fails closed on both sides.
func TestSigner_UnknownQueueFailsClosed(t *testing.T) {
	s, err := NewSigner(testKeyHex)
	require.NoError(t, err)

	_, err = s.Wrap("bogus:queue", testType, []byte("x"))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnknownQueue), "producer must refuse an unknown queue class")

	env, err := s.Wrap(testQueue, testType, []byte("x"))
	require.NoError(t, err)
	for _, q := range []string{"bogus:queue", ""} {
		_, err = s.Verify(q, testType, env)
		require.Error(t, err)
		assert.Truef(t, errors.Is(err, ErrUnknownQueue), "consumer must fail closed on queue %q", q)
	}
}

func TestSigner_VerifyRejectsTruncated(t *testing.T) {
	s, err := NewSigner(testKeyHex)
	require.NoError(t, err)
	for _, short := range [][]byte{{}, {envelopeVersion}, make([]byte, signatureSize)} { // all < 1+32
		_, err := s.Verify(testQueue, testType, short)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrUnsignedTask), "envelopes shorter than version+signature are unsigned/truncated")
	}
}

func TestSigner_VerifyRejectsKeyMismatch(t *testing.T) {
	producer, err := NewSigner(testKeyHex)
	require.NoError(t, err)
	env, err := producer.Wrap(testQueue, testType, []byte("hello"))
	require.NoError(t, err)

	consumer, err := NewSigner(strings.Repeat("ff", 32))
	require.NoError(t, err)
	_, err = consumer.Verify(testQueue, testType, env)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSignatureMismatch))
}

// AC4: a legacy payload-only envelope ([32-byte HMAC][payload], no version byte)
// must be rejected — there is no compatibility fallback.
func TestSigner_RejectsLegacyPayloadOnlyEnvelope(t *testing.T) {
	s, err := NewSigner(testKeyHex)
	require.NoError(t, err)
	payload := []byte(`{"x":1}`)

	// Reconstruct the OLD scheme: HMAC over payload bytes only, no version byte.
	m := hmac.New(sha256.New, s.key)
	m.Write(payload)
	legacy := append(m.Sum(nil), payload...) // [32-byte HMAC][payload]

	_, err = s.Verify(testQueue, testType, legacy)
	require.Error(t, err, "a legacy payload-only envelope must never verify")
	// Rejected either as an unsupported version (its first byte is a random HMAC
	// byte, almost never our version) or, in the 1/256 case it is, as a signature
	// mismatch — never accepted.
	assert.True(t, errors.Is(err, ErrUnsupportedVersion) || errors.Is(err, ErrSignatureMismatch))
}

func TestSigner_NilSafetyOnBothSides(t *testing.T) {
	var s *Signer
	payload := []byte(`{"x":1}`)

	env, err := s.Wrap(testQueue, testType, payload)
	require.NoError(t, err)
	assert.Equal(t, payload, env, "nil Signer Wrap is a passthrough")

	out, err := s.Verify(testQueue, testType, payload)
	require.NoError(t, err)
	assert.Equal(t, payload, out, "nil Signer Verify is a passthrough")
}

// TestDirectionForQueue pins that every real queue class maps to a direction and
// that the classes are distinct, and that unrecognized names fail closed.
func TestDirectionForQueue(t *testing.T) {
	known := []struct {
		queue string
		dir   string
	}{
		{DeviceQueue("dev-1"), dirControlToDevice},
		{DeviceQueue("dev-2"), dirControlToDevice},
		{ControlInboxQueue, dirDeviceToControl},
		{ControlTerminalAuditQueue, dirTerminalAudit},
		{SearchQueue, dirControlToSearch},
	}
	for _, k := range known {
		d, ok := directionForQueue(k.queue)
		require.Truef(t, ok, "queue %q should map to a direction", k.queue)
		assert.Equal(t, k.dir, d)
	}
	// device→control, terminal-audit, and search are three DISTINCT directions
	// so a task can't be replayed across them even at equal queue-name length.
	assert.NotEqual(t, dirDeviceToControl, dirControlToDevice)
	assert.NotEqual(t, dirTerminalAudit, dirDeviceToControl)
	assert.NotEqual(t, dirControlToSearch, dirControlToDevice)

	for _, bad := range []string{"", "bogus", "control:other", "device", "devices:x"} {
		_, ok := directionForQueue(bad)
		assert.Falsef(t, ok, "queue %q must be unknown (fail closed)", bad)
	}
}
