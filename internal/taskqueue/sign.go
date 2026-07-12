package taskqueue

// HMAC-SHA256 signed envelope for Asynq task payloads (audit F-02; hardened by
// spec 29 to bind task metadata, not just payload bytes).
//
// Threat model: Valkey is a trust boundary for the control ↔ gateway path. A
// Valkey compromise (CVE, weak password, network exposure, misconfigured ACL)
// lets an attacker enqueue arbitrary tasks into any device queue or the control
// inbox. Without signing, the gateway dispatches those tasks to the agent's
// mTLS stream, and the agent trusts them. For non-action paths (terminal input,
// osquery, log queries) the agent has no other validation. For action-dispatch,
// the CA-signed action signature mitigates payload forgery but does not stop an
// attacker from causing arbitrary side effects.
//
// The original envelope signed ONLY the payload bytes, so a holder of a valid
// signed task (or a queue writer) could REPLAY those bytes under a different
// queue, task type, or direction — the consumer verified the payload and then
// dispatched using the independently-supplied Asynq queue/type. Spec 29 binds
// the HMAC to (version, direction, exact queue, task type, payload) so a signed
// task is valid only in the exact position it was signed for.
//
// Envelope format (clean-break v1 — there is intentionally NO payload-only
// fallback; an old payload-only envelope fails the version check):
//
//   [ 1 byte version=1 ][ 32 bytes HMAC-SHA256 ][ payload bytes ]
//
// The HMAC preimage is a fixed domain tag followed by length-prefixed fields:
//
//   domainTag || u8(version) || lp(direction) || lp(queue) || lp(type) || lp(payload)
//
// where lp(x) = u32be(len(x)) || x. Direction is DERIVED from the queue class
// (device:* → control→device, control:inbox → device→control, terminal-audit,
// search → control→search), never caller-supplied, so a signed task cannot be
// replayed across directions.
//
// Workers verify in constant time (hmac.Equal) and reject tampered, unsigned,
// unknown-queue, unsupported-version, or truncated tasks with a non-retriable
// asynq.SkipRetry error so they land in the dead queue for operator inspection
// rather than burning retry slots.
//
// Key distribution: `PM_TASK_SIGNING_KEY` is a 32-byte (64 hex char) shared
// secret configured identically on every service in the fan-out (control,
// gateway, indexer). This is a clean-break format: drain pending queues (or stop
// producers) before deploying, and deploy every service from the same release —
// mixed old/new signers are intentionally unsupported.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/hibiken/asynq"
)

// signatureSize is the byte length of an HMAC-SHA256 signature.
const signatureSize = sha256.Size

// envelopeVersion is the current envelope version byte. A clean break: a task
// carrying any other leading byte (including a legacy payload-only envelope,
// whose first byte is a random HMAC byte) is rejected.
const envelopeVersion byte = 1

// signDomainTag domain-separates the task HMAC from any other HMAC in the system
// that might share the key material, and pins the format version.
const signDomainTag = "power-manage:taskqueue:v1"

// Queue-class directions bound into the HMAC preimage. Derived from the queue
// name (not caller-supplied) so a signed task cannot be replayed across the
// control↔device↔search boundaries.
const (
	dirControlToDevice = "c2d"
	dirDeviceToControl = "d2c"
	dirTerminalAudit   = "audit"
	dirControlToSearch = "c2s"
)

// ErrUnsignedTask is returned when the envelope is shorter than version+signature,
// i.e. the producer didn't wrap the payload (or it was truncated).
var ErrUnsignedTask = errors.New("taskqueue: task is unsigned or truncated")

// ErrSignatureMismatch is returned when the HMAC does not match — a key mismatch,
// tampering, or a replay of a task signed for a different queue/type/direction.
var ErrSignatureMismatch = errors.New("taskqueue: task signature mismatch")

// ErrUnknownQueue is returned when a queue name maps to no known direction. It
// fails closed: neither producer nor consumer will proceed for an unrecognized
// queue class.
var ErrUnknownQueue = errors.New("taskqueue: unknown queue class")

// ErrUnsupportedVersion is returned when the envelope's leading version byte is
// not the supported version — including a legacy payload-only envelope.
var ErrUnsupportedVersion = errors.New("taskqueue: unsupported envelope version")

// Signer holds an HMAC key for sign + verify. Construct once at boot from
// PM_TASK_SIGNING_KEY and pass to both Client (producer) and the worker mux
// chains (consumer). nil-safe: a nil Signer means "signing disabled" — Wrap
// returns the payload unchanged and Verify accepts it. nil should only appear in
// test fixtures; production boot rejects an empty key.
type Signer struct {
	key []byte
}

// NewSigner parses keyHex (32-byte HMAC key as 64 hex chars). Empty string
// returns (nil, nil) so callers can pass through "signing disabled" without an
// error — production boot must treat that as fatal.
func NewSigner(keyHex string) (*Signer, error) {
	if keyHex == "" {
		return nil, nil
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("taskqueue: PM_TASK_SIGNING_KEY is not valid hex: %w", err)
	}
	if len(key) != signatureSize {
		return nil, fmt.Errorf("taskqueue: PM_TASK_SIGNING_KEY must be %d bytes (%d hex chars), got %d bytes",
			signatureSize, signatureSize*2, len(key))
	}
	return &Signer{key: key}, nil
}

// directionForQueue maps a queue name to its bound direction. Returns ok=false
// for an unrecognized queue class (fail closed).
func directionForQueue(queue string) (string, bool) {
	switch {
	case strings.HasPrefix(queue, deviceQueuePrefix):
		return dirControlToDevice, true
	case queue == ControlInboxQueue:
		return dirDeviceToControl, true
	case queue == ControlTerminalAuditQueue:
		return dirTerminalAudit, true
	case queue == SearchQueue:
		return dirControlToSearch, true
	default:
		return "", false
	}
}

// mac computes HMAC-SHA256 over the domain-separated, length-prefixed preimage
// binding version, direction, queue, task type, and payload.
func (s *Signer) mac(version byte, direction, queue, taskType string, payload []byte) []byte {
	var b bytes.Buffer
	b.WriteString(signDomainTag)
	b.WriteByte(version)
	writeLenPrefixed(&b, []byte(direction))
	writeLenPrefixed(&b, []byte(queue))
	writeLenPrefixed(&b, []byte(taskType))
	writeLenPrefixed(&b, payload)

	m := hmac.New(sha256.New, s.key)
	m.Write(b.Bytes())
	return m.Sum(nil)
}

// writeLenPrefixed writes u32be(len(x)) || x so concatenated fields are
// unambiguous (no field boundary can be shifted to forge a different tuple with
// the same preimage bytes).
func writeLenPrefixed(b *bytes.Buffer, x []byte) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(x)))
	b.Write(l[:])
	b.Write(x)
}

// Wrap returns the signed envelope for a task destined for queue with taskType.
// Nil-safe — a nil Signer returns the payload unchanged (signing disabled).
// Returns ErrUnknownQueue for an unrecognized queue class so the producer fails
// closed rather than emitting an unverifiable task.
func (s *Signer) Wrap(queue, taskType string, payload []byte) ([]byte, error) {
	if s == nil {
		return payload, nil
	}
	direction, ok := directionForQueue(queue)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownQueue, queue)
	}
	sig := s.mac(envelopeVersion, direction, queue, taskType, payload)
	out := make([]byte, 0, 1+len(sig)+len(payload))
	out = append(out, envelopeVersion)
	out = append(out, sig...)
	out = append(out, payload...)
	return out, nil
}

// Verify checks the envelope against queue+taskType and returns the inner
// payload when the HMAC matches. Constant-time compare via hmac.Equal — do not
// switch to bytes.Equal. Nil-safe. Fails closed on a short envelope, an
// unsupported version (including a legacy payload-only envelope), an unknown
// queue class, or a signature mismatch (which also covers a task replayed under
// a different queue/type/direction).
func (s *Signer) Verify(queue, taskType string, envelope []byte) ([]byte, error) {
	if s == nil {
		return envelope, nil
	}
	if len(envelope) < 1+signatureSize {
		return nil, ErrUnsignedTask
	}
	if version := envelope[0]; version != envelopeVersion {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedVersion, version)
	}
	direction, ok := directionForQueue(queue)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownQueue, queue)
	}
	sig := envelope[1 : 1+signatureSize]
	payload := envelope[1+signatureSize:]
	expected := s.mac(envelopeVersion, direction, queue, taskType, payload)
	if !hmac.Equal(sig, expected) {
		return nil, ErrSignatureMismatch
	}
	return payload, nil
}

// VerifyMiddleware returns an asynq middleware that verifies the envelope
// against the task's actual queue (from ctx) and type before passing the
// unwrapped payload to the handler chain. Wrap every mux registration with it in
// production; a nil Signer makes it a no-op (tests only).
//
// Verification failures wrap asynq.SkipRetry so an attacker with transient
// Valkey access can't burn retry slots by injecting bad tasks — the task
// dead-letters immediately and surfaces as a single WARN line.
func (s *Signer) VerifyMiddleware() asynq.MiddlewareFunc {
	return func(next asynq.Handler) asynq.Handler {
		return asynq.HandlerFunc(func(ctx context.Context, t *asynq.Task) error {
			if s == nil {
				return next.ProcessTask(ctx, t)
			}
			queue := queueOf(ctx)
			payload, err := s.Verify(queue, t.Type(), t.Payload())
			if err != nil {
				return fmt.Errorf("%w: %s/%s: %v", asynq.SkipRetry, queue, t.Type(), err)
			}
			// Rebuild the task with the verified (unwrapped) payload so downstream
			// handlers don't have to know about signing, preserving the queue.
			verified := asynq.NewTask(t.Type(), payload, asynq.Queue(queue))
			return next.ProcessTask(ctx, verified)
		})
	}
}

// queueCtxKey carries the queue name for callers that invoke a handler chain
// outside the Asynq server (which provides the queue via asynq.GetQueueName).
type queueCtxKey struct{}

// WithQueue returns a context carrying the queue a task is processed under. In
// production the Asynq server supplies the queue through its own context; this
// helper is for tests (and any non-Asynq caller) that drive a mux's
// ProcessTask directly, where Asynq's queue context is absent. queueOf prefers
// Asynq's value and only falls back to this one — production wiring runs through
// the real server, so it never sets this key.
func WithQueue(ctx context.Context, queue string) context.Context {
	return context.WithValue(ctx, queueCtxKey{}, queue)
}

// queueOf retrieves the task's queue name: the Asynq server's value in
// production, or the WithQueue fallback for direct-invocation tests. Returns ""
// if neither is present; "" maps to no direction, so Verify fails closed.
func queueOf(ctx context.Context) string {
	if q, ok := asynq.GetQueueName(ctx); ok && q != "" {
		return q
	}
	if q, ok := ctx.Value(queueCtxKey{}).(string); ok {
		return q
	}
	return ""
}
