package taskqueue

// HMAC-SHA256 signed envelope for Asynq task payloads (audit F-02).
//
// Threat model: Valkey is a trust boundary for the control ↔ gateway
// path. A Valkey compromise (CVE, weak password, network exposure,
// misconfigured ACL) lets an attacker enqueue arbitrary tasks into
// any device queue or the control inbox. Without signing, the gateway
// dispatches those tasks to the agent's mTLS stream, and the agent
// trusts them. For non-action paths (terminal input, osquery, log
// queries) the agent has no other validation — a forged task arrives
// as a real instruction. For action-dispatch, the CA-signed action
// signature mitigates payload forgery but does not stop an attacker
// from causing arbitrary side effects (re-dispatching a legitimate
// action against the wrong device, replaying old tasks, etc.).
//
// Format of a signed task envelope:
//
//   [ 32 bytes HMAC-SHA256(key, payload) ][ payload bytes ]
//
// Workers strip the 32-byte prefix, verify the HMAC in constant
// time, and only then invoke their normal JSON-decoding handler.
// Tampered or unsigned tasks are rejected with a non-retriable
// asynq.SkipRetry error so they land in the dead queue for operator
// inspection rather than burning retry slots.
//
// Key distribution: `PM_TASK_SIGNING_KEY` is a 32-byte (64 hex char)
// shared secret that must be configured identically on every service
// that participates in the Asynq fan-out (control, gateway, indexer).
// Operators rotate it by setting two values in `.env` during the
// rotation window and pointing every service at the new one in
// lock-step — there is intentionally no support for "accept either
// of two keys" because the rotation window is bounded by
// queue-drain time (minutes), not by token lifetime (hours/days).

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/hibiken/asynq"
)

// signatureSize is the byte length of an HMAC-SHA256 prefix.
const signatureSize = sha256.Size

// ErrUnsignedTask is returned by Signer.Verify when the envelope is
// shorter than the signature prefix, i.e. the producer didn't wrap
// the payload. Surfaces in worker logs as "task too short" so
// operators can tell unsigned-task-during-upgrade from key-mismatch.
var ErrUnsignedTask = errors.New("taskqueue: task is unsigned or truncated")

// ErrSignatureMismatch is returned by Signer.Verify when the HMAC
// over the payload does not match the prefix. Caused by either a
// key mismatch between producer and consumer, or by a third party
// tampering with the queue contents.
var ErrSignatureMismatch = errors.New("taskqueue: task signature mismatch")

// Signer holds an HMAC key for sign + verify operations. Construct
// once at boot from PM_TASK_SIGNING_KEY and pass through to both
// Client (producer side) and the worker handler chain (consumer
// side). nil-safe: a nil Signer means "signing disabled" — handlers
// receive raw task payloads unchanged. nil should only ever appear
// in test fixtures; production wiring rejects an empty key at boot.
type Signer struct {
	key []byte
}

// NewSigner parses keyHex (32-byte HMAC key as 64 hex chars) and
// returns a Signer. Empty string returns (nil, nil) so callers can
// pass through "signing disabled" without an error — but production
// boot code must treat that case as fatal.
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

// Wrap returns the signed envelope: HMAC prefix followed by the raw
// payload bytes. Nil-safe — a nil Signer returns the payload unchanged
// so tests that don't wire a signer continue to work.
func (s *Signer) Wrap(payload []byte) []byte {
	if s == nil {
		return payload
	}
	mac := hmac.New(sha256.New, s.key)
	mac.Write(payload)
	sig := mac.Sum(nil)
	out := make([]byte, 0, len(sig)+len(payload))
	out = append(out, sig...)
	out = append(out, payload...)
	return out
}

// Verify strips the signature prefix from envelope and returns the
// inner payload bytes when the HMAC matches. Constant-time compare
// via hmac.Equal — do not switch to bytes.Equal. Nil-safe.
func (s *Signer) Verify(envelope []byte) ([]byte, error) {
	if s == nil {
		return envelope, nil
	}
	if len(envelope) < signatureSize {
		return nil, ErrUnsignedTask
	}
	sig := envelope[:signatureSize]
	payload := envelope[signatureSize:]
	mac := hmac.New(sha256.New, s.key)
	mac.Write(payload)
	expected := mac.Sum(nil)
	if !hmac.Equal(sig, expected) {
		return nil, ErrSignatureMismatch
	}
	return payload, nil
}

// VerifyMiddleware returns an asynq middleware that verifies the
// envelope HMAC and replaces the task's payload with the unwrapped
// bytes before passing it down to the wrapped handler chain. Wrap
// every mux registration with this in production wiring; tests that
// don't sign can pass a nil Signer and the middleware is a no-op.
//
// Verification failures wrap asynq.SkipRetry so an attacker with
// transient Valkey access can't burn retry slots by injecting
// unsigned tasks — the task lands in the dead queue immediately
// and surfaces as a single WARN line for the operator.
func (s *Signer) VerifyMiddleware() asynq.MiddlewareFunc {
	return func(next asynq.Handler) asynq.Handler {
		return asynq.HandlerFunc(func(ctx context.Context, t *asynq.Task) error {
			if s == nil {
				return next.ProcessTask(ctx, t)
			}
			payload, err := s.Verify(t.Payload())
			if err != nil {
				return fmt.Errorf("%w: %s/%s: %v",
					asynq.SkipRetry, queueOf(ctx), t.Type(), err)
			}
			// Replace the task's payload in-place so downstream
			// handlers see the unwrapped bytes. asynq.NewTask copies
			// the payload — we construct a fresh Task with the
			// verified content so handlers don't have to know about
			// signing.
			verified := asynq.NewTask(t.Type(), payload, asynq.Queue(queueOf(ctx)))
			return next.ProcessTask(ctx, verified)
		})
	}
}

// queueOf retrieves the task's queue name from the asynq context.
// Returns "" if not present (which only happens in synthetic tests).
func queueOf(ctx context.Context) string {
	q, _ := asynq.GetQueueName(ctx)
	return q
}
