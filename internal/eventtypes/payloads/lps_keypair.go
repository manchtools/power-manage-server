package payloads

import (
	"log/slog"
	"time"
)

// LpsKeypairGenerated is the wire shape for the singleton
// LpsKeypairGenerated event (#495). It event-sources the control server's
// LPS sealing keypair: the lps_keypair table is a projection of this event,
// so an event-store replay reproduces the row 1:1 (the pre-#495 design wrote
// the row directly and broke the replay guarantee).
//
// PrivateKeyEnc is enc:v2 AES-GCM ciphertext (AAD-bound via
// crypto.SecretAAD("global","lps-keypair","lps-keypair-priv")) — the emitter
// never puts plaintext key material in the event, consistent with the at-rest
// model for LPS rotations, TOTP secrets, and IdP client secrets. LogValue
// still masks it defensively.
//
// CreatedAt is set ONLY by the #495 upgrade backfill (it preserves the
// pre-existing row's created_at); the fresh-generation path omits it and the
// projector falls back to the event's occurred_at, so no emitter needs a
// clock.
type LpsKeypairGenerated struct {
	PublicKey     []byte     `json:"public_key"`           // raw 32-byte X25519 public key
	PrivateKeyEnc string     `json:"private_key_enc"`      // enc:v2 ciphertext, never plaintext
	CreatedAt     *time.Time `json:"created_at,omitempty"` // backfill only; nil ⇒ projector uses occurred_at
}

// LogValue masks the encrypted private key so a payload routed through slog
// (`logger.Warn("…", "payload", p)`) cannot leak even the ciphertext.
func (p LpsKeypairGenerated) LogValue() slog.Value {
	attrs := []slog.Attr{
		slog.Int("public_key_len", len(p.PublicKey)),
		slog.String("private_key_enc", "[REDACTED]"),
	}
	if p.CreatedAt != nil {
		attrs = append(attrs, slog.Time("created_at", *p.CreatedAt))
	}
	return slog.GroupValue(attrs...)
}
