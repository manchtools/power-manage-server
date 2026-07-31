package handler

import (
	"context"

	"github.com/manchtools/power-manage/server/internal/terminal"
)

// tokenStoreValidator adapts the terminal token store to the bridge's
// TerminalTokenValidator.
//
// The bridge used to reach control over an RPC that returned a wire message;
// with both in one process the adapter just maps the store's Session onto the
// bridge's struct. Redemption stays SINGLE-USE — Validate consumes the entry —
// which is what stops a token leaked through a proxy access log being replayed
// inside its TTL.
type tokenStoreValidator struct {
	store *terminal.TokenStore
}

// NewTokenStoreValidator returns a TerminalTokenValidator over the token store.
func NewTokenStoreValidator(store *terminal.TokenStore) TerminalTokenValidator {
	return &tokenStoreValidator{store: store}
}

func (v *tokenStoreValidator) ValidateTerminalToken(ctx context.Context, sessionID, token string) (*TerminalSession, error) {
	sess, err := v.store.Validate(ctx, sessionID, token)
	if err != nil {
		return nil, err
	}
	return &TerminalSession{
		DeviceId: sess.DeviceID,
		UserId:   sess.UserID,
		TtyUser:  sess.TtyUser,
		Cols:     sess.Cols,
		Rows:     sess.Rows,
	}, nil
}
