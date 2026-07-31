package identity

import (
	"context"
	"time"

	"connectrpc.com/connect"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// mintSession resolves a subject's current authority from the database
// and issues a token pair for it.
//
// The authority is ALWAYS re-read here rather than carried over from a
// previous token: that is what makes a revoked role stop working at the
// next refresh instead of at the end of the refresh token's lifetime.
func (h *Handlers) mintSession(ctx context.Context, userID, email string, sessionVersion int32) (*auth.TokenPair, error) {
	permissions, err := h.store.ListUserPermissions(ctx, userID)
	if err != nil {
		return nil, err
	}
	grantRows, err := h.store.ListUserScopedGrants(ctx, userID)
	if err != nil {
		return nil, err
	}
	grants := make([]auth.ScopedGrant, 0, len(grantRows))
	for _, g := range grantRows {
		sg := auth.ScopedGrant{Permission: g.Permission}
		if g.ScopeKind != nil {
			sg.ScopeKind = *g.ScopeKind
		}
		if g.ScopeID != nil {
			sg.ScopeID = *g.ScopeID
		}
		grants = append(grants, sg)
	}
	return h.jwt.GenerateTokens(userID, email, permissions, grants, sessionVersion)
}

// RefreshToken rotates a session.
//
// It is a public procedure: the caller has no access token, which is
// the whole reason to be here. The refresh token itself is the
// credential, so it is validated, checked against the revocation list,
// and then revoked BEFORE the replacement is minted — a conditional
// insert, so two concurrent presentations of the same token cannot both
// produce a new session.
func (h *Handlers) RefreshToken(ctx context.Context, req *connect.Request[pmv1.RefreshTokenRequest]) (*connect.Response[pmv1.RefreshTokenResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	result, err := h.jwt.ValidateRefreshToken(req.Msg.RefreshToken, func(jti string) (bool, error) {
		return h.store.IsTokenRevoked(ctx, jti)
	})
	if err != nil {
		return nil, h.rejectSession(ctx, req, "invalid or expired refresh token")
	}

	state, err := h.store.GetUserSessionState(ctx, result.Claims.UserID)
	if err != nil {
		if store.IsNotFound(err) {
			return nil, h.rejectSession(ctx, req, "invalid or expired refresh token")
		}
		return nil, internalError(ctx, "failed to resolve session state")
	}
	// A retired or disabled subject, and a session minted under an
	// older authority, all get the same answer: the session is over.
	// Distinguishing them would report account state to a caller who
	// holds only a stale token.
	if state.IsDeleted || state.Disabled || state.SessionVersion != result.Claims.SessionVersion {
		return nil, h.rejectSession(ctx, req, "session invalidated, please log in again")
	}

	rotated, err := h.revokeRefreshToken(ctx, req, result.OldJTI, result.OldExp, result.Claims.UserID, "ROTATE")
	if err != nil {
		return nil, err
	}
	if !rotated {
		// The token was already spent by a concurrent refresh. That is
		// a replay from this request's point of view.
		return nil, h.rejectSession(ctx, req, "refresh token already used")
	}

	tokens, err := h.mintSession(ctx, result.Claims.UserID, result.Claims.Email, state.SessionVersion)
	if err != nil {
		return nil, internalError(ctx, "failed to issue session")
	}
	return connect.NewResponse(&pmv1.RefreshTokenResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresAt:    timestampValue(tokens.ExpiresAt),
	}), nil
}

// Logout revokes a refresh token so the session cannot be rotated
// again.
//
// A token that does not validate is not an error: logout is best
// described as "make sure this is dead", and reporting that a presented
// value was not a real token tells an unauthenticated caller something
// about it. The response is identical either way.
func (h *Handlers) Logout(ctx context.Context, req *connect.Request[pmv1.LogoutRequest]) (*connect.Response[pmv1.LogoutResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	claims, err := h.jwt.ValidateToken(req.Msg.RefreshToken, auth.TokenTypeRefresh)
	if err != nil {
		return connect.NewResponse(&pmv1.LogoutResponse{}), nil
	}
	var exp time.Time
	if claims.ExpiresAt != nil {
		exp = claims.ExpiresAt.Time
	}
	if _, err := h.revokeRefreshToken(ctx, req, claims.ID, exp, claims.UserID, "LOGOUT"); err != nil {
		return nil, err
	}
	return connect.NewResponse(&pmv1.LogoutResponse{}), nil
}

// revokeRefreshToken records a session token id on the revocation list
// and writes the audit evidence in the same transaction.
//
// Reports whether THIS call performed the revocation: the insert is
// conditional, so a token already revoked by a concurrent caller
// returns false rather than an error, and the caller decides whether
// losing that race matters.
func (h *Handlers) revokeRefreshToken(
	ctx context.Context,
	req connect.AnyRequest,
	jti string,
	expiresAt time.Time,
	subjectID string,
	action string,
) (bool, error) {
	if jti == "" {
		return false, nil
	}
	if expiresAt.IsZero() {
		// A token with no expiry cannot age out of the revocation
		// table, so the row is given the same bound the token would
		// have had.
		expiresAt = h.now().Add(h.jwt.AccessTokenTTL())
	}

	// The subject is the actor: presenting a valid refresh token IS the
	// authentication for this operation.
	actor := &auth.UserContext{ID: subjectID, Kind: auth.PrincipalUser}
	op := h.mutationOp(req, actor, "")
	op.AuthorizationOutcome = store.AuthorizationNotApplicable

	revoked := false
	_, err := h.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		_, err := tx.RevokeToken(ctx, db.RevokeTokenParams{Jti: jti, ExpiresAt: expiresAt.UTC()})
		switch {
		case err == nil:
			revoked = true
		case store.IsNotFound(err):
			// ON CONFLICT DO NOTHING returned no row: already revoked.
			revoked = false
		default:
			return err
		}
		// The effect is recorded either way. "This session was already
		// dead" is evidence too, and a revocation attempt that produced
		// nothing is exactly what a replay looks like.
		outcome := store.EffectApplied
		if !revoked {
			outcome = store.EffectRejected
		}
		rec.Effect(store.AuditEffect{
			ResourceType: "session",
			ResourceID:   subjectID,
			Action:       action,
			Outcome:      outcome,
			// The token id is a session identifier, not a credential,
			// but it is recorded as a digest anyway: an audit row is
			// readable by anyone who may read audit, and a session id
			// is a correlation handle they do not need in the clear.
			EvidenceKind:        "session_token_id_sha256",
			EvidenceFingerprint: auth.Fingerprint(jti),
		})
		return nil
	})
	if err != nil {
		h.logger.Error("failed to revoke session token", "action", action, "error", err)
		return false, internalError(ctx, "failed to end session")
	}
	return revoked, nil
}

// rejectSession records a refused session operation under the
// rejected-authentication class and returns the caller's error.
//
// The refresh path is public, so this is the only place a bad session
// credential on it becomes evidence: the authentication interceptor
// waved the request through precisely because the procedure carries no
// access token.
func (h *Handlers) rejectSession(ctx context.Context, req connect.AnyRequest, msg string) error {
	op := store.AuditOperation{
		Class:                store.ClassRejectedAuthentication,
		ActorType:            auth.AnonymousActorType,
		Origin:               auth.ControlRPCOrigin,
		RequestDescriptor:    req.Spec().Procedure,
		AuthorizationOutcome: store.AuthorizationDenied,
		Result:               store.ResultRejected,
		ResultCode:           ErrTokenExpired,
	}
	if ip := auth.ClientIP(req); ip != "" {
		op.OriginFingerprint = auth.Fingerprint(ip)
	}
	if _, err := h.store.RecordOperation(ctx, op); err != nil {
		h.logger.Error("failed to record rejected session operation", "error", err)
	}
	return rpcError(ctx, ErrTokenExpired, connect.CodeUnauthenticated, msg)
}

// GetCurrentUser returns the authenticated subject's own record.
//
// It is the one user read with no permission target: the caller is the
// resource. A principal that is not a subject — the reserved bootstrap
// principal — has no record to return and gets not-found.
func (h *Handlers) GetCurrentUser(ctx context.Context, req *connect.Request[pmv1.GetCurrentUserRequest]) (*connect.Response[pmv1.GetCurrentUserResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	actor, err := h.requireActor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, PermGetCurrentUser, actor.ID); err != nil {
		return nil, err
	}
	if !actor.CanOwnResources() {
		return nil, notFound(ctx, ErrUserNotFound, "user not found")
	}

	view, err := h.loadUserView(ctx, actor.ID)
	if err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, ErrUserNotFound, "user not found")
		}
		return nil, internalError(ctx, "failed to load user")
	}
	return connect.NewResponse(&pmv1.GetCurrentUserResponse{User: userToProto(view)}), nil
}
