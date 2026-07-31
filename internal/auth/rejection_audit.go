package auth

import (
	"context"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/store"
)

// AuditOperationRecorder is the store's audited no-mutation door.
// Satisfied by *store.Store.
type AuditOperationRecorder interface {
	RecordOperation(ctx context.Context, op store.AuditOperation, effects ...store.AuditEffect) (store.AuditRecord, error)
}

// AnonymousActorType is the actor_type of an attempt that never
// authenticated. It is not "user": nothing about the attempt is known
// to be a user.
const AnonymousActorType = "anonymous"

// ControlRPCOrigin names the surface a control RPC entered through.
const ControlRPCOrigin = "control_rpc"

// NewRejectionRecorder adapts the store's audited no-mutation door to
// the interceptor's rejected-authentication seam.
func NewRejectionRecorder(st AuditOperationRecorder) RejectionRecorder {
	return &storeRejectionRecorder{st: st}
}

type storeRejectionRecorder struct{ st AuditOperationRecorder }

// RecordRejectedAuthentication writes one operation row under the
// dedicated rejected-authentication class.
//
// The row carries no effects: an effect names an affected resource, and
// a refused credential affected nothing. Every value on it is either a
// code-derived constant or a SHA-256 digest — the presented credential
// and the peer address appear only as digests, and there is no actor
// id, because the attempt never authenticated.
func (r *storeRejectionRecorder) RecordRejectedAuthentication(ctx context.Context, att RejectedAuthentication) error {
	_, err := r.st.RecordOperation(ctx, store.AuditOperation{
		Class:                store.ClassRejectedAuthentication,
		ActorType:            AnonymousActorType,
		ActorFingerprint:     att.CredentialFingerprint,
		Origin:               ControlRPCOrigin,
		OriginFingerprint:    att.OriginFingerprint,
		RequestDescriptor:    att.Procedure,
		AuthorizationOutcome: store.AuthorizationDenied,
		Result:               store.ResultRejected,
		ResultCode:           att.Reason,
	})
	if err != nil {
		return fmt.Errorf("record rejected authentication: %w", err)
	}
	return nil
}
