package registrationtoken

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	"github.com/go-playground/validator/v10"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	sdkvalidate "github.com/manchtools/power-manage-sdk/validate"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

const defaultPageSize = int32(50)

// Config supplies the direct SQLite store and process-local seams.
type Config struct {
	Store         *store.Store
	Logger        *slog.Logger
	Now           func() time.Time
	CAFingerprint string
}

// Handlers implements the registration-token control RPCs.
type Handlers struct {
	store     *store.Store
	logger    *slog.Logger
	now       func() time.Time
	validator *validator.Validate
	caPin     string
}

// New constructs direct registration-token handlers.
func New(cfg Config) *Handlers {
	if cfg.Store == nil {
		panic("registrationtoken: store is required")
	}
	decodedPin, err := hex.DecodeString(cfg.CAFingerprint)
	if err != nil || len(decodedPin) != sha256.Size {
		panic("registrationtoken: a SHA-256 CA fingerprint is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Handlers{
		store: cfg.Store, logger: cfg.Logger, now: cfg.Now,
		validator: sdkvalidate.NewValidator(), caPin: cfg.CAFingerprint,
	}
}

func validateRequest[T any](h *Handlers, ctx context.Context, req *connect.Request[T]) error {
	if req == nil || req.Msg == nil {
		return rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument, "request is required")
	}
	if detail, ok := sdkvalidate.Struct(h.validator, req.Msg); !ok {
		return rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument, detail)
	}
	return nil
}

func (h *Handlers) actor(ctx context.Context) (*auth.UserContext, error) {
	actor, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, rpcError(ctx, errNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}
	return actor, nil
}

func (h *Handlers) authorize(ctx context.Context, permission, resourceID string) error {
	if !auth.AuthorizeContext(ctx, permission, resourceID) {
		return rpcError(ctx, errPermissionDenied, connect.CodePermissionDenied, "permission denied")
	}
	return nil
}

func (h *Handlers) internal(ctx context.Context, operation string, err error) *connect.Error {
	h.logger.Error("registration-token RPC failed", "operation", operation, "error", err)
	return rpcError(ctx, errInternal, connect.CodeInternal, "internal error")
}

func (h *Handlers) operation(req connect.AnyRequest, actor *auth.UserContext, procedure, permission string) store.AuditOperation {
	op := store.AuditOperation{
		Class: store.ClassMutation, ActorType: string(actor.Kind), Origin: auth.ControlRPCOrigin,
		RequestDescriptor: procedure, AuthorizationOutcome: store.AuthorizationAllowed,
		AuthorizationDetail: permission, Result: store.ResultSuccess, ResultCode: "OK",
	}
	if actor.CanOwnResources() {
		op.ActorID = actor.ID
	}
	if ip := auth.ClientIP(req); ip != "" {
		op.OriginFingerprint = auth.Fingerprint(ip)
	}
	return op
}

func tokenEffect(id, action string, fields ...string) store.AuditEffect {
	return store.AuditEffect{
		ResourceType: "registration_token", ResourceID: id, Action: action,
		Outcome: store.EffectApplied, ChangedFields: fields,
	}
}

// CreateToken mints a bearer value once and stores only its SHA-256 digest.
func (h *Handlers) CreateToken(ctx context.Context, req *connect.Request[pmv1.CreateTokenRequest]) (*connect.Response[pmv1.CreateTokenResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	if req.Msg.Name == store.BootstrapAdminTokenName {
		return nil, rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument, "token name is reserved")
	}
	if req.Msg.ExpiresAt != nil {
		if err := req.Msg.ExpiresAt.CheckValid(); err != nil {
			return nil, rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument, "invalid token expiry")
		}
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "CreateToken", ""); err != nil {
		return nil, err
	}

	oneTime, maxUses := req.Msg.OneTime, req.Msg.MaxUses
	var ownerID *string
	var expiresAt *time.Time
	if auth.HasPermission(ctx, "CreateToken") {
		if req.Msg.OwnerId != "" {
			if _, err := h.store.GetUser(ctx, req.Msg.OwnerId); err != nil {
				if store.IsNotFound(err) {
					return nil, notFound(ctx, errUserNotFound, "owner user not found")
				}
				return nil, h.internal(ctx, "read token owner", err)
			}
			owner := req.Msg.OwnerId
			ownerID = &owner
		}
		if req.Msg.ExpiresAt != nil {
			expiry := req.Msg.ExpiresAt.AsTime().UTC()
			expiresAt = &expiry
		}
	} else {
		oneTime, maxUses = true, 1
		owner := actor.ID
		ownerID = &owner
		expiry := h.now().UTC().Add(7 * 24 * time.Hour)
		expiresAt = &expiry
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, h.internal(ctx, "generate token", err)
	}
	plaintext := base64.RawURLEncoding.EncodeToString(secret)
	digest := sha256.Sum256([]byte(plaintext))
	digestHex := hex.EncodeToString(digest[:])
	id, createdAt := ulid.Make().String(), h.now().UTC()
	var row store.RegistrationTokenRow
	_, err = h.store.WithAudit(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceCreateTokenProcedure, "CreateToken"),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			inserted, err := tx.InsertRegistrationToken(ctx, db.InsertRegistrationTokenParams{
				ID: id, ValueHash: digestHex, Name: req.Msg.Name, OneTime: oneTime,
				MaxUses: maxUses, ExpiresAt: expiresAt, CreatedAt: &createdAt,
				CreatedBy: actor.ID, OwnerID: ownerID,
			})
			if err != nil {
				return fmt.Errorf("registration token: insert: %w", err)
			}
			row = inserted
			effect := tokenEffect(id, "CREATE", "name", "one_time", "max_uses", "expires_at", "owner_id")
			effect.EvidenceKind = "registration_token"
			effect.EvidenceFingerprint = digestHex
			rec.Effect(effect)
			return nil
		})
	if err != nil {
		return nil, h.internal(ctx, "create token", err)
	}
	out := tokenToProto(row)
	out.Value = plaintext
	return connect.NewResponse(&pmv1.CreateTokenResponse{Token: out, CaFingerprintPin: h.caPin}), nil
}

// GetToken returns one live non-bootstrap token without its bearer value.
func (h *Handlers) GetToken(ctx context.Context, req *connect.Request[pmv1.GetTokenRequest]) (*connect.Response[pmv1.GetTokenResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	if _, err := h.actor(ctx); err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "GetToken", req.Msg.Id); err != nil {
		return nil, err
	}
	row, err := h.store.GetRegistrationToken(ctx, req.Msg.Id)
	if err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, errTokenNotFound, "token not found")
		}
		return nil, h.internal(ctx, "get token", err)
	}
	return connect.NewResponse(&pmv1.GetTokenResponse{Token: tokenToProto(row)}), nil
}

// ListTokens returns a deterministic keyset page of live non-bootstrap tokens.
func (h *Handlers) ListTokens(ctx context.Context, req *connect.Request[pmv1.ListTokensRequest]) (*connect.Response[pmv1.ListTokensResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	if req.Msg.PageToken != "" {
		if _, err := ulid.ParseStrict(req.Msg.PageToken); err != nil {
			return nil, rpcError(ctx, errInvalidPageToken, connect.CodeInvalidArgument, "invalid page token")
		}
	}
	if _, err := h.actor(ctx); err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "ListTokens", ""); err != nil {
		return nil, err
	}
	pageSize := req.Msg.PageSize
	if pageSize == 0 {
		pageSize = defaultPageSize
	}
	rows, err := h.store.ListRegistrationTokens(ctx, store.RegistrationTokenListFilter{
		AfterID: req.Msg.PageToken, Limit: pageSize + 1, IncludeDisabled: req.Msg.IncludeDisabled,
	})
	if err != nil {
		return nil, h.internal(ctx, "list tokens", err)
	}
	count, err := h.store.CountRegistrationTokens(ctx, req.Msg.IncludeDisabled)
	if err != nil {
		return nil, h.internal(ctx, "count tokens", err)
	}
	next := ""
	if len(rows) > int(pageSize) {
		rows = rows[:pageSize]
		next = rows[len(rows)-1].ID
	}
	out := make([]*pmv1.RegistrationToken, len(rows))
	for i, row := range rows {
		out[i] = tokenToProto(row)
	}
	return connect.NewResponse(&pmv1.ListTokensResponse{
		Tokens: out, NextPageToken: next, TotalCount: boundedCount(count),
	}), nil
}

// RenameToken replaces a token name in the same transaction as its audit row.
func (h *Handlers) RenameToken(ctx context.Context, req *connect.Request[pmv1.RenameTokenRequest]) (*connect.Response[pmv1.UpdateTokenResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	if req.Msg.Name == store.BootstrapAdminTokenName {
		return nil, rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument, "token name is reserved")
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "RenameToken", req.Msg.Id); err != nil {
		return nil, err
	}
	var row store.RegistrationTokenRow
	_, err = h.store.WithAudit(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceRenameTokenProcedure, "RenameToken"),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			updated, err := tx.RenameRegistrationToken(ctx, db.RenameRegistrationTokenParams{
				ID: req.Msg.Id, Name: req.Msg.Name, ReservedName: store.BootstrapAdminTokenName,
			})
			if err != nil {
				return err
			}
			row = updated
			rec.Effect(tokenEffect(req.Msg.Id, "UPDATE", "name"))
			return nil
		})
	if err != nil {
		return nil, h.writeError(ctx, "rename token", err)
	}
	return connect.NewResponse(&pmv1.UpdateTokenResponse{Token: tokenToProto(row)}), nil
}

// SetTokenDisabled changes whether a token may be consumed.
func (h *Handlers) SetTokenDisabled(ctx context.Context, req *connect.Request[pmv1.SetTokenDisabledRequest]) (*connect.Response[pmv1.UpdateTokenResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "SetTokenDisabled", req.Msg.Id); err != nil {
		return nil, err
	}
	var row store.RegistrationTokenRow
	_, err = h.store.WithAudit(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceSetTokenDisabledProcedure, "SetTokenDisabled"),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			updated, err := tx.SetRegistrationTokenDisabled(ctx, db.SetRegistrationTokenDisabledParams{
				ID: req.Msg.Id, Disabled: req.Msg.Disabled, ReservedName: store.BootstrapAdminTokenName,
			})
			if err != nil {
				return err
			}
			row = updated
			effect := tokenEffect(req.Msg.Id, "UPDATE", "disabled")
			effect.AfterFlag = &req.Msg.Disabled
			rec.Effect(effect)
			return nil
		})
	if err != nil {
		return nil, h.writeError(ctx, "set token disabled", err)
	}
	return connect.NewResponse(&pmv1.UpdateTokenResponse{Token: tokenToProto(row)}), nil
}

// DeleteToken soft-deletes a token so prior bearer values stay unusable.
func (h *Handlers) DeleteToken(ctx context.Context, req *connect.Request[pmv1.DeleteTokenRequest]) (*connect.Response[pmv1.DeleteTokenResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "DeleteToken", req.Msg.Id); err != nil {
		return nil, err
	}
	_, err = h.store.WithAudit(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceDeleteTokenProcedure, "DeleteToken"),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			if _, err := tx.SoftDeleteRegistrationToken(ctx, db.SoftDeleteRegistrationTokenParams{
				ID: req.Msg.Id, ReservedName: store.BootstrapAdminTokenName,
			}); err != nil {
				return err
			}
			rec.Effect(tokenEffect(req.Msg.Id, "DELETE", "is_deleted"))
			return nil
		})
	if err != nil {
		return nil, h.writeError(ctx, "delete token", err)
	}
	return connect.NewResponse(&pmv1.DeleteTokenResponse{}), nil
}

func (h *Handlers) writeError(ctx context.Context, operation string, err error) error {
	if store.IsNotFound(err) {
		return notFound(ctx, errTokenNotFound, "token not found")
	}
	return h.internal(ctx, operation, err)
}

func tokenToProto(row store.RegistrationTokenRow) *pmv1.RegistrationToken {
	out := &pmv1.RegistrationToken{
		Id: row.ID, Name: row.Name, OneTime: row.OneTime,
		MaxUses: row.MaxUses, CurrentUses: row.CurrentUses,
		CreatedBy: row.CreatedBy, Disabled: row.Disabled,
	}
	if row.ExpiresAt != nil {
		out.ExpiresAt = timestamppb.New(*row.ExpiresAt)
	}
	if row.CreatedAt != nil {
		out.CreatedAt = timestamppb.New(*row.CreatedAt)
	}
	if row.OwnerID != nil {
		out.OwnerId = *row.OwnerID
	}
	return out
}

func boundedCount(n int64) int32 {
	const maxInt32 = int64(^uint32(0) >> 1)
	if n > maxInt32 {
		return int32(maxInt32)
	}
	return int32(n)
}
