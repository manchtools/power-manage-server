package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// DefaultAuditStream is the stream every operation joins unless a
// caller names another one.
const DefaultAuditStream = "control"

// OperationClass distinguishes the kinds of thing worth recording, so
// the log does not force a sensitive read or a failed login through a
// mutation-shaped template.
type OperationClass string

const (
	// ClassMutation is a state change.
	ClassMutation OperationClass = "MUTATION"
	// ClassSensitiveRead is a read of protected material — a stored
	// passphrase, a recovery key, an audit export.
	ClassSensitiveRead OperationClass = "SENSITIVE_READ"
	// ClassRejectedAuthentication is an authentication attempt that
	// did not succeed. It has no actor id, by definition.
	ClassRejectedAuthentication OperationClass = "REJECTED_AUTHENTICATION"
	// ClassBackgroundWriter is a non-RPC writer: SCIM, a scheduled
	// job, retention, enrollment, maintenance.
	ClassBackgroundWriter OperationClass = "BACKGROUND_WRITER"
)

// AuthorizationOutcome records what the authorization layer decided.
type AuthorizationOutcome string

const (
	AuthorizationAllowed       AuthorizationOutcome = "ALLOWED"
	AuthorizationDenied        AuthorizationOutcome = "DENIED"
	AuthorizationNotApplicable AuthorizationOutcome = "NOT_APPLICABLE"
)

// OperationResult is the operation's overall outcome.
type OperationResult string

const (
	ResultSuccess  OperationResult = "SUCCESS"
	ResultFailure  OperationResult = "FAILURE"
	ResultRejected OperationResult = "REJECTED"
)

// EffectOutcome is one effect's outcome.
type EffectOutcome string

const (
	EffectApplied  EffectOutcome = "APPLIED"
	EffectRejected EffectOutcome = "REJECTED"
	EffectFailed   EffectOutcome = "FAILED"
)

// Errors the audited primitives return. Callers distinguish them with
// errors.Is; none of them carry a caller value in their message.
var (
	// ErrAuditOperationRequired means a mutation was attempted without
	// a usable operation descriptor. The mutation never ran.
	ErrAuditOperationRequired = errors.New("audit operation required")
	// ErrAuditEffectRequired means a continuation appended no effect,
	// so it would have recorded nothing.
	ErrAuditEffectRequired = errors.New("audit effect required")
	// ErrAuditEffectInvalid means an effect carried a reference that is
	// not a row id. The schema enforces the same shape, but only at
	// INSERT time — by then the effect and the operation are inside one
	// transaction, so the whole audited call rolls back and the caller
	// sees a database error rather than the bad reference. Refusing in
	// Go makes the offending call site fail where it can be read.
	ErrAuditEffectInvalid = errors.New("audit effect is invalid")
	// ErrAuditChainBroken means verification found a row whose hash,
	// linkage or position does not follow from its predecessor.
	ErrAuditChainBroken = errors.New("audit chain broken")
	// ErrAuditAnchorMismatch means the local chain does not reproduce
	// the value an off-host anchor pinned.
	ErrAuditAnchorMismatch = errors.New("audit chain anchor mismatch")
	// ErrAuditArchiveRequired means retention was asked to delete a
	// prefix without evidence that the prefix had been archived.
	ErrAuditArchiveRequired = errors.New("audit archive confirmation required")
	// ErrAuditBoundaryNotClosed means the proposed retention boundary
	// would leave a surviving effect referencing a deleted operation.
	ErrAuditBoundaryNotClosed = errors.New("audit retention boundary is not a closed prefix")
)

// AuditOperation describes one logical request or background
// operation. Its text fields are code-derived constants — an RPC full
// method, a permission constant, a status code name — never request
// input; the database rejects anything outside those shapes.
type AuditOperation struct {
	// OperationID is minted when empty. Supply it to reuse an id
	// across a fan-out.
	OperationID string
	// Stream defaults to DefaultAuditStream.
	Stream string

	Class     OperationClass
	ActorType string
	// ActorID is the acting subject's ULID, empty when the attempt
	// never authenticated.
	ActorID string
	// ActorFingerprint is the SHA-256 hex digest of the presented
	// certificate, key or token.
	ActorFingerprint string

	Origin string
	// OriginFingerprint is the SHA-256 hex digest of the peer address.
	// The address itself is personal data and is not stored in clear.
	OriginFingerprint string
	RequestDescriptor string

	AuthorizationOutcome AuthorizationOutcome
	AuthorizationDetail  string

	Result     OperationResult
	ResultCode string

	// SealedDetail is class-three evidence: a value that is only
	// meaningful as itself, encrypted under SealedDetailSubject's DEK.
	SealedDetail        []byte
	SealedDetailSubject string
}

// AuditEffect describes one thing an operation did.
//
// There is no free-form value field. A changed value is a reference to
// another row, a state flag, a count, a non-reversible digest, or
// per-subject sealed detail — nothing else is representable, which is
// what keeps a credential out of the log by construction rather than
// by reviewer vigilance.
type AuditEffect struct {
	ResourceType string
	ResourceID   string
	Action       string
	Outcome      EffectOutcome

	// ChangedFields lists field NAMES. Bounded lowercase identifiers.
	ChangedFields []string

	BeforeRef   *string
	AfterRef    *string
	BeforeFlag  *bool
	AfterFlag   *bool
	BeforeCount *int64
	AfterCount  *int64

	// EvidenceKind names what EvidenceFingerprint digests, so the
	// digest is interpretable without being reversible. Both or
	// neither.
	EvidenceKind        string
	EvidenceFingerprint string

	SealedDetail        []byte
	SealedDetailSubject string
}

// AuditRecorder collects the effects an audited call produced. A
// mutation callback records effects as it discovers them — including
// ids minted during the mutation — and the primitive writes them in
// the same transaction.
type AuditRecorder struct {
	effects       []AuditEffect
	searchTouches []searchTouch
}

// Effect appends one effect to the operation.
func (r *AuditRecorder) Effect(e AuditEffect) { r.effects = append(r.effects, e) }

// RefreshSearch records derived search state that must be refreshed in this
// transaction but is not itself a separate auditable effect. Use it when a
// relationship row changes fields on another resource's search document.
func (r *AuditRecorder) RefreshSearch(resourceType, resourceID string) {
	r.searchTouches = append(r.searchTouches, searchTouch{resourceType: resourceType, resourceID: resourceID})
}

// Len reports how many effects have been recorded.
func (r *AuditRecorder) Len() int { return len(r.effects) }

// AuditRecord is what an audited call wrote.
type AuditRecord struct {
	OperationID string
	Stream      string
	// OperationSeq is the operation row's chain position; zero for a
	// continuation, which appends no operation row.
	OperationSeq int64
	// EffectSeqs are the chain positions of the effect rows written by
	// this call, in order.
	EffectSeqs []int64
	// HeadSeq and HeadHash are the chain tip after this call.
	HeadSeq  int64
	HeadHash []byte
}

// genesisHash is the prev_hash of the first row in a stream.
var genesisHash = make([]byte, sha256.Size)

// WithAudit is the only door through which a state mutation reaches
// the database.
//
// It opens one transaction, runs mutate with a transaction-bound
// query handle, then appends the operation row and every recorded
// effect at consecutive chain positions and advances the head — all
// before the single commit. Either everything lands or nothing does: a
// failure anywhere, including in the audit write itself, rolls the
// mutation back.
//
// mutate may be nil for an operation that changes no state, which is
// how a sensitive read or a rejected authentication is recorded.
//
// SQLite has one writer. Store serializes the complete callback and audit
// append in-process, avoiding lock-upgrade races while preserving the single
// transaction boundary. The control server is deliberately single-process.
func (s *Store) WithAudit(
	ctx context.Context,
	op AuditOperation,
	mutate func(ctx context.Context, tx *Tx, rec *AuditRecorder) error,
) (AuditRecord, error) {
	if err := op.validate(); err != nil {
		// Refused before the transaction opens: a mutation without a
		// usable operation performs no database work at all.
		return AuditRecord{}, err
	}
	if op.OperationID == "" {
		op.OperationID = ulid.Make().String()
	}
	if op.Stream == "" {
		op.Stream = DefaultAuditStream
	}

	var rec AuditRecorder
	var out AuditRecord
	err := s.withTx(ctx, func(raw *sql.Tx, q *generated.Queries) error {
		if mutate != nil {
			if err := mutate(ctx, &Tx{Queries: q, raw: raw}, &rec); err != nil {
				return err
			}
		}
		if err := refreshSearchDocumentsForEffects(ctx, raw, rec.effects, rec.searchTouches); err != nil {
			return err
		}

		head, err := q.LockAuditChainHead(ctx, op.Stream)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("audit: unknown stream %q", op.Stream)
			}
			return fmt.Errorf("audit: lock chain head: %w", err)
		}

		at := s.auditNow()
		prev, seq := head.HeadHash, head.Height

		seq++
		row := op.canonical(seq, at)
		hash := chainHash(prev, row)
		if _, err := q.InsertAuditOperation(ctx, op.insertParams(seq, at, prev, hash)); err != nil {
			return fmt.Errorf("audit: insert operation: %w", err)
		}
		out.OperationSeq = seq
		prev = hash

		for i, e := range rec.effects {
			if err := e.validate(); err != nil {
				return fmt.Errorf("audit: effect %d: %w", i, err)
			}
			seq++
			effectID := ulid.Make().String()
			ec := e.canonical(op.Stream, op.OperationID, effectID, seq, int64(i), at)
			hash = chainHash(prev, ec)
			if _, err := q.InsertAuditEffect(ctx, e.insertParams(
				op.Stream, op.OperationID, effectID, seq, int64(i), at, prev, hash,
			)); err != nil {
				return fmt.Errorf("audit: insert effect %d: %w", i, err)
			}
			out.EffectSeqs = append(out.EffectSeqs, seq)
			prev = hash
		}
		if err := refreshSearchDocument(ctx, raw, "audit_events", op.OperationID); err != nil {
			return err
		}

		if err := q.AdvanceAuditChainHead(ctx, generated.AdvanceAuditChainHeadParams{
			Stream:   op.Stream,
			HeadHash: prev,
			Height:   seq,
		}); err != nil {
			return fmt.Errorf("audit: advance chain head: %w", err)
		}

		out.OperationID = op.OperationID
		out.Stream = op.Stream
		out.HeadSeq = seq
		out.HeadHash = prev
		return nil
	})
	if err != nil {
		return AuditRecord{}, err
	}
	return out, nil
}

// RecordOperation writes an operation and its effects with no state
// mutation. Sensitive reads and rejected authentication attempts use
// it; they are audited operations that change nothing.
func (s *Store) RecordOperation(ctx context.Context, op AuditOperation, effects ...AuditEffect) (AuditRecord, error) {
	// Every effect is known here, so a malformed one is refused before the
	// transaction opens — the same standing rule op.validate() follows.
	for i, e := range effects {
		if err := e.validate(); err != nil {
			return AuditRecord{}, fmt.Errorf("audit: effect %d: %w", i, err)
		}
	}
	return s.WithAudit(ctx, op, func(_ context.Context, _ *Tx, rec *AuditRecorder) error {
		for _, e := range effects {
			rec.Effect(e)
		}
		return nil
	})
}

// WithAuditEffects continues an operation that is already on the
// chain. Work that finishes long after the request that started it —
// a delivery acknowledged after a reconnect, a result ingested minutes
// later — appends its effects here, carrying the original
// operation_id, so the outcome stays attributable without anything
// already committed being rewritten.
//
// The effects take fresh positions at the current head. The operation
// row is untouched, so an anchor taken before this call still
// authenticates its prefix afterwards.
func (s *Store) WithAuditEffects(
	ctx context.Context,
	operationID string,
	mutate func(ctx context.Context, tx *Tx, rec *AuditRecorder) error,
) (AuditRecord, error) {
	if operationID == "" {
		return AuditRecord{}, fmt.Errorf("%w: continuation needs the operation it belongs to", ErrAuditOperationRequired)
	}

	var rec AuditRecorder
	var out AuditRecord
	err := s.withTx(ctx, func(raw *sql.Tx, q *generated.Queries) error {
		parent, err := q.GetAuditOperation(ctx, operationID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("%w: no operation %s on the chain", ErrAuditOperationRequired, operationID)
			}
			return fmt.Errorf("audit: load operation: %w", err)
		}

		if mutate != nil {
			if err := mutate(ctx, &Tx{Queries: q, raw: raw}, &rec); err != nil {
				return err
			}
		}
		if len(rec.effects) == 0 {
			return fmt.Errorf("%w: a continuation of %s recorded nothing", ErrAuditEffectRequired, operationID)
		}
		if err := refreshSearchDocumentsForEffects(ctx, raw, rec.effects, rec.searchTouches); err != nil {
			return err
		}

		// The store-wide writer lock already serializes this append.
		head, err := q.LockAuditChainHead(ctx, parent.Stream)
		if err != nil {
			return fmt.Errorf("audit: lock chain head: %w", err)
		}

		// Read under the head lock: two continuations of the same
		// operation must not both claim the same position within it.
		nextEffectSeq, err := q.NextAuditEffectSeq(ctx, operationID)
		if err != nil {
			return fmt.Errorf("audit: next effect seq: %w", err)
		}

		at := s.auditNow()
		prev, seq := head.HeadHash, head.Height
		for i, e := range rec.effects {
			if err := e.validate(); err != nil {
				return fmt.Errorf("audit: effect %d: %w", i, err)
			}
			seq++
			effectID := ulid.Make().String()
			pos := nextEffectSeq + int64(i)
			ec := e.canonical(parent.Stream, operationID, effectID, seq, pos, at)
			hash := chainHash(prev, ec)
			if _, err := q.InsertAuditEffect(ctx, e.insertParams(
				parent.Stream, operationID, effectID, seq, pos, at, prev, hash,
			)); err != nil {
				return fmt.Errorf("audit: insert effect %d: %w", i, err)
			}
			out.EffectSeqs = append(out.EffectSeqs, seq)
			prev = hash
		}
		if err := refreshSearchDocument(ctx, raw, "audit_events", operationID); err != nil {
			return err
		}

		if err := q.AdvanceAuditChainHead(ctx, generated.AdvanceAuditChainHeadParams{
			Stream:   parent.Stream,
			HeadHash: prev,
			Height:   seq,
		}); err != nil {
			return fmt.Errorf("audit: advance chain head: %w", err)
		}

		out.OperationID = operationID
		out.Stream = parent.Stream
		out.HeadSeq = seq
		out.HeadHash = prev
		return nil
	})
	if err != nil {
		return AuditRecord{}, err
	}
	return out, nil
}

// validate rejects an operation that could not be attributed. It is
// deliberately narrow: the structural requirements live here so a
// mutation with no operation performs zero database work, while every
// format rule lives in the schema, where it is enforced for every
// writer rather than for the ones that remembered to ask.
func (op AuditOperation) validate() error {
	switch {
	case op.Class == "":
		return fmt.Errorf("%w: operation class is unset", ErrAuditOperationRequired)
	case op.RequestDescriptor == "":
		return fmt.Errorf("%w: request descriptor is unset", ErrAuditOperationRequired)
	case op.ActorType == "":
		return fmt.Errorf("%w: actor type is unset", ErrAuditOperationRequired)
	case op.Origin == "":
		return fmt.Errorf("%w: origin is unset", ErrAuditOperationRequired)
	case op.AuthorizationOutcome == "":
		return fmt.Errorf("%w: authorization outcome is unset", ErrAuditOperationRequired)
	case op.Result == "":
		return fmt.Errorf("%w: result is unset", ErrAuditOperationRequired)
	}
	return nil
}

// validate rejects an effect whose reference columns are not row ids.
//
// before_ref and after_ref name ANOTHER ROW; they are the one part of an
// effect the schema constrains to a ULID, and they are therefore the one
// part a caller can quietly misuse as a free-text field. When that happens
// the INSERT aborts inside the audited transaction and takes the operation
// row with it, so the call site's only symptom is an error it usually logs
// and swallows — the audit record simply never exists. A discriminator
// belongs in the operation's result code or in the effect's action.
func (e AuditEffect) validate() error {
	for _, ref := range []struct {
		column string
		value  *string
	}{{"before_ref", e.BeforeRef}, {"after_ref", e.AfterRef}} {
		if ref.value == nil {
			continue
		}
		if _, err := ulid.ParseStrict(*ref.value); err != nil {
			// The value itself stays out of the message: it is the caller's
			// data, and this error reaches ordinary error logs.
			return fmt.Errorf("%w: %s must be a ULID naming another row", ErrAuditEffectInvalid, ref.column)
		}
	}
	return nil
}

// auditNow returns the timestamp the audit rows carry, truncated to
// the microsecond resolution SQLite stores. Hashing a value the
// database cannot round-trip would make every chain fail verification
// on the first read-back.
func (s *Store) auditNow() time.Time {
	return s.clock().UTC().Truncate(time.Microsecond)
}

func nilIfEmpty(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

func (op AuditOperation) insertParams(seq int64, at time.Time, prev, hash []byte) generated.InsertAuditOperationParams {
	return generated.InsertAuditOperationParams{
		OperationID:          op.OperationID,
		Stream:               op.Stream,
		ChainSeq:             seq,
		OperationClass:       string(op.Class),
		ActorType:            op.ActorType,
		ActorID:              op.ActorID,
		ActorFingerprint:     op.ActorFingerprint,
		Origin:               op.Origin,
		OriginFingerprint:    op.OriginFingerprint,
		RequestDescriptor:    op.RequestDescriptor,
		AuthorizationOutcome: string(op.AuthorizationOutcome),
		AuthorizationDetail:  op.AuthorizationDetail,
		Result:               string(op.Result),
		ResultCode:           op.ResultCode,
		OccurredAt:           at,
		SealedDetail:         op.SealedDetail,
		SealedDetailSubject:  nilIfEmpty(op.SealedDetailSubject),
		PrevHash:             prev,
		RowHash:              hash,
	}
}

func (e AuditEffect) insertParams(
	stream, operationID, effectID string,
	seq int64, effectSeq int64,
	at time.Time, prev, hash []byte,
) generated.InsertAuditEffectParams {
	// The column is NOT NULL with an empty-array default; a nil slice
	// would be sent as NULL and rejected. An effect that changed no
	// named field is ordinary — a read, a dispatch — so it must not
	// have to pass an empty literal.
	changed := e.ChangedFields
	if changed == nil {
		changed = []string{}
	}
	return generated.InsertAuditEffectParams{
		EffectID:            effectID,
		OperationID:         operationID,
		Stream:              stream,
		ChainSeq:            seq,
		EffectSeq:           effectSeq,
		ResourceType:        e.ResourceType,
		ResourceID:          e.ResourceID,
		Action:              e.Action,
		Outcome:             string(e.Outcome),
		ChangedFields:       changed,
		BeforeRef:           e.BeforeRef,
		AfterRef:            e.AfterRef,
		BeforeFlag:          e.BeforeFlag,
		AfterFlag:           e.AfterFlag,
		BeforeCount:         e.BeforeCount,
		AfterCount:          e.AfterCount,
		EvidenceKind:        e.EvidenceKind,
		EvidenceFingerprint: e.EvidenceFingerprint,
		SealedDetail:        e.SealedDetail,
		SealedDetailSubject: nilIfEmpty(e.SealedDetailSubject),
		OccurredAt:          at,
		PrevHash:            prev,
		RowHash:             hash,
	}
}

// ---------------------------------------------------------------------------
// Canonical encoding
// ---------------------------------------------------------------------------

// canonicalWriter builds the byte string a row's hash covers.
//
// Every field is written as a one-byte presence marker, an eight-byte
// big-endian length and the bytes themselves. Length prefixing is what
// makes the encoding unambiguous: without it, moving a character from
// the end of one field to the start of the next would produce the same
// bytes and the same hash.
type canonicalWriter struct{ buf []byte }

func (w *canonicalWriter) field(present bool, v []byte) {
	if !present {
		w.buf = append(w.buf, 0)
		return
	}
	w.buf = append(w.buf, 1)
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(v)))
	w.buf = append(w.buf, n[:]...)
	w.buf = append(w.buf, v...)
}

func (w *canonicalWriter) str(v string)     { w.field(true, []byte(v)) }
func (w *canonicalWriter) bytes(v []byte)   { w.field(v != nil, v) }
func (w *canonicalWriter) optStr(v *string) { w.field(v != nil, []byte(deref(v))) }

func (w *canonicalWriter) int(v int64) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(v))
	w.field(true, n[:])
}

func (w *canonicalWriter) optInt(v *int64) {
	if v == nil {
		w.field(false, nil)
		return
	}
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(*v))
	w.field(true, n[:])
}

func (w *canonicalWriter) optBool(v *bool) {
	if v == nil {
		w.field(false, nil)
		return
	}
	b := byte(0)
	if *v {
		b = 1
	}
	w.field(true, []byte{b})
}

func (w *canonicalWriter) strs(v []string) {
	w.int(int64(len(v)))
	for _, s := range v {
		w.str(s)
	}
}

func (w *canonicalWriter) time(v time.Time) {
	w.str(v.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano))
}

func deref(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

// chainHash links a row to its predecessor.
func chainHash(prev, canonical []byte) []byte {
	h := sha256.New()
	h.Write(prev)
	h.Write(canonical)
	return h.Sum(nil)
}

// The domain tags keep the two row kinds in separate hash spaces, so
// an operation row and an effect row can never produce the same
// canonical bytes.
const (
	canonicalOperationTag = "pm.audit.operation.v1"
	canonicalEffectTag    = "pm.audit.effect.v1"
)

func (op AuditOperation) canonical(seq int64, at time.Time) []byte {
	w := &canonicalWriter{}
	w.str(canonicalOperationTag)
	w.str(op.Stream)
	w.int(seq)
	w.str(op.OperationID)
	w.str(string(op.Class))
	w.str(op.ActorType)
	w.str(op.ActorID)
	w.str(op.ActorFingerprint)
	w.str(op.Origin)
	w.str(op.OriginFingerprint)
	w.str(op.RequestDescriptor)
	w.str(string(op.AuthorizationOutcome))
	w.str(op.AuthorizationDetail)
	w.str(string(op.Result))
	w.str(op.ResultCode)
	w.time(at)
	w.bytes(op.SealedDetail)
	w.optStr(nilIfEmpty(op.SealedDetailSubject))
	return w.buf
}

func (e AuditEffect) canonical(stream, operationID, effectID string, seq int64, effectSeq int64, at time.Time) []byte {
	// Normalised exactly as insertParams normalises it, so a nil slice
	// and an empty slice hash identically to the empty array the
	// database stores for both.
	changed := e.ChangedFields
	if changed == nil {
		changed = []string{}
	}
	w := &canonicalWriter{}
	w.str(canonicalEffectTag)
	w.str(stream)
	w.int(seq)
	w.str(effectID)
	w.str(operationID)
	w.int(int64(effectSeq))
	w.str(e.ResourceType)
	w.str(e.ResourceID)
	w.str(e.Action)
	w.str(string(e.Outcome))
	w.strs(changed)
	w.optStr(e.BeforeRef)
	w.optStr(e.AfterRef)
	w.optBool(e.BeforeFlag)
	w.optBool(e.AfterFlag)
	w.optInt(e.BeforeCount)
	w.optInt(e.AfterCount)
	w.str(e.EvidenceKind)
	w.str(e.EvidenceFingerprint)
	w.bytes(e.SealedDetail)
	w.optStr(nilIfEmpty(e.SealedDetailSubject))
	w.time(at)
	return w.buf
}

// canonicalOf recomputes the canonical bytes of a stored operation row
// exactly as they were computed at append time. Verification uses it,
// so a single encoder change cannot make a stored chain silently
// unverifiable in one direction only.
func canonicalOfOperation(row generated.AuditOperation) []byte {
	op := AuditOperation{
		OperationID:          row.OperationID,
		Stream:               row.Stream,
		Class:                OperationClass(row.OperationClass),
		ActorType:            row.ActorType,
		ActorID:              row.ActorID,
		ActorFingerprint:     row.ActorFingerprint,
		Origin:               row.Origin,
		OriginFingerprint:    row.OriginFingerprint,
		RequestDescriptor:    row.RequestDescriptor,
		AuthorizationOutcome: AuthorizationOutcome(row.AuthorizationOutcome),
		AuthorizationDetail:  row.AuthorizationDetail,
		Result:               OperationResult(row.Result),
		ResultCode:           row.ResultCode,
		SealedDetail:         row.SealedDetail,
		SealedDetailSubject:  deref(row.SealedDetailSubject),
	}
	return op.canonical(row.ChainSeq, row.OccurredAt)
}

func canonicalOfEffect(row generated.AuditEffect) []byte {
	e := AuditEffect{
		ResourceType:        row.ResourceType,
		ResourceID:          row.ResourceID,
		Action:              row.Action,
		Outcome:             EffectOutcome(row.Outcome),
		ChangedFields:       row.ChangedFields,
		BeforeRef:           row.BeforeRef,
		AfterRef:            row.AfterRef,
		BeforeFlag:          row.BeforeFlag,
		AfterFlag:           row.AfterFlag,
		BeforeCount:         row.BeforeCount,
		AfterCount:          row.AfterCount,
		EvidenceKind:        row.EvidenceKind,
		EvidenceFingerprint: row.EvidenceFingerprint,
		SealedDetail:        row.SealedDetail,
		SealedDetailSubject: deref(row.SealedDetailSubject),
	}
	return e.canonical(row.Stream, row.OperationID, row.EffectID, row.ChainSeq, row.EffectSeq, row.OccurredAt)
}
