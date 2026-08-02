package store_test

// The audit spine, driven against a real PostgreSQL.
//
// Every test here exercises the property through the real primitive
// and the real schema. The failure paths are produced by genuine
// constraint violations and genuine trigger refusals — there is no
// test-only branch in the production type to reach them with, because
// a guard that only fires for tests proves nothing about production.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// mutationOp is a well-formed MUTATION descriptor. Tests vary only the
// field under examination so a failure names one cause.
func mutationOp() store.AuditOperation {
	return store.AuditOperation{
		Class:                store.ClassMutation,
		ActorType:            "user",
		ActorID:              newID(),
		Origin:               "rpc",
		OriginFingerprint:    sha256hex("198.51.100.7"),
		RequestDescriptor:    "powermanage.v1.ControlService/RegisterDevice",
		AuthorizationOutcome: store.AuthorizationAllowed,
		AuthorizationDetail:  "RegisterDevice",
		Result:               store.ResultSuccess,
		ResultCode:           "OK",
	}
}

func insertDevice(ctx context.Context, tx *store.Tx, id, hostname string) error {
	at := time.Now().UTC()
	_, err := tx.InsertDevice(ctx, generated.InsertDeviceParams{
		ID:                    id,
		Hostname:              hostname,
		AgentVersion:          "1.0.0",
		AgentSealingPublicKey: make([]byte, 32),
		RegisteredAt:          &at,
		LastSeenAt:            &at,
	})
	return err
}

func deviceEffect(id string) store.AuditEffect {
	return store.AuditEffect{
		ResourceType:  "device",
		ResourceID:    id,
		Action:        "CREATE",
		Outcome:       store.EffectApplied,
		ChangedFields: []string{"hostname", "agent_version"},
	}
}

func countRows(t *testing.T, pool *pgxpool.Pool, table string) int64 {
	t.Helper()
	var n int64
	// table is a constant from this file, never caller input.
	require.NoError(t, pool.QueryRow(context.Background(),
		fmt.Sprintf("SELECT count(*) FROM public.%s", table)).Scan(&n))
	return n
}

// ---------------------------------------------------------------------------
// The mutation door
// ---------------------------------------------------------------------------

// A mutation cannot commit without an operation. The callback must not
// even run: refusing after the callback has written rows would rely on
// rollback, and the guarantee is stronger than that.
func TestWithAudit_RefusesMutationWithoutOperation(t *testing.T) {
	st, pool := setupPostgres(t)
	ctx := context.Background()

	ran := false
	_, err := st.WithAudit(ctx, store.AuditOperation{}, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		ran = true
		return insertDevice(ctx, tx, newID(), "never-created")
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, store.ErrAuditOperationRequired)
	assert.False(t, ran, "the mutation callback must not run without an operation descriptor")
	assert.Zero(t, countRows(t, pool, "devices"), "no device may exist after a refused audited mutation")
	assert.Zero(t, countRows(t, pool, "audit_operations"))
}

// Each structurally required field is checked on its own, so a missing
// one names itself rather than being masked by whichever check runs
// first.
func TestWithAudit_RefusesIncompleteOperationDescriptor(t *testing.T) {
	st, pool := setupPostgres(t)
	ctx := context.Background()

	cases := map[string]func(*store.AuditOperation){
		"class":                 func(o *store.AuditOperation) { o.Class = "" },
		"request descriptor":    func(o *store.AuditOperation) { o.RequestDescriptor = "" },
		"actor type":            func(o *store.AuditOperation) { o.ActorType = "" },
		"origin":                func(o *store.AuditOperation) { o.Origin = "" },
		"authorization outcome": func(o *store.AuditOperation) { o.AuthorizationOutcome = "" },
		"result":                func(o *store.AuditOperation) { o.Result = "" },
	}
	require.NotEmpty(t, cases, "matches-zero guard: the descriptor case table is empty")

	for name, blank := range cases {
		t.Run(name, func(t *testing.T) {
			op := mutationOp()
			blank(&op)
			ran := false
			_, err := st.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, _ *store.AuditRecorder) error {
				ran = true
				return insertDevice(ctx, tx, newID(), "never-created")
			})
			assert.ErrorIs(t, err, store.ErrAuditOperationRequired)
			assert.False(t, ran)
		})
	}
	assert.Zero(t, countRows(t, pool, "devices"))
}

// The initial operation row, its effects and the state change commit
// together, at consecutive chain positions, and the chain verifies.
func TestWithAudit_CommitsMutationOperationAndEffectsInOneTransaction(t *testing.T) {
	st, pool := setupPostgres(t)
	ctx := context.Background()

	deviceID := newID()
	rec, err := st.WithAudit(ctx, mutationOp(), func(ctx context.Context, tx *store.Tx, r *store.AuditRecorder) error {
		if err := insertDevice(ctx, tx, deviceID, "alpha.example.test"); err != nil {
			return err
		}
		r.Effect(deviceEffect(deviceID))
		r.Effect(store.AuditEffect{
			ResourceType:  "device",
			ResourceID:    deviceID,
			Action:        "LABEL_SET",
			Outcome:       store.EffectApplied,
			ChangedFields: []string{"environment"},
		})
		return nil
	})
	require.NoError(t, err)

	assert.Equal(t, int64(1), rec.OperationSeq, "the first row of a fresh stream is position 1")
	assert.Equal(t, []int64{2, 3}, rec.EffectSeqs, "initial effects take the positions right after their operation")
	assert.Equal(t, int64(3), rec.HeadSeq)

	dev, err := st.GetDevice(ctx, deviceID)
	require.NoError(t, err)
	assert.Equal(t, "alpha.example.test", dev.Hostname)

	op, err := st.GetAuditOperation(ctx, rec.OperationID)
	require.NoError(t, err)
	assert.Equal(t, string(store.ClassMutation), op.OperationClass)
	assert.Equal(t, "ALLOWED", op.AuthorizationOutcome)

	effects, err := st.ListAuditEffects(ctx, rec.OperationID)
	require.NoError(t, err)
	require.Len(t, effects, 2)
	assert.Equal(t, int32(0), effects[0].EffectSeq)
	assert.Equal(t, int32(1), effects[1].EffectSeq)

	v, err := st.VerifyAuditChain(ctx, store.AuditVerifyOptions{})
	require.NoError(t, err)
	assert.Equal(t, int64(3), v.Rows)

	assert.Equal(t, int64(3), countRows(t, pool, "audit_effects")+countRows(t, pool, "audit_operations"))
}

// A mutation callback error rolls the whole transaction back, audit
// rows included, and leaves the chain head where it was.
func TestWithAudit_MutationFailureLeavesNoAuditRecord(t *testing.T) {
	st, pool := setupPostgres(t)
	ctx := context.Background()

	sentinel := errors.New("domain rejected the request")
	_, err := st.WithAudit(ctx, mutationOp(), func(ctx context.Context, tx *store.Tx, r *store.AuditRecorder) error {
		if err := insertDevice(ctx, tx, newID(), "rolled-back"); err != nil {
			return err
		}
		r.Effect(deviceEffect(newID()))
		return sentinel
	})
	require.ErrorIs(t, err, sentinel)

	assert.Zero(t, countRows(t, pool, "devices"))
	assert.Zero(t, countRows(t, pool, "audit_operations"))

	tip, err := st.AuditChainTipOf(ctx, store.DefaultAuditStream)
	require.NoError(t, err)
	assert.Zero(t, tip.Height, "a rolled-back operation must not advance the chain head")
}

// A failure in the AUDIT write rolls the state change back.
//
// The failure is a real one: the effect names a before/after reference
// that is not a ULID, which the schema's typed reference CHECK
// refuses. Nothing in the production type knows this is a test.
func TestWithAudit_AuditWriteFailureRollsBackTheMutation(t *testing.T) {
	st, pool := setupPostgres(t)
	ctx := context.Background()

	deviceID := newID()
	notAULID := "hunter2.v2"
	_, err := st.WithAudit(ctx, mutationOp(), func(ctx context.Context, tx *store.Tx, r *store.AuditRecorder) error {
		if err := insertDevice(ctx, tx, deviceID, "should-not-survive"); err != nil {
			return err
		}
		e := deviceEffect(deviceID)
		e.AfterRef = &notAULID
		r.Effect(e)
		return nil
	})
	require.Error(t, err, "the schema must refuse a reference value that is not a ULID")
	assert.Contains(t, err.Error(), "audit_effects_after_ref_ulid")

	_, getErr := st.GetDevice(ctx, deviceID)
	assert.True(t, store.IsNotFound(getErr),
		"a failed audit write must take the state change with it, got %v", getErr)
	assert.Zero(t, countRows(t, pool, "devices"))
	assert.Zero(t, countRows(t, pool, "audit_operations"))
	assert.Zero(t, countRows(t, pool, "audit_effects"))
}

// ---------------------------------------------------------------------------
// Typed reference values
// ---------------------------------------------------------------------------

// The class-1 value slots take ULIDs and nothing else, so a credential
// cannot be written into an effect even by a caller that tries. Both
// shapes a permissive charset would have admitted are covered: a
// password that happens to use only identifier characters, and a
// lowercase hex token.
func TestAuditEffect_ReferenceValuesRejectCredentialShapedStrings(t *testing.T) {
	st, pool := setupPostgres(t)
	ctx := context.Background()

	rejected := map[string]string{
		"password with punctuation": "hunter2.v2",
		"password with symbols":     "Tr0ub4dor&3",
		"lowercase hex token":       strings.Repeat("a3f9", 12), // 48 hex characters
		"bare word password":        "correcthorsebatterystaple",
	}
	require.NotEmpty(t, rejected, "matches-zero guard: the credential-shape table is empty")

	for name, value := range rejected {
		t.Run(name, func(t *testing.T) {
			v := value
			e := deviceEffect(newID())
			e.AfterRef = &v
			_, err := st.RecordOperation(ctx, mutationOp(), e)
			require.Error(t, err, "a reference value must be a ULID, %q is not", value)
			assert.Contains(t, err.Error(), "audit_effects_after_ref_ulid")
		})
		t.Run(name+" as before_ref", func(t *testing.T) {
			v := value
			e := deviceEffect(newID())
			e.BeforeRef = &v
			_, err := st.RecordOperation(ctx, mutationOp(), e)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "audit_effects_before_ref_ulid")
		})
	}

	assert.Zero(t, countRows(t, pool, "audit_effects"),
		"not one credential-shaped reference value may have landed")
}

// The changed-field list holds NAMES. Anything that is not a short
// lowercase identifier is refused, so it cannot be repurposed as the
// value slot the typed columns deny.
func TestAuditEffect_ChangedFieldsRejectNonIdentifiers(t *testing.T) {
	st, pool := setupPostgres(t)
	ctx := context.Background()

	rejected := map[string]string{
		"punctuation":         "hunter2.v2",
		"upper case and sign": "Tr0ub4dor&3",
		"48-character token":  strings.Repeat("a3f9", 12),
		"whitespace":          "two words",
	}
	require.NotEmpty(t, rejected, "matches-zero guard: the changed-field table is empty")

	for name, value := range rejected {
		t.Run(name, func(t *testing.T) {
			e := deviceEffect(newID())
			e.ChangedFields = []string{value}
			_, err := st.RecordOperation(ctx, mutationOp(), e)
			require.Error(t, err, "%q is not a field name", value)
			assert.Contains(t, err.Error(), "audit_effects_changed_fields_identifiers")
		})
	}

	// The positive control: real field names are accepted, so the
	// constraint is rejecting the right thing rather than everything.
	ok := deviceEffect(newID())
	ok.ChangedFields = []string{"hostname", "agent_version", "compliance_status"}
	_, err := st.RecordOperation(ctx, mutationOp(), ok)
	require.NoError(t, err)
	assert.Equal(t, int64(1), countRows(t, pool, "audit_effects"))
}

// Non-reversible evidence has its own named slot with its own format,
// and a digest without a kind — or a kind without a digest — is not
// admissible.
func TestAuditEffect_EvidenceIsADigestWithAKind(t *testing.T) {
	st, _ := setupPostgres(t)
	ctx := context.Background()

	t.Run("a plaintext value is not a digest", func(t *testing.T) {
		e := deviceEffect(newID())
		e.EvidenceKind = "certificate"
		e.EvidenceFingerprint = "-----BEGIN CERTIFICATE-----"
		_, err := st.RecordOperation(ctx, mutationOp(), e)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "audit_effects_evidence_fingerprint_sha256")
	})

	t.Run("a digest without a kind is uninterpretable", func(t *testing.T) {
		e := deviceEffect(newID())
		e.EvidenceFingerprint = sha256hex("leaf certificate")
		_, err := st.RecordOperation(ctx, mutationOp(), e)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "audit_effects_evidence_paired")
	})

	t.Run("a kind with a digest is accepted", func(t *testing.T) {
		e := deviceEffect(newID())
		e.EvidenceKind = "certificate"
		e.EvidenceFingerprint = sha256hex("leaf certificate")
		rec, err := st.RecordOperation(ctx, mutationOp(), e)
		require.NoError(t, err)
		effects, err := st.ListAuditEffects(ctx, rec.OperationID)
		require.NoError(t, err)
		require.Len(t, effects, 1)
		assert.Equal(t, sha256hex("leaf certificate"), effects[0].EvidenceFingerprint)
	})
}

// ---------------------------------------------------------------------------
// Append-only guards
// ---------------------------------------------------------------------------

func seedOperation(t *testing.T, st *store.Store) store.AuditRecord {
	t.Helper()
	rec, err := st.RecordOperation(context.Background(), mutationOp(), deviceEffect(newID()))
	require.NoError(t, err)
	return rec
}

func TestAuditTables_RejectUpdateAndDelete(t *testing.T) {
	st, pool := setupPostgres(t)
	ctx := context.Background()
	rec := seedOperation(t, st)

	statements := map[string]string{
		"update an operation": `UPDATE public.audit_operations SET result = 'SUCCESS' WHERE operation_id = $1`,
		"delete an operation": `DELETE FROM public.audit_operations WHERE operation_id = $1`,
		"update an effect":    `UPDATE public.audit_effects SET outcome = 'FAILED' WHERE operation_id = $1`,
		"delete an effect":    `DELETE FROM public.audit_effects WHERE operation_id = $1`,
	}
	require.NotEmpty(t, statements, "matches-zero guard: the append-only statement table is empty")

	for name, sql := range statements {
		t.Run(name, func(t *testing.T) {
			_, err := pool.Exec(ctx, sql, rec.OperationID)
			require.Error(t, err, "the append-only guard must refuse: %s", sql)
			assert.Contains(t, err.Error(), "append-only")
			assert.True(t, store.IsAppendOnlyViolation(err),
				"the refusal must be the append-only guard, not an incidental error: %v", err)
		})
	}

	assert.Equal(t, int64(1), countRows(t, pool, "audit_operations"))
	assert.Equal(t, int64(1), countRows(t, pool, "audit_effects"))

	v, err := st.VerifyAuditChain(ctx, store.AuditVerifyOptions{})
	require.NoError(t, err)
	assert.Equal(t, int64(2), v.Rows)
}

// TRUNCATE fires no row triggers, so it needs its own statement-level
// guard; without one it would bypass the retention range bound
// entirely.
func TestAuditTables_RejectTruncate(t *testing.T) {
	st, pool := setupPostgres(t)
	ctx := context.Background()
	seedOperation(t, st)

	for _, table := range []string{"audit_operations", "audit_effects", "audit_chain_anchors", "audit_chain_checkpoints"} {
		t.Run(table, func(t *testing.T) {
			_, err := pool.Exec(ctx, fmt.Sprintf("TRUNCATE public.%s CASCADE", table))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "append-only")
		})
	}
	assert.Equal(t, int64(1), countRows(t, pool, "audit_operations"))
}

// The anchors and checkpoints have no retention exemption at all: an
// anchor is a published fact and a checkpoint explains a gap, and
// editing either would defeat the guard it exists to provide.
func TestAuditAnchorsAndCheckpoints_RejectUpdateAndDelete(t *testing.T) {
	st, pool := setupPostgres(t)
	ctx := context.Background()
	seedOperation(t, st)

	anchor := publishAnchor(t, st, "s3://audit-anchors/2026-07-31")

	_, err := pool.Exec(ctx, `UPDATE public.audit_chain_anchors SET external_ref = 'elsewhere' WHERE anchor_id = $1`, anchor.AnchorID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "append-only")

	_, err = pool.Exec(ctx, `DELETE FROM public.audit_chain_anchors WHERE anchor_id = $1`, anchor.AnchorID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "append-only")

	assert.Equal(t, int64(1), countRows(t, pool, "audit_chain_anchors"))
}

// ---------------------------------------------------------------------------
// Chain verification
// ---------------------------------------------------------------------------

// disableAuditTriggers simulates the one adversary the triggers cannot
// stop — someone with rights over the table itself — so the hash chain
// can be tested as the guard that still holds when they are gone.
func disableAuditTriggers(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	for _, table := range []string{"audit_operations", "audit_effects"} {
		_, err := pool.Exec(ctx, fmt.Sprintf("ALTER TABLE public.%s DISABLE TRIGGER USER", table))
		require.NoError(t, err, "the fixture needs table ownership to simulate a privileged edit")
	}
	t.Cleanup(func() {
		for _, table := range []string{"audit_operations", "audit_effects"} {
			_, _ = pool.Exec(context.Background(),
				fmt.Sprintf("ALTER TABLE public.%s ENABLE TRIGGER USER", table))
		}
	})
}

func TestVerifyAuditChain_DetectsATamperedOperation(t *testing.T) {
	st, pool := setupPostgres(t)
	ctx := context.Background()

	rec := seedOperation(t, st)
	seedOperation(t, st)

	v, err := st.VerifyAuditChain(ctx, store.AuditVerifyOptions{})
	require.NoError(t, err, "the intact chain must verify before anything is touched")
	require.Equal(t, int64(4), v.Rows)

	disableAuditTriggers(t, pool)
	_, err = pool.Exec(ctx,
		`UPDATE public.audit_operations SET authorization_outcome = 'ALLOWED', result = 'SUCCESS', authorization_detail = 'Rewritten' WHERE operation_id = $1`,
		rec.OperationID)
	require.NoError(t, err, "with the guard disabled the edit lands — that is the point")

	_, err = st.VerifyAuditChain(ctx, store.AuditVerifyOptions{})
	require.Error(t, err)
	assert.ErrorIs(t, err, store.ErrAuditChainBroken)
	assert.Contains(t, err.Error(), "has been altered")
}

// An effect row carries its own position and its own hash, so editing
// one is detected exactly like editing an operation. A model that
// hashed effects only as part of their operation would miss this the
// moment an effect arrived after its operation was written.
func TestVerifyAuditChain_DetectsATamperedEffect(t *testing.T) {
	st, pool := setupPostgres(t)
	ctx := context.Background()

	rec := seedOperation(t, st)

	disableAuditTriggers(t, pool)
	_, err := pool.Exec(ctx,
		`UPDATE public.audit_effects SET outcome = 'REJECTED' WHERE operation_id = $1`, rec.OperationID)
	require.NoError(t, err)

	_, err = st.VerifyAuditChain(ctx, store.AuditVerifyOptions{})
	require.Error(t, err)
	assert.ErrorIs(t, err, store.ErrAuditChainBroken)
	assert.Contains(t, err.Error(), "effect row")
}

// A removed row leaves a gap no checkpoint explains, which is a break
// rather than a shorter chain.
func TestVerifyAuditChain_DetectsAnUnexplainedGap(t *testing.T) {
	st, pool := setupPostgres(t)
	ctx := context.Background()

	seedOperation(t, st)
	rec := seedOperation(t, st)
	seedOperation(t, st)

	disableAuditTriggers(t, pool)
	_, err := pool.Exec(ctx, `DELETE FROM public.audit_effects WHERE operation_id = $1`, rec.OperationID)
	require.NoError(t, err)

	_, err = st.VerifyAuditChain(ctx, store.AuditVerifyOptions{})
	require.Error(t, err)
	assert.ErrorIs(t, err, store.ErrAuditChainBroken)
}

// ---------------------------------------------------------------------------
// Operation classes
// ---------------------------------------------------------------------------

// A rejected authentication has no actor id — it never authenticated —
// and must still produce a complete, chained operation row. Recording
// it through the mutation template would have forced an actor that
// does not exist.
func TestRecordOperation_RejectedAuthentication(t *testing.T) {
	st, _ := setupPostgres(t)
	ctx := context.Background()

	rec, err := st.RecordOperation(ctx, store.AuditOperation{
		Class:                store.ClassRejectedAuthentication,
		ActorType:            "anonymous",
		ActorFingerprint:     sha256hex("presented-client-certificate"),
		Origin:               "agent_mtls",
		OriginFingerprint:    sha256hex("203.0.113.9"),
		RequestDescriptor:    "powermanage.v1.AgentService/Connect",
		AuthorizationOutcome: store.AuthorizationDenied,
		AuthorizationDetail:  "certificate_revoked",
		Result:               store.ResultRejected,
		ResultCode:           "Unauthenticated",
	})
	require.NoError(t, err)

	op, err := st.GetAuditOperation(ctx, rec.OperationID)
	require.NoError(t, err)
	assert.Equal(t, string(store.ClassRejectedAuthentication), op.OperationClass)
	assert.Empty(t, op.ActorID, "a rejected authentication has no authenticated subject")
	assert.Equal(t, sha256hex("presented-client-certificate"), op.ActorFingerprint)
	assert.Equal(t, "DENIED", op.AuthorizationOutcome)
	assert.Equal(t, "REJECTED", op.Result)
	assert.Equal(t, int64(1), op.ChainSeq)
	assert.Len(t, op.RowHash, sha256.Size)

	v, err := st.VerifyAuditChain(ctx, store.AuditVerifyOptions{})
	require.NoError(t, err)
	assert.Equal(t, int64(1), v.Rows)
}

// A sensitive read changes nothing and still produces an operation and
// an effect naming what was read.
func TestRecordOperation_SensitiveRead(t *testing.T) {
	st, pool := setupPostgres(t)
	ctx := context.Background()

	subject := newID()
	rec, err := st.RecordOperation(ctx, store.AuditOperation{
		Class:                store.ClassSensitiveRead,
		ActorType:            "user",
		ActorID:              subject,
		Origin:               "rpc",
		RequestDescriptor:    "powermanage.v1.ControlService/RevealLuksKey",
		AuthorizationOutcome: store.AuthorizationAllowed,
		AuthorizationDetail:  "RevealLuksKey",
		Result:               store.ResultSuccess,
		ResultCode:           "OK",
	}, store.AuditEffect{
		ResourceType: "luks_key",
		ResourceID:   newID(),
		Action:       "READ",
		Outcome:      store.EffectApplied,
	})
	require.NoError(t, err)

	op, err := st.GetAuditOperation(ctx, rec.OperationID)
	require.NoError(t, err)
	assert.Equal(t, string(store.ClassSensitiveRead), op.OperationClass)
	assert.Equal(t, subject, op.ActorID)

	effects, err := st.ListAuditEffects(ctx, rec.OperationID)
	require.NoError(t, err)
	require.Len(t, effects, 1)
	assert.Equal(t, "READ", effects[0].Action)

	assert.Zero(t, countRows(t, pool, "devices"), "a sensitive read changes no state")
}

// ---------------------------------------------------------------------------
// Late effects
// ---------------------------------------------------------------------------

// Work that finishes long after the request that started it appends
// its effects at the current head, carrying the original operation id.
// Rows written in between do not interfere and nothing already
// committed is rewritten.
func TestWithAuditEffects_LateEffectAppendsAfterInterveningRows(t *testing.T) {
	st, _ := setupPostgres(t)
	ctx := context.Background()

	deliveryID := newID()
	dispatch, err := st.RecordOperation(ctx, mutationOp(), store.AuditEffect{
		ResourceType: "delivery",
		ResourceID:   deliveryID,
		Action:       "DISPATCH",
		Outcome:      store.EffectApplied,
	})
	require.NoError(t, err)
	require.Equal(t, []int64{2}, dispatch.EffectSeqs)

	// Unrelated traffic lands in between.
	seedOperation(t, st)
	seedOperation(t, st)

	late, err := st.WithAuditEffects(ctx, dispatch.OperationID, func(_ context.Context, _ *store.Tx, r *store.AuditRecorder) error {
		r.Effect(store.AuditEffect{
			ResourceType: "delivery",
			ResourceID:   deliveryID,
			Action:       "ACK_RECEIPT",
			Outcome:      store.EffectApplied,
		})
		return nil
	})
	require.NoError(t, err)
	require.Len(t, late.EffectSeqs, 1)
	assert.Equal(t, int64(7), late.EffectSeqs[0], "the late effect takes the next free position, not one beside its operation")
	assert.Equal(t, dispatch.OperationID, late.OperationID)

	effects, err := st.ListAuditEffects(ctx, dispatch.OperationID)
	require.NoError(t, err)
	require.Len(t, effects, 2, "both effects belong to the same operation")
	assert.Equal(t, int32(0), effects[0].EffectSeq)
	assert.Equal(t, int32(1), effects[1].EffectSeq, "the late effect continues the numbering within the operation")
	assert.Equal(t, "ACK_RECEIPT", effects[1].Action)

	v, err := st.VerifyAuditChain(ctx, store.AuditVerifyOptions{})
	require.NoError(t, err)
	assert.Equal(t, int64(7), v.Rows)
	assert.Equal(t, int64(7), v.LastSeq)
}

// A continuation must not touch anything already on the chain. This is
// asserted directly: every prior row's hash is identical before and
// after.
func TestWithAuditEffects_RewritesNothingAlreadyCommitted(t *testing.T) {
	st, pool := setupPostgres(t)
	ctx := context.Background()

	dispatch, err := st.RecordOperation(ctx, mutationOp(), store.AuditEffect{
		ResourceType: "delivery",
		ResourceID:   newID(),
		Action:       "DISPATCH",
		Outcome:      store.EffectApplied,
	})
	require.NoError(t, err)
	seedOperation(t, st)

	before := chainSnapshot(t, pool)
	require.NotEmpty(t, before, "matches-zero guard: the chain snapshot is empty")

	_, err = st.WithAuditEffects(ctx, dispatch.OperationID, func(_ context.Context, _ *store.Tx, r *store.AuditRecorder) error {
		r.Effect(store.AuditEffect{
			ResourceType: "delivery",
			ResourceID:   newID(),
			Action:       "RESULT",
			Outcome:      store.EffectApplied,
		})
		return nil
	})
	require.NoError(t, err)

	after := chainSnapshot(t, pool)
	for seq, hash := range before {
		assert.Equal(t, hash, after[seq],
			"position %d was rewritten by a late append; nothing already committed may change", seq)
	}
	assert.Len(t, after, len(before)+1, "the continuation appends exactly one row")
}

// chainSnapshot maps every chain position to its stored row hash.
func chainSnapshot(t *testing.T, pool *pgxpool.Pool) map[int64]string {
	t.Helper()
	rows, err := pool.Query(context.Background(), `
		SELECT chain_seq, encode(row_hash, 'hex') FROM public.audit_operations
		UNION ALL
		SELECT chain_seq, encode(row_hash, 'hex') FROM public.audit_effects`)
	require.NoError(t, err)
	defer rows.Close()

	out := map[int64]string{}
	for rows.Next() {
		var seq int64
		var hash string
		require.NoError(t, rows.Scan(&seq, &hash))
		out[seq] = hash
	}
	require.NoError(t, rows.Err())
	return out
}

// A continuation that records nothing is refused: it would advance
// nothing and claim an outcome it never wrote.
func TestWithAuditEffects_RefusesAnEmptyContinuation(t *testing.T) {
	st, _ := setupPostgres(t)
	ctx := context.Background()
	rec := seedOperation(t, st)

	_, err := st.WithAuditEffects(ctx, rec.OperationID, func(_ context.Context, _ *store.Tx, _ *store.AuditRecorder) error {
		return nil
	})
	assert.ErrorIs(t, err, store.ErrAuditEffectRequired)
}

func TestWithAuditEffects_RefusesAnUnknownOperation(t *testing.T) {
	st, _ := setupPostgres(t)

	_, err := st.WithAuditEffects(context.Background(), newID(), func(_ context.Context, _ *store.Tx, r *store.AuditRecorder) error {
		r.Effect(deviceEffect(newID()))
		return nil
	})
	assert.ErrorIs(t, err, store.ErrAuditOperationRequired)
}

// ---------------------------------------------------------------------------
// Off-host anchors
// ---------------------------------------------------------------------------

// publishAnchor performs the two steps a real publisher performs:
// capture the tip, then record that exact tuple as published. The
// off-host write itself is what the reference stands in for.
func publishAnchor(t *testing.T, st *store.Store, ref string) store.AuditAnchor {
	t.Helper()
	ctx := context.Background()
	tip, err := st.AuditChainTipOf(ctx, store.DefaultAuditStream)
	require.NoError(t, err)
	anchor, err := st.RecordPublishedAuditAnchor(ctx, tip, ref)
	require.NoError(t, err)
	return anchor
}

// The recorded anchor must attest a tuple that was actually published.
// A hash the chain does not carry at that position is refused, and
// nothing is written: an anchor that disagrees with its own chain is
// worse than no anchor.
func TestRecordPublishedAuditAnchor_RefusesAHashTheChainDoesNotCarry(t *testing.T) {
	st, pool := setupPostgres(t)
	ctx := context.Background()
	seedOperation(t, st)

	tip, err := st.AuditChainTipOf(ctx, store.DefaultAuditStream)
	require.NoError(t, err)

	wrong := tip
	wrong.HeadHash = []byte(strings.Repeat("\x07", sha256.Size))
	_, err = st.RecordPublishedAuditAnchor(ctx, wrong, "s3://audit-anchors/forged")
	require.Error(t, err)
	assert.ErrorIs(t, err, store.ErrAuditAnchorMismatch)
	assert.Zero(t, countRows(t, pool, "audit_chain_anchors"))

	beyond := tip
	beyond.Height = tip.Height + 100
	_, err = st.RecordPublishedAuditAnchor(ctx, beyond, "s3://audit-anchors/beyond")
	require.Error(t, err)
	assert.ErrorIs(t, err, store.ErrAuditAnchorMismatch)
	assert.Zero(t, countRows(t, pool, "audit_chain_anchors"))
}

// An anchor with no off-host reference attests nothing: the value it
// pins exists only in the database an attacker would already control.
func TestRecordPublishedAuditAnchor_RefusesAnEmptyExternalReference(t *testing.T) {
	st, pool := setupPostgres(t)
	ctx := context.Background()
	seedOperation(t, st)

	tip, err := st.AuditChainTipOf(ctx, store.DefaultAuditStream)
	require.NoError(t, err)

	_, err = st.RecordPublishedAuditAnchor(ctx, tip, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, store.ErrAuditAnchorMismatch)
	assert.Zero(t, countRows(t, pool, "audit_chain_anchors"))
}

// Appends between capture and recording are expected — publishing
// takes time — and must not invalidate the captured tuple. The anchor
// pins the position it captured, not wherever the head has since
// moved.
func TestRecordPublishedAuditAnchor_AcceptsACapturedTipAfterFurtherAppends(t *testing.T) {
	st, _ := setupPostgres(t)
	ctx := context.Background()

	seedOperation(t, st)
	tip, err := st.AuditChainTipOf(ctx, store.DefaultAuditStream)
	require.NoError(t, err)
	require.Equal(t, int64(2), tip.Height)

	// The publisher is writing off-host; the server keeps working.
	seedOperation(t, st)
	seedOperation(t, st)

	anchor, err := st.RecordPublishedAuditAnchor(ctx, tip, "s3://audit-anchors/captured-earlier")
	require.NoError(t, err)
	assert.Equal(t, int64(2), anchor.ChainSeq, "the anchor pins the captured position, not the current head")

	v, err := st.VerifyAuditChain(ctx, store.AuditVerifyOptions{
		ExpectedAnchor:     &anchor,
		CheckStoredAnchors: true,
	})
	require.NoError(t, err)
	assert.Equal(t, 2, v.AnchorsChecked)
	assert.Equal(t, int64(6), v.LastSeq)
}

// An anchor authenticates the prefix up to its position. A late effect
// appended afterwards must not disturb it — which is the whole reason
// a row hash covers only itself.
func TestAuditAnchor_PrefixStillVerifiesAfterALateEffect(t *testing.T) {
	st, _ := setupPostgres(t)
	ctx := context.Background()

	dispatch, err := st.RecordOperation(ctx, mutationOp(), store.AuditEffect{
		ResourceType: "delivery",
		ResourceID:   newID(),
		Action:       "DISPATCH",
		Outcome:      store.EffectApplied,
	})
	require.NoError(t, err)

	anchor := publishAnchor(t, st, "s3://audit-anchors/before-late-effect")
	require.Equal(t, dispatch.HeadSeq, anchor.ChainSeq)

	_, err = st.WithAuditEffects(ctx, dispatch.OperationID, func(_ context.Context, _ *store.Tx, r *store.AuditRecorder) error {
		r.Effect(store.AuditEffect{
			ResourceType: "delivery",
			ResourceID:   newID(),
			Action:       "ACK_RECEIPT",
			Outcome:      store.EffectApplied,
		})
		return nil
	})
	require.NoError(t, err)

	v, err := st.VerifyAuditChain(ctx, store.AuditVerifyOptions{
		ExpectedAnchor:     &anchor,
		CheckStoredAnchors: true,
	})
	require.NoError(t, err, "an anchor taken before a late effect must still verify after it")
	assert.Equal(t, 2, v.AnchorsChecked)
	assert.Greater(t, v.LastSeq, anchor.ChainSeq)
}

// Verification against an anchor the local chain does not reproduce
// fails. This is the check a local rewrite cannot pass: recomputing
// every hash locally still cannot produce a value already held
// elsewhere.
func TestVerifyAuditChain_FailsWhenAnAnchoredPositionIsAltered(t *testing.T) {
	st, _ := setupPostgres(t)
	ctx := context.Background()

	rec := seedOperation(t, st)
	anchor := publishAnchor(t, st, "s3://audit-anchors/pinned")
	require.Equal(t, rec.HeadSeq, anchor.ChainSeq)

	intact, err := st.VerifyAuditChain(ctx, store.AuditVerifyOptions{ExpectedAnchor: &anchor})
	require.NoError(t, err)
	require.Equal(t, 1, intact.AnchorsChecked)

	// What an off-host copy would say if the local rows had been
	// rewritten: a different hash at the same position.
	tampered := anchor
	tampered.RowHash = []byte(strings.Repeat("\x01", sha256.Size))
	_, err = st.VerifyAuditChain(ctx, store.AuditVerifyOptions{ExpectedAnchor: &tampered})
	require.Error(t, err)
	assert.ErrorIs(t, err, store.ErrAuditAnchorMismatch)
	assert.Contains(t, err.Error(), "does not reproduce anchor")
}

// An anchored position that no longer exists locally cannot be
// verified, and silence is not the answer: the anchor says the
// position was there.
func TestVerifyAuditChain_FailsWhenAnAnchoredPositionIsGone(t *testing.T) {
	st, pool := setupPostgres(t)
	ctx := context.Background()

	seedOperation(t, st)
	anchor := publishAnchor(t, st, "s3://audit-anchors/pinned")

	disableAuditTriggers(t, pool)
	_, err := pool.Exec(ctx, `DELETE FROM public.audit_effects`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `DELETE FROM public.audit_operations`)
	require.NoError(t, err)

	_, err = st.VerifyAuditChain(ctx, store.AuditVerifyOptions{ExpectedAnchor: &anchor})
	require.Error(t, err)
	assert.ErrorIs(t, err, store.ErrAuditChainBroken,
		"an emptied chain whose head still stands is a break, not an empty stream")
}

// ---------------------------------------------------------------------------
// Head consistency
// ---------------------------------------------------------------------------

// Removing the NEWEST rows leaves a shorter chain that is internally
// perfect: every remaining hash still follows from its predecessor.
// Comparing the walk against the recorded head is what catches it.
func TestVerifyAuditChain_DetectsARemovedTail(t *testing.T) {
	st, pool := setupPostgres(t)
	ctx := context.Background()

	seedOperation(t, st)
	last := seedOperation(t, st)

	disableAuditTriggers(t, pool)
	_, err := pool.Exec(ctx, `DELETE FROM public.audit_effects WHERE operation_id = $1`, last.OperationID)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `DELETE FROM public.audit_operations WHERE operation_id = $1`, last.OperationID)
	require.NoError(t, err)

	_, err = st.VerifyAuditChain(ctx, store.AuditVerifyOptions{})
	require.Error(t, err)
	assert.ErrorIs(t, err, store.ErrAuditChainBroken)
	assert.Contains(t, err.Error(), "head stands at")
}

// A head row edited to match a truncated chain is caught by its hash.
func TestVerifyAuditChain_DetectsAnEditedChainHead(t *testing.T) {
	st, pool := setupPostgres(t)
	ctx := context.Background()

	seedOperation(t, st)
	_, err := pool.Exec(ctx,
		`UPDATE public.audit_chain_head SET head_hash = decode(repeat('00', 32), 'hex') WHERE stream = $1`,
		store.DefaultAuditStream)
	require.NoError(t, err)

	_, err = st.VerifyAuditChain(ctx, store.AuditVerifyOptions{})
	require.Error(t, err)
	assert.ErrorIs(t, err, store.ErrAuditChainBroken)
	assert.Contains(t, err.Error(), "head hash does not match")
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

// Two audited writers must be able to be inside their domain callbacks
// at the same time. The barrier makes that a requirement rather than a
// hope: neither is released until both have arrived, so a
// implementation that held the chain head across the callback could
// not get both in and would deadlock until the timeout.
//
// Both must then commit, and the resulting chain must be gapless.
func TestWithAudit_ConcurrentWritersOverlapAndTheChainStaysGapless(t *testing.T) {
	st, _ := setupPostgresPool(t, 8)
	ctx := context.Background()

	var arrived sync.WaitGroup
	arrived.Add(2)
	release := make(chan struct{})
	inside := make(chan string, 2)

	run := func(hostname string) error {
		_, err := st.WithAudit(ctx, mutationOp(), func(ctx context.Context, tx *store.Tx, r *store.AuditRecorder) error {
			id := newID()
			if err := insertDevice(ctx, tx, id, hostname); err != nil {
				return err
			}
			inside <- hostname
			arrived.Done()
			select {
			case <-release:
			case <-time.After(30 * time.Second):
				return fmt.Errorf("%s never released: the other writer could not enter its domain callback", hostname)
			}
			r.Effect(deviceEffect(id))
			return nil
		})
		return err
	}

	errs := make(chan error, 2)
	go func() { errs <- run("concurrent-a.example.test") }()
	go func() { errs <- run("concurrent-b.example.test") }()

	// Both must be inside before either proceeds.
	done := make(chan struct{})
	go func() { arrived.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("both writers must be inside their domain callbacks concurrently; the audited path must not serialise domain work")
	}
	close(release)

	for i := 0; i < 2; i++ {
		require.NoError(t, <-errs)
	}
	close(inside)
	seen := map[string]bool{}
	for h := range inside {
		seen[h] = true
	}
	assert.Len(t, seen, 2)

	n, err := st.CountDevices(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(2), n)

	v, err := st.VerifyAuditChain(ctx, store.AuditVerifyOptions{})
	require.NoError(t, err, "concurrent appends must leave one gapless, verifiable chain")
	assert.Equal(t, int64(4), v.Rows)
	assert.Equal(t, int64(1), v.FirstSeq)
	assert.Equal(t, int64(4), v.LastSeq)

	tip, err := st.AuditChainTipOf(ctx, store.DefaultAuditStream)
	require.NoError(t, err)
	assert.Equal(t, int64(4), tip.Height)
	assert.Equal(t, v.HeadHash, tip.HeadHash)
}
